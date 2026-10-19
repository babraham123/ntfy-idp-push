// Package core holds shared operations for the Duo facade, web UI, and CLI (directory sync and
// welcome emails, provisioning, enrollment, logins, revocation). It owns the running
// configuration: a reload swaps the per-request settings and rebuilds the ntfy adapter, and
// refuses keys that need a restart.
package core

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/mail"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

// ErrRestartRequired is a reload that changed a key bound at startup; the running configuration
// is kept.
var ErrRestartRequired = errors.New("restart required")

const (
	EnrollCodeTTL      = 5 * time.Minute
	UnverifiedTTL      = 24 * time.Hour
	challengeRetention = 7 * 24 * time.Hour
)

// ntfy's user.AllowedUsername, so a name valid here is valid there.
var usernameRe = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]{1,128}$`)

type Service struct {
	cfg atomic.Pointer[config.Config]
	// ntfyc is the ntfy adapter for the current ntfy-base-url and ntfy-admin-token; Reload
	// replaces it when either changes.
	ntfyc atomic.Pointer[ntfy.Client]
	store *store.Store
	Log   *slog.Logger
	rp    *webauthn.RP
	// dir lists the people who should have accounts; mail delivers their welcome emails. Both are
	// built at startup from restart-only keys.
	dir  directory.Source
	mail mail.Sender

	waitMu sync.Mutex
	// waiters holds a channel per pending auth call challenge in this process, closed upon
	// decision.
	waiters map[string]chan struct{}

	enrollMu sync.Mutex
	// enrolling holds the passkey ceremonies begun in this process, by handle.
	enrolling map[string]*pendingEnrollment

	pushMu sync.Mutex
	// pushes is each user's remaining push allowance.
	pushes map[string]*rate.Limiter
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger, dir directory.Source, mailer mail.Sender) (*Service, error) {
	pub, _ := url.Parse(cfg.PublicURL)
	rp, err := webauthn.New(webauthn.Config{
		RPID:               pub.Hostname(),
		Origin:             cfg.PublicOrigin,
		AllowSynced:        cfg.WebAuthnAllowSynced,
		RequireAttestation: cfg.WebAuthnRequireAttestation,
	})
	if err != nil {
		return nil, err
	}
	s := &Service{
		store:     st,
		rp:        rp,
		Log:       log,
		dir:       dir,
		mail:      mailer,
		waiters:   map[string]chan struct{}{},
		enrolling: map[string]*pendingEnrollment{},
		pushes:    map[string]*rate.Limiter{},
	}
	s.cfg.Store(cfg)
	s.ntfyc.Store(ntfy.New(cfg.NtfyBaseURL, cfg.NtfyAdminToken))
	return s, nil
}

func (s *Service) Config() *config.Config { return s.cfg.Load() }

func (s *Service) ntfy() *ntfy.Client { return s.ntfyc.Load() }

// Reload makes cfg the running configuration. Keys bound at startup (see Config.RestartOnly)
// refuse the whole reload with ErrRestartRequired, so the operator sees that nothing changed.
// Enabling the kill switch denies pending phone pushes.
func (s *Service) Reload(cfg *config.Config) error {
	cur := s.Config()
	if keys := cur.RestartOnly(cfg); len(keys) > 0 {
		return fmt.Errorf("%w: %s changed", ErrRestartRequired, strings.Join(keys, ", "))
	}
	if cfg.NtfyBaseURL != cur.NtfyBaseURL || cfg.NtfyAdminToken != cur.NtfyAdminToken {
		s.ntfyc.Store(ntfy.New(cfg.NtfyBaseURL, cfg.NtfyAdminToken))
	}
	s.cfg.Store(cfg)
	if cfg.PushDisabled {
		if err := s.denyPending(context.Background(), store.ChallengeFilter{}); err != nil {
			s.Log.Error("reload: deny pending logins", "err", err)
		}
	}
	return nil
}

func ValidUsername(u string) error {
	if !usernameRe.MatchString(u) || u == "everyone" {
		return fmt.Errorf("%w: %q", ErrInvalidName, u)
	}
	return nil
}

// Provision safely ensures the ntfy account exists with enroll-access grants without creating push
// resources.
func (s *Service) Provision(ctx context.Context, username string) (*model.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	// Expanded before the user row exists, so a name refused here leaves nothing behind.
	grants, err := s.enrollGrants(username)
	if err != nil {
		return nil, err
	}
	u, err := s.store.EnsureUser(ctx, username, uuid.NewString())
	if err != nil {
		return nil, err
	}
	if !u.Enabled() {
		return nil, ErrUserDisabled
	}
	if err := s.applyNtfyAccount(ctx, u, grants); err != nil {
		return nil, err
	}
	s.store.Audit(ctx, username, "provision", map[string]any{"grants": grants})
	return u, nil
}

// TopicLink is the ntfy:// deep link that subscribes the app to Topic on the shim's ntfy server.
type TopicLink struct {
	Topic string
	URL   string
}

// Handoff is what an ntfy app needs to subscribe a user to topics: the server URL and one deep
// link per topic. It carries no credentials; the app must already be signed in as the user.
type Handoff struct {
	Username string
	// Server is ntfy-base-url, for apps that subscribe by hand instead of opening a link.
	Server string
	Links  []TopicLink
}

// Handoff builds the subscribe links for topics, expanding ${user}.
func (s *Service) Handoff(username string, topics []string) *Handoff {
	cfg := s.Config()
	h := &Handoff{Username: username, Server: cfg.NtfyBaseURL}
	for _, t := range topics {
		t = config.Expand(t, username)
		h.Links = append(h.Links, TopicLink{Topic: t, URL: ntfyLink(cfg, t, username)})
	}
	return h
}

// DefaultHandoff is Handoff for the configured default-topics.
func (s *Service) DefaultHandoff(username string) *Handoff {
	return s.Handoff(username, s.Config().DefaultTopics)
}

// ntfyLink is the deep link the ntfy app opens to subscribe to topic as username.
func ntfyLink(cfg *config.Config, topic, username string) string {
	host, secure := cfg.NtfyHost()
	q := url.Values{}
	if username != "" {
		q.Set("user", username)
	}
	if !secure {
		q.Set("secure", "false")
	}
	link := "ntfy://" + host + "/" + url.PathEscape(topic)
	if len(q) > 0 {
		link += "?" + q.Encode()
	}
	return link
}

// Purge expires challenges/records, removes unverified devices, and reconciles unfinished
// revocations. Steps run independently of previous failures.
func (s *Service) Purge(ctx context.Context) {
	now := time.Now()
	// Times out challenges with missing auth calls (e.g., process restarted) and clears their
	// phone pushes.
	if err := s.decidePending(ctx, store.ChallengeFilter{ExpiredBy: now}, model.StateTimeout); err != nil {
		s.Log.Error("purge: expire challenges", "err", err)
	}
	if err := s.store.Purge(ctx, now, UnverifiedTTL, challengeRetention); err != nil {
		s.Log.Error("purge", "err", err)
	}
	if unverified, err := s.store.ExpiredUnverifiedDevices(ctx, now, UnverifiedTTL); err != nil {
		s.Log.Error("purge: unverified devices", "err", err)
	} else if err := s.removeDevices(ctx, unverified); err != nil {
		s.Log.Warn("purge: unverified devices", "err", err)
	}
	if err := s.Reconcile(ctx); err != nil {
		s.Log.Warn("purge: reconcile revocations", "err", err)
	}
}

// SetNtfyPassword provisions username and replaces its ntfy password with a random one, returned
// for the user to sign their apps in with. Tokens of apps already signed in remain valid.
func (s *Service) SetNtfyPassword(ctx context.Context, username string) (string, error) {
	if _, err := s.Provision(ctx, username); err != nil {
		return "", err
	}
	password := token.Random(18)
	if err := s.ntfy().ChangePassword(ctx, username, password); err != nil {
		return "", err
	}
	s.store.Audit(ctx, username, "ntfy_password_set", nil)
	return password, nil
}

// AuditLog is the last limit audit entries, for one user or all.
func (s *Service) AuditLog(ctx context.Context, username string, limit int) ([]model.AuditEntry, error) {
	return s.store.AuditLog(ctx, username, limit)
}

// StartupChecks fails closed on an ntfy setup that would let anyone but the phone read pushes.
func (s *Service) StartupChecks(ctx context.Context) error {
	cfg := s.Config()
	n := s.ntfy()
	acct, err := n.Account(ctx)
	if err != nil {
		return fmt.Errorf("ntfy admin token: %w", err)
	}
	if acct.Role != "admin" {
		return fmt.Errorf("ntfy token belongs to %q with role %q; admin required", acct.Username, acct.Role)
	}
	if _, err := n.Users(ctx); err != nil {
		return fmt.Errorf("ntfy GET /v1/users: %w", err)
	}
	probe := cfg.NtfyTopicPrefix + "probe"
	status, err := n.AnonymousReadStatus(ctx, probe)
	if err != nil {
		return fmt.Errorf("ntfy anonymous probe: %w", err)
	}
	if status != 401 && status != 403 {
		return fmt.Errorf("anonymous read of %q returned %d; set ntfy auth-default-access: deny-all", probe, status)
	}
	if err := n.Publish(ctx, &ntfy.Message{Topic: probe, Message: "probe", Cache: "no", Firebase: "no"}); err != nil {
		return fmt.Errorf("publish to %q: %w", probe, err)
	}
	return nil
}
