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
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

// ErrRestartRequired is a reload that changed a key bound at startup; the running configuration
// is kept.
var ErrRestartRequired = errors.New("restart required")

var errNotFound = store.ErrNotFound

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
	// dir lists the people who should have accounts, and is nil when no directory is configured;
	// mail delivers their welcome emails. Both are built at startup from restart-only keys.
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

	// welcoming runs one welcome per user at a time.
	welcoming keyedMutex
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

// ensureUser is the user row for username, created if it is new. A disabled user is refused: this
// is the gate every way in (provisioning, enrollment) passes through.
func (s *Service) ensureUser(ctx context.Context, username string) (*model.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	u, err := s.store.EnsureUser(ctx, username, uuid.NewString())
	if err != nil {
		return nil, err
	}
	if !u.Enabled() {
		return nil, ErrUserDisabled
	}
	return u, nil
}

// provision ensures the ntfy account exists with enroll-access grants without creating push
// resources. It is idempotent; the first call makes preauth answer "enroll" instead of "deny".
func (s *Service) provision(ctx context.Context, acc *ntfy.Accounts, username string) (*model.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	// Expanded before the user row exists, so a name refused here leaves nothing behind.
	grants, err := s.enrollGrants(username)
	if err != nil {
		return nil, err
	}
	u, err := s.ensureUser(ctx, username)
	if err != nil {
		return nil, err
	}
	if err := s.applyNtfyAccount(ctx, acc, u, grants); err != nil {
		return nil, err
	}
	s.store.Audit(ctx, username, "provision", map[string]any{"grants": grants})
	return u, nil
}

// TopicLink is the ntfy:// deep link that subscribes the app to Topic on the shim's ntfy server.
type TopicLink struct {
	Topic string
	URL   string
	// Intent is URL as a Chrome intent:// link, for Android's tap button: it opens ntfy's Play Store
	// listing when the app is not installed. It needs a tap, so QR codes carry URL.
	Intent string
}

// topicLink is the subscribe link for topic as username. It carries no credentials; the app must
// already be signed in as the user.
func (s *Service) topicLink(username, topic string) TopicLink {
	link := ntfyLink(s.Config(), topic, username)
	return TopicLink{Topic: topic, URL: link, Intent: intentLink(link)}
}

// defaultTopicLinks is one subscribe link per default-topics entry, ${user} expanded.
func (s *Service) defaultTopicLinks(username string) []TopicLink {
	var out []TopicLink
	for _, t := range s.Config().DefaultTopics {
		out = append(out, s.topicLink(username, config.Expand(t, username)))
	}
	return out
}

// DefaultTopicLink is the subscribe link for topic, which must be one of username's default
// topics: the subscribe page serves only the links the welcome email names.
func (s *Service) DefaultTopicLink(username, topic string) (TopicLink, error) {
	if ValidUsername(username) == nil {
		for _, l := range s.defaultTopicLinks(username) {
			if l.Topic == topic {
				return l, nil
			}
		}
	}
	return TopicLink{}, ErrUnknownTopic
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

// ntfyAndroidPackage is the ntfy Android app's ID on Google Play and F-Droid alike.
const ntfyAndroidPackage = "io.heckel.ntfy"

// intentLink is the Chrome intent:// form of an ntfy:// link.
func intentLink(ntfyLink string) string {
	return "intent://" + strings.TrimPrefix(ntfyLink, "ntfy://") + "#Intent;scheme=ntfy;package=" + ntfyAndroidPackage + ";end"
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
	if err := s.reconcile(ctx); err != nil {
		s.Log.Warn("purge: reconcile revocations", "err", err)
	}
}

// StartupChecks fails closed on an ntfy setup that would let anyone but the phone read pushes.
func (s *Service) StartupChecks(ctx context.Context) error {
	return s.ntfy().CheckServer(ctx, s.Config().NtfyTopicPrefix+"probe")
}
