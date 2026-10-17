// Package core holds shared operations for the Duo facade, web UI, and CLI (provisioning,
// enrollment, logins, revocation).
package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

var (
	ErrUserDisabled  = errors.New("user disabled")
	ErrInvalidName   = errors.New("invalid username")
	ErrNotOwner      = errors.New("device does not belong to user")
	ErrForeignGrants = errors.New("ntfy user has grants the shim did not make; use --force")
	ErrInvalidCode   = errors.New("invalid or expired enrollment code")
	ErrPushDisabled  = errors.New("push disabled")
	ErrDeviceRevoked = errors.New("device revoked or not active")
	// ErrPasskeyPolicy wraps a webauthn refusal of the device's passkeys (synced, or none usable).
	ErrPasskeyPolicy = errors.New("passkey refused by policy")

	ErrUnknownUser        = errors.New("unknown user")
	ErrUnknownDevice      = errors.New("unknown device")
	ErrEnrollmentRequired = errors.New("enrollment required")
)

const (
	EnrollCodeTTL      = 5 * time.Minute
	UnverifiedTTL      = 24 * time.Hour
	challengeRetention = 7 * 24 * time.Hour
)

// ntfy's user.AllowedUsername, so a name valid here is valid there.
var usernameRe = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]{1,128}$`)

type Service struct {
	cfg atomic.Pointer[config.Config]
	// Store remains exported for store-level features: OIDC sessions, backup, and the audit
	// log.
	Store *store.Store
	Log   *slog.Logger
	ntfy  *ntfy.Client
	rp    *webauthn.RP

	waitMu sync.Mutex
	// waiters holds a channel per pending auth call challenge in this process, closed upon
	// decision.
	waiters map[string]chan struct{}

	enrollMu sync.Mutex
	// enrolling holds the passkey ceremonies begun in this process, by handle.
	enrolling map[string]*pendingEnrollment
}

func New(cfg *config.Config, st *store.Store, log *slog.Logger) (*Service, error) {
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
		Store:     st,
		ntfy:      ntfy.New(cfg.NtfyBaseURL, cfg.NtfyAdminToken),
		rp:        rp,
		Log:       log,
		waiters:   map[string]chan struct{}{},
		enrolling: map[string]*pendingEnrollment{},
	}
	s.cfg.Store(cfg)
	return s, nil
}

func (s *Service) Config() *config.Config { return s.cfg.Load() }

// Reload swaps config for per-request settings (keys, kill switch, grants, timeouts). Listener,
// TLS, DB, and WebAuthn need a restart. Enabling the kill switch denies pending phone pushes.
func (s *Service) Reload(cfg *config.Config) {
	s.cfg.Store(cfg)
	if cfg.PushDisabled {
		if err := s.denyPending(context.Background(), store.ChallengeFilter{}); err != nil {
			s.Log.Error("reload: deny pending logins", "err", err)
		}
	}
}

func ValidUsername(u string) error {
	if !usernameRe.MatchString(u) || u == "everyone" {
		return fmt.Errorf("%w: %q", ErrInvalidName, u)
	}
	return nil
}

// Provision safely ensures the ntfy account exists with enroll-access grants without creating push
// resources.
func (s *Service) Provision(ctx context.Context, username string) (*store.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	// Expanded before the user row exists, so a name refused here leaves nothing behind.
	grants, err := s.enrollGrants(username)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.EnsureUser(ctx, username, uuid.NewString())
	if err != nil {
		return nil, err
	}
	if u.DisabledAt != nil {
		return nil, ErrUserDisabled
	}
	if err := s.applyNtfyAccount(ctx, u, grants); err != nil {
		return nil, err
	}
	s.Store.Audit(ctx, username, "provision", map[string]any{"grants": grants})
	return u, nil
}

// NtfyLink is the deep link the ntfy app opens to sign in (with code) and subscribe to topic.
func (s *Service) NtfyLink(topic, username, code string) string {
	host, secure := s.Config().NtfyHost()
	q := url.Values{}
	if username != "" {
		q.Set("user", username)
	}
	if code != "" {
		q.Set("code", code)
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

// MintNtfyCode returns an ntfy enrollment code (or nil if unsupported). Minting supersedes any
// previous pending code for the user.
func (s *Service) MintNtfyCode(ctx context.Context, username string) (*ntfy.EnrollCode, error) {
	ec, err := s.ntfy.MintEnrollCode(ctx, username)
	if errors.Is(err, ntfy.ErrNotSupported) {
		return nil, nil
	}
	return ec, err
}

// Purge expires challenges/records, removes unverified devices, and reconciles unfinished
// revocations. Steps run independently of previous failures.
func (s *Service) Purge(ctx context.Context) {
	now := time.Now()
	// Times out challenges with missing auth calls (e.g., process restarted) and clears their
	// phone pushes.
	if err := s.decidePending(ctx, store.ChallengeFilter{ExpiredBy: now}, store.StateTimeout); err != nil {
		s.Log.Error("purge: expire challenges", "err", err)
	}
	if err := s.Store.Purge(ctx, now, UnverifiedTTL, challengeRetention); err != nil {
		s.Log.Error("purge", "err", err)
	}
	if unverified, err := s.Store.ExpiredUnverifiedDevices(ctx, now, UnverifiedTTL); err != nil {
		s.Log.Error("purge: unverified devices", "err", err)
	} else if err := s.removeDevices(ctx, unverified); err != nil {
		s.Log.Warn("purge: unverified devices", "err", err)
	}
	if err := s.Reconcile(ctx); err != nil {
		s.Log.Warn("purge: reconcile revocations", "err", err)
	}
}

// SetNtfyPassword generates a random password for apps unable to redeem enrollment codes. Existing
// tokens remain valid.
func (s *Service) SetNtfyPassword(ctx context.Context, username string) (string, error) {
	if _, err := s.Provision(ctx, username); err != nil {
		return "", err
	}
	password := token.Random(18)
	if err := s.ntfy.ChangePassword(ctx, username, password); err != nil {
		return "", err
	}
	s.Store.Audit(ctx, username, "ntfy_password_set", nil)
	return password, nil
}

// StartupChecks fails closed on an ntfy setup that would let anyone but the phone read pushes.
func (s *Service) StartupChecks(ctx context.Context) error {
	cfg := s.Config()
	acct, err := s.ntfy.Account(ctx)
	if err != nil {
		return fmt.Errorf("ntfy admin token: %w", err)
	}
	if acct.Role != "admin" {
		return fmt.Errorf("ntfy token belongs to %q with role %q; admin required", acct.Username, acct.Role)
	}
	if _, err := s.ntfy.Users(ctx); err != nil {
		return fmt.Errorf("ntfy GET /v1/users: %w", err)
	}
	probe := cfg.NtfyTopicPrefix + "probe"
	status, err := s.ntfy.AnonymousReadStatus(ctx, probe)
	if err != nil {
		return fmt.Errorf("ntfy anonymous probe: %w", err)
	}
	if status != 401 && status != 403 {
		return fmt.Errorf("anonymous read of %q returned %d; set ntfy auth-default-access: deny-all", probe, status)
	}
	if err := s.ntfy.Publish(ctx, &ntfy.Message{Topic: probe, Message: "probe", Cache: "no", Firebase: "no"}); err != nil {
		return fmt.Errorf("publish to %q: %w", probe, err)
	}
	return nil
}
