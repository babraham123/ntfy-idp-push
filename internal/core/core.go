// Package core holds the operations shared by the Duo facade, the web UI and the CLI: provisioning,
// enrollment, login challenges and revocation.
package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/babraham123/ntfy-idp-push/internal/challenge"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
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
)

const (
	EnrollCodeTTL      = 5 * time.Minute
	UnverifiedTTL      = 24 * time.Hour
	challengeRetention = 7 * 24 * time.Hour
)

// ntfy's user.AllowedUsername, so a name valid here is valid there.
var usernameRe = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]{1,128}$`)

type Service struct {
	cfg        atomic.Pointer[config.Config]
	Store      *store.Store
	Ntfy       *ntfy.Client
	RP         *webauthn.RP
	Challenges *challenge.Manager
	Log        *slog.Logger
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
		Store:      st,
		Ntfy:       ntfy.New(cfg.NtfyBaseURL, cfg.NtfyAdminToken),
		RP:         rp,
		Challenges: challenge.New(st),
		Log:        log,
	}
	s.cfg.Store(cfg)
	s.Challenges.OnDecided = s.clearPush
	return s, nil
}

func (s *Service) Config() *config.Config { return s.cfg.Load() }

// Reload swaps in a new config for settings read per request (keys, kill switch, grants, timeouts).
// Listener, TLS, database and WebAuthn RP settings need a restart. Turning the kill switch on also
// denies every login whose push is still on a phone.
func (s *Service) Reload(cfg *config.Config) {
	s.cfg.Store(cfg)
	if cfg.PushDisabled {
		if err := s.denyPending(context.Background(), store.ChallengeFilter{}); err != nil {
			s.Log.Error("reload: deny pending logins", "err", err)
		}
	}
}

// denyPending denies the pending challenges matching f, waking their blocked auth calls.
func (s *Service) denyPending(ctx context.Context, f store.ChallengeFilter) error {
	ids, err := s.Store.PendingChallengeIDs(ctx, f)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.Challenges.Decide(ctx, id, store.StateDeny); err != nil && !errors.Is(err, challenge.ErrGone) {
			return err
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

// Provision ensures the ntfy account exists with the enroll-access grants. It creates nothing
// push-related and is safe to re-run.
func (s *Service) Provision(ctx context.Context, username string) (*store.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	cfg := s.Config()
	grants, err := config.ExpandAccess(cfg.Access, cfg.NtfyTopicPrefix, username)
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
	if err := s.ensureNtfyUser(ctx, username); err != nil {
		return nil, err
	}
	for _, g := range grants {
		if err := s.Ntfy.AllowAccess(ctx, username, g.Topic, g.Permission); err != nil {
			return nil, err
		}
	}
	recorded := grants
	if !cfg.EnrollAccessReconcile {
		// Keep remembering grants dropped from config so a later reconcile or reset can see them.
		recorded = mergeGrants(grants, u.Grants)
	} else {
		for _, old := range u.Grants {
			if !hasTopic(grants, old.Topic) {
				if err := s.Ntfy.ResetAccess(ctx, username, old.Topic); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := s.Store.SetUserGrants(ctx, u.ID, recorded); err != nil {
		return nil, err
	}
	u.Grants = recorded
	s.Store.Audit(ctx, username, "provision", map[string]any{"grants": grants})
	return u, nil
}

func (s *Service) ensureNtfyUser(ctx context.Context, username string) error {
	nu, err := s.Ntfy.User(ctx, username)
	if err != nil {
		return err
	}
	if nu != nil {
		if nu.Role == "admin" {
			return fmt.Errorf("ntfy user %q is an admin; refusing to manage it", username)
		}
		return nil
	}
	// Nobody needs the password: the apps sign in with enrollment codes.
	return s.Ntfy.AddUser(ctx, username, challenge.RandomToken(32))
}

func mergeGrants(a, b []config.Grant) []config.Grant {
	out := append([]config.Grant{}, a...)
	for _, g := range b {
		if !hasTopic(out, g.Topic) {
			out = append(out, g)
		}
	}
	return out
}

func hasTopic(gs []config.Grant, topic string) bool {
	for _, g := range gs {
		if g.Topic == topic {
			return true
		}
	}
	return false
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

// MintNtfyCode returns an ntfy#597 enrollment code, or nil when the server does not support it.
// ntfy keeps one pending code per user, so minting supersedes any code handed out earlier.
func (s *Service) MintNtfyCode(ctx context.Context, username string) (*ntfy.EnrollCode, error) {
	ec, err := s.Ntfy.MintEnrollCode(ctx, username)
	if errors.Is(err, ntfy.ErrNotSupported) {
		return nil, nil
	}
	return ec, err
}

// clearPush deletes the login push once its challenge is decided, so stale requests vanish.
func (s *Service) clearPush(c *store.Challenge) {
	d, err := s.Store.Device(context.Background(), c.DeviceID)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Ntfy.DeleteMessage(ctx, d.NtfyTopic, c.ID); err != nil {
		s.Log.Debug("clear push", "challenge", c.ID, "err", err)
	}
}

// Purge expires challenges, removes devices never verified, and finishes revocations whose ntfy
// cleanup failed earlier.
func (s *Service) Purge(ctx context.Context) {
	now := time.Now()
	if err := s.Store.Purge(ctx, now, UnverifiedTTL, challengeRetention); err != nil {
		s.Log.Error("purge", "err", err)
		return
	}
	stale, err := s.Store.StaleDevices(ctx, now, UnverifiedTTL)
	if err != nil {
		s.Log.Error("purge", "err", err)
		return
	}
	for _, d := range stale {
		if err := s.removeDevice(ctx, &d); err != nil {
			s.Log.Warn("purge: remove device", "device", d.ID, "err", err)
			continue
		}
		s.Store.Audit(ctx, d.Username, "device_purged", map[string]any{"device": d.ID, "revoked": d.RevokedAt != nil})
	}
}

// removeDevice drops the device's topic grant, then its row. The row goes last so a failed ntfy
// call leaves something to retry from.
func (s *Service) removeDevice(ctx context.Context, d *store.Device) error {
	if err := s.Ntfy.ResetAccess(ctx, d.Username, d.NtfyTopic); err != nil {
		return err
	}
	return s.Store.DeleteDevice(ctx, d.ID)
}

// SetNtfyPassword gives the ntfy user a fresh random password and returns it, for apps that cannot
// redeem enrollment codes. Existing tokens stay valid.
func (s *Service) SetNtfyPassword(ctx context.Context, username string) (string, error) {
	if _, err := s.Provision(ctx, username); err != nil {
		return "", err
	}
	password := challenge.RandomToken(18)
	if err := s.Ntfy.ChangePassword(ctx, username, password); err != nil {
		return "", err
	}
	s.Store.Audit(ctx, username, "ntfy_password_set", nil)
	return password, nil
}

// StartupChecks fails closed on an ntfy setup that would let anyone but the phone read pushes.
func (s *Service) StartupChecks(ctx context.Context) error {
	cfg := s.Config()
	acct, err := s.Ntfy.Account(ctx)
	if err != nil {
		return fmt.Errorf("ntfy admin token: %w", err)
	}
	if acct.Role != "admin" {
		return fmt.Errorf("ntfy token belongs to %q with role %q; admin required", acct.Username, acct.Role)
	}
	if _, err := s.Ntfy.Users(ctx); err != nil {
		return fmt.Errorf("ntfy GET /v1/users: %w", err)
	}
	probe := cfg.NtfyTopicPrefix + "probe"
	status, err := s.Ntfy.AnonymousReadStatus(ctx, probe)
	if err != nil {
		return fmt.Errorf("ntfy anonymous probe: %w", err)
	}
	if status != 401 && status != 403 {
		return fmt.Errorf("anonymous read of %q returned %d; set ntfy auth-default-access: deny-all", probe, status)
	}
	if err := s.Ntfy.Publish(ctx, &ntfy.Message{Topic: probe, Message: "probe", Cache: "no", Firebase: "no"}); err != nil {
		return fmt.Errorf("publish to %q: %w", probe, err)
	}
	return nil
}
