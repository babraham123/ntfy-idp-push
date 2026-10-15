package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/challenge"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

// UserRef names a user by ID or, when ID is empty, by username, as the Duo API's user_id and
// username parameters do.
type UserRef struct{ ID, Username string }

func (s *Service) resolveUser(ctx context.Context, ref UserRef) (*store.User, error) {
	var u *store.User
	var err error
	if ref.ID != "" {
		u, err = s.Store.UserByID(ctx, ref.ID)
	} else {
		u, err = s.Store.UserByName(ctx, ref.Username)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownUser
	}
	return u, err
}

// active reports whether d can receive logins: set up on the phone and not revoked.
func active(d *store.Device) bool { return d.VerifiedAt != nil && d.RevokedAt == nil }

// eligible is the one rule for whether device d of user u may receive or approve a push now. A nil
// u or d skips the checks that need it, so preauth can ask before it has either. The store's
// DecideChallenge repeats the user and device part in SQL to close the race with a concurrent
// revoke or disable.
func eligible(cfg *config.Config, u *store.User, d *store.Device) error {
	switch {
	case cfg.PushDisabled:
		return ErrPushDisabled
	case u == nil:
		return nil
	case u.DisabledAt != nil:
		return ErrUserDisabled
	case d == nil:
		return nil
	case d.UserID != u.ID:
		return ErrNotOwner
	case !active(d):
		return ErrDeviceRevoked
	}
	return nil
}

// activeDevices lists u's active devices, most recently used first: store.Devices orders them so,
// and device=auto takes the first.
func (s *Service) activeDevices(ctx context.Context, u *store.User) ([]store.Device, error) {
	devs, err := s.Store.Devices(ctx, u.ID, false)
	if err != nil {
		return nil, err
	}
	out := devs[:0]
	for _, d := range devs {
		if active(&d) {
			out = append(out, d)
		}
	}
	return out, nil
}

// loginDevice resolves the Duo device parameter among u's active devices; "auto" or empty is the
// most recently used one.
func (s *Service) loginDevice(ctx context.Context, u *store.User, selector string) (*store.Device, error) {
	devs, err := s.activeDevices(ctx, u)
	if err != nil {
		return nil, err
	}
	if selector == "" || selector == "auto" {
		if len(devs) == 0 {
			return nil, ErrUnknownDevice
		}
		return &devs[0], nil
	}
	for i := range devs {
		if devs[i].ID == selector {
			return &devs[i], nil
		}
	}
	if d, err := s.Store.Device(ctx, selector); err == nil && d.UserID != u.ID {
		return nil, ErrNotOwner
	}
	return nil, ErrUnknownDevice
}

// PreauthResult is one of: Deny, why the user may not sign in with push; EnrollURL, where the user
// enrolls a first device; or Devices, the active devices, most recently used first.
type PreauthResult struct {
	Deny      error
	EnrollURL string
	Devices   []store.Device
}

// Preauth reports whether ref can sign in with push, and on which devices. An unknown user is sent
// to enroll, like a known one with no active device.
func (s *Service) Preauth(ctx context.Context, ref UserRef) (PreauthResult, error) {
	cfg := s.Config()
	// Before the lookup, so the kill switch answers the same for every username.
	if err := eligible(cfg, nil, nil); err != nil {
		return PreauthResult{Deny: err}, nil
	}
	u, err := s.resolveUser(ctx, ref)
	var devs []store.Device
	switch {
	case errors.Is(err, ErrUnknownUser):
	case err != nil:
		return PreauthResult{}, err
	default:
		if err := eligible(cfg, u, nil); err != nil {
			return PreauthResult{Deny: err}, nil
		}
		if devs, err = s.activeDevices(ctx, u); err != nil {
			return PreauthResult{}, err
		}
	}
	switch {
	case len(devs) > 0:
		return PreauthResult{Devices: devs}, nil
	case cfg.EnrollPortalURL == "":
		return PreauthResult{Deny: ErrEnrollmentRequired}, nil
	default:
		return PreauthResult{EnrollURL: cfg.EnrollPortalURL}, nil
	}
}

type AuthRequest struct {
	User UserRef
	// Device is a device ID, or "auto" or empty for the most recently used device.
	Device          string
	IPAddr          string
	TargetURL       string
	DisplayUsername string
	// Timeout is how long the push stays open; zero means push-timeout. The caller's response
	// deadline must outlast it.
	Timeout time.Duration
}

// Authenticate pushes a sign-in request to the device and blocks until it is approved, denied or
// times out. Any failure resolves to a non-allow state; the error says why: ErrUnknownUser,
// ErrUnknownDevice or ErrNotOwner when the request names nothing the user may use, an eligibility
// error, or a failure to push. The state is empty only when the user or device could not be looked
// up (a store failure), before anything was pushed.
func (s *Service) Authenticate(ctx context.Context, r AuthRequest) (store.ChallengeState, error) {
	cfg := s.Config()
	u, err := s.resolveUser(ctx, r.User)
	if errors.Is(err, ErrUnknownUser) {
		return store.StateDeny, err
	} else if err != nil {
		return "", err
	}
	d, err := s.loginDevice(ctx, u, r.Device)
	if errors.Is(err, ErrUnknownDevice) || errors.Is(err, ErrNotOwner) {
		return store.StateDeny, err
	} else if err != nil {
		return "", err
	}
	if err := eligible(cfg, u, d); err != nil {
		return store.StateDeny, err
	}
	if r.DisplayUsername == "" {
		r.DisplayUsername = u.Username
	}
	if r.Timeout == 0 {
		r.Timeout = cfg.PushTimeout.D()
	}
	c, denyToken, err := s.Challenges.Create(ctx, challenge.Params{
		Username: u.Username, DeviceID: d.ID, IPAddr: r.IPAddr, TargetURL: r.TargetURL,
		DisplayUsername: r.DisplayUsername, TTL: r.Timeout,
	})
	if err != nil {
		return store.StateDeny, err
	}
	approveURL := cfg.PublicURL + "/challenge/" + c.ID
	if err := s.Ntfy.Publish(ctx, &ntfy.Message{
		Topic:      d.NtfyTopic,
		SequenceID: c.ID,
		Title:      "Sign-in request",
		Message:    Describe(c),
		Priority:   4,
		Tags:       []string{"lock"},
		Click:      approveURL,
		Actions: []ntfy.Action{
			{Action: "view", Label: "Approve", URL: approveURL, Clear: true},
			{Action: "http", Label: "Deny", URL: approveURL + "/deny", Method: "POST", Body: denyToken, Clear: true},
		},
	}); err != nil {
		_ = s.Challenges.Decide(context.WithoutCancel(ctx), c.ID, store.StateDeny)
		return store.StateDeny, fmt.Errorf("publish: %w", err)
	}
	s.Store.Audit(ctx, u.Username, "push_sent", map[string]any{"challenge": c.ID, "device": d.ID, "ipaddr": r.IPAddr})
	bg := context.WithoutCancel(ctx)
	state, err := s.Challenges.Wait(ctx, c)
	if state == store.StateAllow {
		// The user, device or kill switch may have changed while the push was on the phone.
		if err = s.checkEligible(bg, d.ID); err != nil {
			state = store.StateDeny
		}
	}
	s.Store.Audit(bg, u.Username, "auth_"+string(state), map[string]any{"challenge": c.ID, "device": d.ID})
	return state, err
}

// checkEligible re-reads what can change while a push is pending and reports why a login on
// deviceID may not be allowed now.
func (s *Service) checkEligible(ctx context.Context, deviceID string) error {
	d, err := s.Store.Device(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrDeviceRevoked
	} else if err != nil {
		return err
	}
	u, err := s.Store.UserByID(ctx, d.UserID)
	if err != nil {
		return err
	}
	return eligible(s.Config(), u, d)
}

// allow decides a pending challenge as allowed if its login is still eligible.
func (s *Service) allow(ctx context.Context, c *store.Challenge) error {
	if err := s.checkEligible(ctx, c.DeviceID); err != nil {
		return err
	}
	// The store re-checks device and user in the same statement, closing the race with a
	// concurrent revoke or disable.
	return s.Challenges.Decide(ctx, c.ID, store.StateAllow)
}

// Describe is the human summary shown in the push and on the approve page.
func Describe(c *store.Challenge) string {
	msg := c.DisplayUsername
	if c.IPAddr != "" {
		msg += " from " + c.IPAddr
	}
	if u, err := url.Parse(c.TargetURL); err == nil && u.Host != "" {
		msg += " to " + u.Host
	}
	return msg
}

// PendingChallenge returns the challenge if it can still be decided.
func (s *Service) PendingChallenge(ctx context.Context, id string) (*store.Challenge, error) {
	c, err := s.Store.Challenge(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, challenge.ErrGone
	} else if err != nil {
		return nil, err
	}
	if c.State != store.StatePending || !time.Now().Before(c.ExpiresAt) {
		return nil, challenge.ErrGone
	}
	return c, nil
}

// devicePasskeys returns the device c was pushed to and its passkeys, the only ones that may
// approve c.
func (s *Service) devicePasskeys(ctx context.Context, c *store.Challenge) (*store.Device, []store.Passkey, error) {
	d, err := s.Store.Device(ctx, c.DeviceID)
	if err != nil {
		return nil, nil, err
	}
	pks, err := s.Store.Passkeys(ctx, d.ID)
	return d, pks, err
}

// AssertionOptions returns the navigator.credentials.get() options for a pending challenge: its
// nonce, restricted to the passkeys of the device the push went to.
func (s *Service) AssertionOptions(ctx context.Context, id string) (json.RawMessage, error) {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return nil, err
	}
	d, pks, err := s.devicePasskeys(ctx, c)
	if err != nil {
		return nil, err
	}
	return s.RP.BeginLogin(d.UserID, pks, c.Nonce)
}

// Approve allows the challenge if assertion is a valid signature over its nonce by its device.
func (s *Service) Approve(ctx context.Context, id string, assertion io.Reader) error {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return err
	}
	d, pks, err := s.devicePasskeys(ctx, c)
	if err != nil {
		return err
	}
	pk, regressed, err := s.RP.FinishLogin(d.UserID, pks, c.Nonce, assertion)
	if err != nil {
		s.Store.Audit(ctx, c.Username, "assertion_failed", map[string]any{"challenge": id, "err": err.Error()})
		return err
	}
	if err := s.allow(ctx, c); err != nil {
		return err
	}
	if regressed {
		s.Log.Warn("passkey sign count regressed", "user", c.Username, "device", c.DeviceID)
		s.Store.Audit(ctx, c.Username, "sign_count_regressed", map[string]any{"device": c.DeviceID})
	}
	_ = s.Store.UpdatePasskey(ctx, pk.CredID, pk.CredentialJSON, pk.SignCount)
	_ = s.Store.TouchDevice(ctx, c.DeviceID)
	return nil
}

// AdminApprove allows a challenge without a passkey. Only the CLI calls it.
func (s *Service) AdminApprove(ctx context.Context, id string) error {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return err
	}
	if err := s.allow(ctx, c); err != nil {
		return err
	}
	s.Store.Audit(ctx, c.Username, "admin_approve", map[string]any{"challenge": id})
	return nil
}
