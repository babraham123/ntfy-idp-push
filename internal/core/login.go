package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

// UserRef names a user by ID (or username if ID is empty), mirroring Duo API's parameters.
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

// eligible determines if a device can receive/approve a push. Nil u/d skips checks for preauth.
// It serves preauth, the pre-flight before a push, and the re-check after approval; the decision
// itself is guarded by the store in the deciding statement (see decide).
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

// activeDevices lists u's active devices (MRU first).
func (s *Service) activeDevices(ctx context.Context, u *store.User) ([]store.Device, error) {
	devs, err := s.Store.Devices(ctx, u.ID)
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

// loginDevice maps the Duo device parameter to an active device ("auto" or empty gets the MRU one).
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

// PreauthResult is either Deny (reason), EnrollURL (for first device), or Devices (MRU list).
type PreauthResult struct {
	Deny      error
	EnrollURL string
	Devices   []store.Device
}

// Preauth reports if ref can sign in and via which devices. Unknown users or users without active
// devices are sent to enroll.
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
	// Timeout defines push duration (0 = push-timeout). The caller's response deadline must
	// outlast this.
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
	c, denyToken, err := s.createChallenge(ctx, d, r)
	if err != nil {
		return store.StateDeny, err
	}
	approveURL := cfg.PublicURL + "/challenge/" + c.ID
	if err := s.ntfy.Publish(ctx, &ntfy.Message{
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
		_ = s.decide(context.WithoutCancel(ctx), c.ID, store.StateDeny)
		return store.StateDeny, fmt.Errorf("publish: %w", err)
	}
	s.Store.Audit(ctx, u.Username, "push_sent", map[string]any{"challenge": c.ID, "device": d.ID, "ipaddr": r.IPAddr})
	bg := context.WithoutCancel(ctx)
	state, err := s.wait(ctx, c)
	if state == store.StateAllow {
		// The user, device or kill switch may have changed while the push was on the phone.
		if err = s.checkEligible(bg, d.ID); err != nil {
			state = store.StateDeny
		}
	}
	s.Store.Audit(bg, u.Username, "auth_"+string(state), map[string]any{"challenge": c.ID, "device": d.ID})
	return state, err
}

// checkEligible re-verifies push validity, reporting reasons for rejection.
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

// allow decides a pending challenge as allowed if its login is still eligible. The kill switch is
// checked here; the device and user conditions are checked by the store as it decides.
func (s *Service) allow(ctx context.Context, c *store.Challenge) error {
	if s.Config().PushDisabled {
		return ErrPushDisabled
	}
	return s.decide(ctx, c.ID, store.StateAllow)
}

// passkeyPolicy wraps webauthn's policy refusals so callers need not know the webauthn package.
func passkeyPolicy(err error) error {
	if errors.Is(err, webauthn.ErrSynced) || errors.Is(err, webauthn.ErrNoUsableCredential) {
		return fmt.Errorf("%w: %w", ErrPasskeyPolicy, err)
	}
	return err
}

// devicePasskeys returns the target device and its passkeys, which are the only ones allowed to
// approve c.
func (s *Service) devicePasskeys(ctx context.Context, c *store.Challenge) (*store.Device, []store.Passkey, error) {
	d, err := s.Store.Device(ctx, c.DeviceID)
	if err != nil {
		return nil, nil, err
	}
	pks, err := s.Store.Passkeys(ctx, d.ID)
	return d, pks, err
}

// AssertionOptions restricts navigator.credentials.get() options to the passkeys of the push's
// target device.
func (s *Service) AssertionOptions(ctx context.Context, id string) (json.RawMessage, error) {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return nil, err
	}
	d, pks, err := s.devicePasskeys(ctx, c)
	if err != nil {
		return nil, err
	}
	opts, err := s.rp.BeginLogin(d.UserID, pks, c.Nonce)
	return opts, passkeyPolicy(err)
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
	pk, regressed, err := s.rp.FinishLogin(d.UserID, pks, c.Nonce, assertion)
	if err != nil {
		s.Store.Audit(ctx, c.Username, "assertion_failed", map[string]any{"challenge": id, "err": err.Error()})
		return passkeyPolicy(err)
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
