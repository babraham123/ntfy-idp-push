package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/routes"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

// UserRef names a user by ID, or by username when ID is empty.
type UserRef struct{ ID, Username string }

func (s *Service) resolveUser(ctx context.Context, ref UserRef) (*model.User, error) {
	var u *model.User
	var err error
	if ref.ID != "" {
		u, err = s.store.UserByID(ctx, ref.ID)
	} else {
		u, err = s.store.UserByName(ctx, ref.Username)
	}
	return u, notFound(err, ErrUnknownUser)
}

// eligible determines if a device can receive/approve a push. Nil u/d skips checks for preauth.
// It serves preauth, the pre-flight before a push, and the re-check after approval; the decision
// itself is guarded by the store in the deciding statement (see decide).
func eligible(cfg *config.Config, u *model.User, d *model.Device) error {
	switch {
	case cfg.PushDisabled:
		return ErrPushDisabled
	case u == nil:
		return nil
	case !u.Enabled():
		return ErrUserDisabled
	case d == nil:
		return nil
	case d.UserID != u.ID:
		return ErrNotOwner
	case !d.Active():
		return ErrDeviceRevoked
	}
	return nil
}

// activeDevices lists u's active devices (MRU first).
func (s *Service) activeDevices(ctx context.Context, u *model.User) ([]model.Device, error) {
	devs, err := s.store.Devices(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	out := devs[:0]
	for _, d := range devs {
		if d.Active() {
			out = append(out, d)
		}
	}
	return out, nil
}

// loginDevice picks the active device a login goes to: deviceID, or the most recently used when
// empty.
func (s *Service) loginDevice(ctx context.Context, u *model.User, deviceID string) (*model.Device, error) {
	devs, err := s.activeDevices(ctx, u)
	if err != nil {
		return nil, err
	}
	if deviceID == "" {
		if len(devs) == 0 {
			return nil, ErrUnknownDevice
		}
		return &devs[0], nil
	}
	for i := range devs {
		if devs[i].ID == deviceID {
			return &devs[i], nil
		}
	}
	if d, err := s.store.Device(ctx, deviceID); err == nil && d.UserID != u.ID {
		return nil, ErrNotOwner
	}
	return nil, ErrUnknownDevice
}

// PreauthResult is either EnrollURL (for a first device) or Devices (MRU list).
type PreauthResult struct {
	EnrollURL string
	Devices   []model.Device
}

// Preauth reports if ref can sign in and via which devices. Unknown users or users without active
// devices are sent to enroll. As with Authenticate, a refusal is the error: an eligibility failure,
// or ErrEnrollmentRequired when there is nowhere to enroll; an internal failure is KindOf Internal.
func (s *Service) Preauth(ctx context.Context, ref UserRef) (PreauthResult, error) {
	cfg := s.Config()
	// Before the lookup, so the kill switch answers the same for every username.
	if err := eligible(cfg, nil, nil); err != nil {
		return PreauthResult{}, err
	}
	u, err := s.resolveUser(ctx, ref)
	var devs []model.Device
	switch {
	case errors.Is(err, ErrUnknownUser):
	case err != nil:
		return PreauthResult{}, err
	default:
		if err := eligible(cfg, u, nil); err != nil {
			return PreauthResult{}, err
		}
		if devs, err = s.activeDevices(ctx, u); err != nil {
			return PreauthResult{}, err
		}
	}
	switch {
	case len(devs) > 0:
		return PreauthResult{Devices: devs}, nil
	case cfg.EnrollPortalURL == "":
		return PreauthResult{}, ErrEnrollmentRequired
	default:
		return PreauthResult{EnrollURL: cfg.EnrollPortalURL}, nil
	}
}

type AuthRequest struct {
	User UserRef
	// Device is a device ID, or empty for the most recently used device.
	Device          string
	IPAddr          string
	TargetURL       string
	DisplayUsername string
	// Timeout defines push duration (0 = push-timeout). The caller's response deadline must
	// outlast this.
	Timeout time.Duration
}

// Authenticate pushes a sign-in request to the device and blocks until it is approved, denied or
// times out. The state is never pending; any failure resolves to a non-allow state and the error
// says why: ErrUnknownUser, ErrUnknownDevice or ErrNotOwner when the request names nothing the
// user may use, an eligibility error, or an internal failure (KindOf == Internal) to look up, push
// or wait.
func (s *Service) Authenticate(ctx context.Context, r AuthRequest) (model.ChallengeState, error) {
	cfg := s.Config()
	u, err := s.resolveUser(ctx, r.User)
	if err != nil {
		return model.StateDeny, err
	}
	d, err := s.loginDevice(ctx, u, r.Device)
	if err != nil {
		return model.StateDeny, err
	}
	if err := eligible(cfg, u, d); err != nil {
		return model.StateDeny, err
	}
	if r.DisplayUsername == "" {
		r.DisplayUsername = u.Username
	}
	if r.Timeout == 0 {
		r.Timeout = cfg.PushTimeout.D()
	}
	bg := context.WithoutCancel(ctx)
	// A push already on the phone is answered once for every login waiting on it: a retried
	// login joins it instead of stacking a second request on the screen.
	if c, err := s.pendingFor(ctx, d.ID); err != nil {
		return model.StateDeny, err
	} else if c != nil {
		s.store.Audit(ctx, u.Username, "push_joined", map[string]any{"challenge": c.ID, "device": d.ID, "ipaddr": r.IPAddr})
		return s.await(ctx, bg, u, d, c)
	}
	if !s.pushAllowed(u.Username) {
		return model.StateDeny, ErrTooManyPushes
	}
	c, denyToken, err := s.createChallenge(ctx, d, r)
	if err != nil {
		return model.StateDeny, err
	}
	if err := s.ntfy().SendLogin(ctx, ntfy.Login{
		Topic: d.NtfyTopic, ChallengeID: c.ID, Text: Describe(c),
		ApproveURL: routes.ApproveURL(cfg.PublicURL, c.ID), DenyURL: routes.DenyURL(cfg.PublicURL, c.ID), DenyToken: denyToken,
	}); err != nil {
		_ = s.decide(context.WithoutCancel(ctx), c.ID, model.StateDeny)
		return model.StateDeny, fmt.Errorf("publish: %w", err)
	}
	s.store.Audit(ctx, u.Username, "push_sent", map[string]any{"challenge": c.ID, "device": d.ID, "ipaddr": r.IPAddr})
	return s.await(ctx, bg, u, d, c)
}

// await blocks on c and turns its decision into the login's result.
func (s *Service) await(ctx, bg context.Context, u *model.User, d *model.Device, c *model.Challenge) (model.ChallengeState, error) {
	state, err := s.wait(ctx, c)
	if state == model.StateAllow {
		// The user, device or kill switch may have changed while the push was on the phone.
		if err = s.checkEligible(bg, d.ID); err != nil {
			state = model.StateDeny
		}
	}
	s.store.Audit(bg, u.Username, "auth_"+string(state), map[string]any{"challenge": c.ID, "device": d.ID})
	return state, err
}

// pendingFor is the challenge still waiting on device deviceID, or nil.
func (s *Service) pendingFor(ctx context.Context, deviceID string) (*model.Challenge, error) {
	ids, err := s.store.PendingChallengeIDs(ctx, store.ChallengeFilter{DeviceID: deviceID})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, id := range ids {
		c, err := s.store.Challenge(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		if c.Decidable(now) {
			return c, nil
		}
	}
	return nil, nil
}

// Pushes per user: a burst of pushBurst, then one every pushRefill. Repeated logins join the
// pending push instead, so this only bites a caller that keeps asking after each one is decided.
const (
	pushBurst  = 3
	pushRefill = 30 * time.Second
)

// pushAllowed takes one push from username's allowance.
func (s *Service) pushAllowed(username string) bool {
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	if len(s.pushes) > 1000 {
		for k, l := range s.pushes {
			if l.Tokens() >= pushBurst {
				delete(s.pushes, k)
			}
		}
	}
	l := s.pushes[username]
	if l == nil {
		l = rate.NewLimiter(rate.Every(pushRefill), pushBurst)
		s.pushes[username] = l
	}
	return l.Allow()
}

// checkEligible re-verifies push validity, reporting reasons for rejection.
func (s *Service) checkEligible(ctx context.Context, deviceID string) error {
	d, err := s.store.Device(ctx, deviceID)
	if err != nil {
		return notFound(err, ErrDeviceRevoked)
	}
	u, err := s.store.UserByID(ctx, d.UserID)
	if err != nil {
		return notFound(err, ErrDeviceRevoked)
	}
	return eligible(s.Config(), u, d)
}

// allow decides a pending challenge as allowed if its login is still eligible. The kill switch is
// checked here; the device and user conditions are checked by the store as it decides.
func (s *Service) allow(ctx context.Context, c *model.Challenge) error {
	if s.Config().PushDisabled {
		return ErrPushDisabled
	}
	return s.decide(ctx, c.ID, model.StateAllow)
}

// devicePasskeys returns the target device and its passkeys, which are the only ones allowed to
// approve c.
func (s *Service) devicePasskeys(ctx context.Context, c *model.Challenge) (*model.Device, []model.Passkey, error) {
	d, pks, err := s.store.DevicePasskeys(ctx, c.DeviceID)
	return d, pks, notFound(err, ErrDeviceRevoked)
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
	if err != nil {
		return nil, passkeyFailure(err)
	}
	return opts, nil
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
		s.store.Audit(ctx, c.Username, "assertion_failed", map[string]any{"challenge": id, "err": err.Error()})
		return passkeyFailure(err)
	}
	if err := s.allow(ctx, c); err != nil {
		return err
	}
	if regressed {
		s.Log.Warn("passkey sign count regressed", "user", c.Username, "device", c.DeviceID)
		s.store.Audit(ctx, c.Username, "sign_count_regressed", map[string]any{"device": c.DeviceID})
	}
	if err := s.store.RecordApproval(ctx, c.DeviceID, pk); err != nil {
		s.Log.Warn("record approval", "device", c.DeviceID, "err", err)
	}
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
	s.store.Audit(ctx, c.Username, "admin_approve", map[string]any{"challenge": id})
	return nil
}
