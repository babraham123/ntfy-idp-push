package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/babraham123/ntfy-idp-push/internal/challenge"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

type AuthRequest struct {
	User            *store.User
	Device          *store.Device
	IPAddr          string
	TargetURL       string
	DisplayUsername string
}

// Authenticate pushes a sign-in request to the device and blocks until it is approved, denied or
// times out. Any failure resolves to a non-allow state.
func (s *Service) Authenticate(ctx context.Context, r AuthRequest) (store.ChallengeState, error) {
	cfg := s.Config()
	if cfg.PushDisabled {
		return store.StateDeny, ErrPushDisabled
	}
	if r.User.DisabledAt != nil {
		return store.StateDeny, ErrUserDisabled
	}
	if r.Device.UserID != r.User.ID || r.Device.VerifiedAt == nil {
		return store.StateDeny, ErrNotOwner
	}
	if r.DisplayUsername == "" {
		r.DisplayUsername = r.User.Username
	}
	c, denyToken, err := s.Challenges.Create(ctx, challenge.Params{
		Username: r.User.Username, DeviceID: r.Device.ID, IPAddr: r.IPAddr, TargetURL: r.TargetURL,
		DisplayUsername: r.DisplayUsername, TTL: cfg.PushTimeout.D(),
	})
	if err != nil {
		return store.StateDeny, err
	}
	approveURL := cfg.PublicURL + "/c/" + c.ID
	if err := s.Ntfy.Publish(ctx, &ntfy.Message{
		Topic:      r.Device.NtfyTopic,
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
	s.Store.Audit(ctx, r.User.Username, "push_sent", map[string]any{"challenge": c.ID, "device": r.Device.ID, "ipaddr": r.IPAddr})
	bg := context.WithoutCancel(ctx)
	state, err := s.Challenges.Wait(ctx, c)
	if state == store.StateAllow {
		// The user, device or kill switch may have changed while the push was on the phone.
		if err = s.checkEligible(bg, r.Device.ID); err != nil {
			state = store.StateDeny
		}
	}
	s.Store.Audit(bg, r.User.Username, "auth_"+string(state), map[string]any{"challenge": c.ID, "device": r.Device.ID})
	return state, err
}

// checkEligible re-reads what can change while a push is pending and reports why a login on
// deviceID may not be allowed now.
func (s *Service) checkEligible(ctx context.Context, deviceID string) error {
	if s.Config().PushDisabled {
		return ErrPushDisabled
	}
	d, err := s.Store.Device(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrDeviceRevoked
	} else if err != nil {
		return err
	}
	if d.RevokedAt != nil || d.VerifiedAt == nil {
		return ErrDeviceRevoked
	}
	u, err := s.Store.UserByID(ctx, d.UserID)
	if err != nil {
		return err
	}
	if u.DisabledAt != nil {
		return ErrUserDisabled
	}
	return nil
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

func (s *Service) deviceOwner(ctx context.Context, c *store.Challenge) (webauthn.Owner, error) {
	d, err := s.Store.Device(ctx, c.DeviceID)
	if err != nil {
		return webauthn.Owner{}, err
	}
	pks, err := s.Store.Passkeys(ctx, d.ID)
	if err != nil {
		return webauthn.Owner{}, err
	}
	creds := make([]gowebauthn.Credential, 0, len(pks))
	for _, p := range pks {
		cred, err := webauthn.UnmarshalCredential(p.CredentialJSON)
		if err != nil {
			return webauthn.Owner{}, err
		}
		if s.RP.Allowed(&cred) {
			creds = append(creds, cred)
		}
	}
	if len(creds) == 0 {
		return webauthn.Owner{}, webauthn.ErrNoUsableCredential
	}
	return webauthn.Owner{UserID: d.UserID, Username: d.Username, DisplayName: d.Username, Credentials: creds}, nil
}

// AssertionOptions returns the navigator.credentials.get() options for a pending challenge: its
// nonce, restricted to the passkeys of the device the push went to.
func (s *Service) AssertionOptions(ctx context.Context, id string) (*protocol.CredentialAssertion, error) {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return nil, err
	}
	o, err := s.deviceOwner(ctx, c)
	if err != nil {
		return nil, err
	}
	return s.RP.BeginAssertion(o, c.Nonce)
}

// Approve allows the challenge if assertion is a valid signature over its nonce by its device.
func (s *Service) Approve(ctx context.Context, id string, assertion io.Reader) error {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return err
	}
	o, err := s.deviceOwner(ctx, c)
	if err != nil {
		return err
	}
	cred, err := s.RP.FinishAssertion(o, c.Nonce, assertion)
	if err != nil {
		s.Store.Audit(ctx, c.Username, "assertion_failed", map[string]any{"challenge": id, "err": err.Error()})
		return err
	}
	if err := s.allow(ctx, c); err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		// Passkeys commonly report a zero counter, so a regression is logged, not refused.
		s.Log.Warn("passkey sign count regressed", "user", c.Username, "device", c.DeviceID)
		s.Store.Audit(ctx, c.Username, "sign_count_regressed", map[string]any{"device": c.DeviceID})
	}
	if stored := webauthn.FindCredential(o.Credentials, cred.ID); stored != nil {
		stored.Authenticator.SignCount = cred.Authenticator.SignCount
		if b, err := webauthn.MarshalCredential(stored); err == nil {
			_ = s.Store.UpdatePasskey(ctx, cred.ID, b, cred.Authenticator.SignCount)
		}
	}
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
