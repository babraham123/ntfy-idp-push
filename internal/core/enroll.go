package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/routes"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

// CreateEnrollCode mints a single-use enrollment link that identifies username by itself, valid
// for ttl.
func (s *Service) CreateEnrollCode(ctx context.Context, username string, ttl time.Duration) (code, link string, expires time.Time, err error) {
	if err := ValidUsername(username); err != nil {
		return "", "", time.Time{}, err
	}
	code = token.Random(24)
	expires = time.Now().Add(ttl)
	err = s.store.CreateEnrollCode(ctx, token.Hash(code), model.EnrollCode{Username: username, ExpiresAt: expires})
	if err != nil {
		return "", "", time.Time{}, err
	}
	s.store.Audit(ctx, username, "enroll_link", map[string]any{"ttl": ttl.String()})
	return code, routes.EnrollURL(s.Config().PublicURL, code), expires, nil
}

// EnrollURL is the enrollment page for a code.
func (s *Service) EnrollURL(code string) string { return routes.EnrollURL(s.Config().PublicURL, code) }

// ResolveEnrollCode returns the username an unused, unexpired code was issued for.
func (s *Service) ResolveEnrollCode(ctx context.Context, code string) (string, error) {
	ec, err := s.store.EnrollCode(ctx, token.Hash(code))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !ec.Usable(time.Now())) {
		return "", ErrInvalidCode
	} else if err != nil {
		return "", err
	}
	return ec.Username, nil
}

// IdPEnrollment is what the IdP needs to show a user who enrolls through it: the code and link
// the phone uses, and the user ID it uses to poll EnrollmentState.
type IdPEnrollment struct {
	UserID, Username string
	Code, Link       string
	ExpiresAt        time.Time
}

// StartIdPEnrollment provisions username and issues an enrollment code, the IdP-driven way in.
func (s *Service) StartIdPEnrollment(ctx context.Context, username string) (*IdPEnrollment, error) {
	u, err := s.Provision(ctx, username)
	if err != nil {
		return nil, err
	}
	code, link, expires, err := s.CreateEnrollCode(ctx, username, EnrollCodeTTL)
	if err != nil {
		return nil, err
	}
	return &IdPEnrollment{UserID: u.ID, Username: u.Username, Code: code, Link: link, ExpiresAt: expires}, nil
}

// EnrollmentState is how far an IdP-driven enrollment has come.
type EnrollmentState int

const (
	// EnrollmentInvalid: the code is unknown, expired unused, or its device was revoked.
	EnrollmentInvalid EnrollmentState = iota
	// EnrollmentWaiting: no device yet, or one that its owner has not activated.
	EnrollmentWaiting
	// EnrollmentDone: the device is active.
	EnrollmentDone
)

// EnrollmentState reports the state of the enrollment code issued to userID.
func (s *Service) EnrollmentState(ctx context.Context, userID, code string) EnrollmentState {
	ec, err := s.store.EnrollCode(ctx, token.Hash(code))
	if err != nil {
		return EnrollmentInvalid
	}
	u, err := s.store.UserByName(ctx, ec.Username)
	if err != nil || u.ID != userID {
		return EnrollmentInvalid
	}
	if ec.DeviceID != "" {
		d, err := s.store.Device(ctx, ec.DeviceID)
		switch {
		case err != nil || d.RevokedAt != nil:
			return EnrollmentInvalid
		case d.Active():
			return EnrollmentDone
		}
		// Enrolled but not yet verified: still waiting until the unverified device is purged.
		return EnrollmentWaiting
	}
	if !ec.Usable(time.Now()) {
		return EnrollmentInvalid
	}
	return EnrollmentWaiting
}

// EnrollRequest says who is enrolling a device. A shim-issued Code identifies the user by itself;
// otherwise Username is the signed-in user.
type EnrollRequest struct {
	Code, Username, DeviceName string
}

// pendingEnrollment is a passkey ceremony between BeginEnrollment and FinishEnrollment.
type pendingEnrollment struct {
	username, name, code string
	session              webauthn.Session
	expires              time.Time
}

// enrollCeremonyTTL bounds how long the browser has between BeginEnrollment and FinishEnrollment,
// matching the registration timeout the passkey options carry.
const enrollCeremonyTTL = 5 * time.Minute

// deviceName normalizes what the user typed into the device's display name.
func deviceName(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = name[:64]
	}
	if name == "" {
		name = "Phone"
	}
	return name
}

// BeginEnrollment starts passkey registration for a new device and returns the handle the browser
// finishes it with, plus the navigator.credentials.create() options. The ceremony is held in this
// process for enrollCeremonyTTL.
func (s *Service) BeginEnrollment(ctx context.Context, r EnrollRequest) (handle string, options json.RawMessage, err error) {
	username := r.Username
	if r.Code != "" {
		if username, err = s.ResolveEnrollCode(ctx, r.Code); err != nil {
			return "", nil, err
		}
	}
	if err := ValidUsername(username); err != nil {
		return "", nil, err
	}
	name := deviceName(r.DeviceName)
	u, err := s.store.EnsureUser(ctx, username, uuid.NewString())
	if err != nil {
		return "", nil, err
	}
	if !u.Enabled() {
		return "", nil, ErrUserDisabled
	}
	options, session, err := s.rp.BeginRegistration(u, name)
	if err != nil {
		return "", nil, err
	}
	handle = token.Random(24)
	now := time.Now()
	s.enrollMu.Lock()
	for k, p := range s.enrolling {
		if now.After(p.expires) {
			delete(s.enrolling, k)
		}
	}
	s.enrolling[handle] = &pendingEnrollment{username: username, name: name, code: r.Code, session: session, expires: now.Add(enrollCeremonyTTL)}
	s.enrollMu.Unlock()
	return handle, options, nil
}

// takeEnrollment removes and returns the ceremony under handle, or nil when there is none or it
// has expired.
func (s *Service) takeEnrollment(handle string) *pendingEnrollment {
	s.enrollMu.Lock()
	p := s.enrolling[handle]
	delete(s.enrolling, handle)
	s.enrollMu.Unlock()
	if p == nil || time.Now().After(p.expires) {
		return nil
	}
	return p
}

type Enrollment struct {
	Device *model.Device
	// Handoff subscribes the phone's ntfy app to the device's topic.
	Handoff *Handoff
	// ResultToken lets the result page act for this device for EnrollResultTTL (see EnrolledDevice).
	ResultToken string
}

// EnrollResultTTL sets how long the enrollment result page works before requiring re-enrollment.
const EnrollResultTTL = time.Hour

// FinishEnrollment completes the ceremony begun under handle: it verifies the passkey, provisions
// the device and its grant, and sends the setup push. signedIn is the user the proxy names on this
// request ("" on token routes); when no code identifies the enrolling user, it must be the one who
// began. Failures roll everything back and release the code for another try.
func (s *Service) FinishEnrollment(ctx context.Context, handle, signedIn string, attestation io.Reader) (*Enrollment, error) {
	p := s.takeEnrollment(handle)
	if p == nil {
		return nil, ErrEnrollmentExpired
	}
	if p.code == "" && signedIn != p.username {
		return nil, ErrIdentityChanged
	}
	cfg := s.Config()
	u, err := s.store.UserByName(ctx, p.username)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownUser
	} else if err != nil {
		return nil, err
	}
	if !u.Enabled() {
		return nil, ErrUserDisabled
	}
	pk, attestationFormat, err := s.rp.FinishRegistration(u, p.session, attestation)
	if err != nil {
		return nil, passkeyFailure(err)
	}
	dev := &model.Device{ID: uuid.NewString(), UserID: u.ID, Username: p.username, Name: p.name}
	dev.NtfyTopic = cfg.NtfyTopicPrefix + dev.ID
	pk.DeviceID = dev.ID
	var codeHash []byte
	if p.code != "" {
		codeHash = token.Hash(p.code)
	}
	verifyToken, resultToken := token.Random(24), token.Random(24)
	err = s.store.CreateEnrollment(ctx, dev, token.Hash(verifyToken), token.Hash(resultToken), &pk, codeHash)
	if errors.Is(err, store.ErrCodeUnavailable) {
		return nil, ErrInvalidCode
	} else if err != nil {
		return nil, err
	}
	res, err := s.connectDevice(ctx, dev, verifyToken)
	if err != nil {
		s.undoEnrollment(context.WithoutCancel(ctx), dev, codeHash)
		return nil, err
	}
	s.store.Audit(ctx, p.username, "device_enrolled", map[string]any{"device": dev.ID, "name": p.name,
		"aaguid": uuidString(pk.AAGUID), "attestation": attestationFormat})
	res.ResultToken = resultToken
	return res, nil
}

// passkeyFailure sorts a webauthn error into policy refusals (which name their reason), malformed
// responses, and verification failures. Verification detail is logged by the caller, never shown.
func passkeyFailure(err error) error {
	switch {
	case errors.Is(err, webauthn.ErrSynced), errors.Is(err, webauthn.ErrNoUsableCredential),
		errors.Is(err, webauthn.ErrNoAttestation), errors.Is(err, webauthn.ErrNotUserVerified):
		return &wrapped{ErrPasskeyPolicy, err}
	case errors.Is(err, webauthn.ErrMalformed):
		return &wrapped{ErrMalformed, err}
	}
	return &wrapped{ErrPasskeyRejected, err}
}

// wrapped is a core sentinel with the cause behind it; the message is the sentinel's reason plus the
// cause's, which for policy and malformed errors is the user-facing reason.
type wrapped struct{ kind, cause error }

func (w *wrapped) Error() string {
	if errors.Is(w.kind, ErrPasskeyRejected) {
		return w.kind.Error()
	}
	return w.kind.Error() + ": " + w.cause.Error()
}
func (w *wrapped) Is(target error) bool { return errors.Is(w.kind, target) }
func (w *wrapped) Unwrap() error        { return w.cause }

// EnrolledDevice maps the result token (identity post-enrollment code consumption) to a device.
func (s *Service) EnrolledDevice(ctx context.Context, resultToken string) (*model.Device, error) {
	d, err := s.store.DeviceByResultToken(ctx, token.Hash(resultToken), time.Now(), EnrollResultTTL)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrResultExpired
	}
	return d, err
}

// connectDevice does enrollment's ntfy side: account, topic grant and setup push.
func (s *Service) connectDevice(ctx context.Context, dev *model.Device, verifyToken string) (*Enrollment, error) {
	if _, err := s.Provision(ctx, dev.Username); err != nil {
		return nil, err
	}
	if err := s.grantDevice(ctx, dev); err != nil {
		return nil, err
	}
	if err := s.publishSetup(ctx, dev, verifyToken); err != nil {
		return nil, err
	}
	return &Enrollment{Device: dev, Handoff: s.Handoff(dev.Username, []string{dev.NtfyTopic})}, nil
}

func (s *Service) publishSetup(ctx context.Context, dev *model.Device, verifyToken string) error {
	verifyURL := routes.VerifyURL(s.Config().PublicURL, dev.ID, verifyToken)
	return s.ntfy().Publish(ctx, &ntfy.Message{
		Topic:    dev.NtfyTopic,
		Title:    "Finish setup",
		Message:  "Tap to finish enrolling " + dev.Name + " for sign-in approvals.",
		Priority: 4,
		Tags:     []string{"key"},
		Click:    verifyURL,
		Actions:  []ntfy.Action{{Action: "view", Label: "Finish setup", URL: verifyURL, Clear: true}},
	})
}

// undoEnrollment rolls back half-built enrollments. Lingering state is cleaned up by Purge later.
func (s *Service) undoEnrollment(ctx context.Context, dev *model.Device, codeHash []byte) {
	if err := s.removeDevice(ctx, dev); err != nil {
		s.Log.Warn("enroll: undo", "device", dev.ID, "err", err)
	}
	if codeHash != nil {
		if err := s.store.ReleaseEnrollCode(ctx, codeHash); err != nil {
			s.Log.Warn("enroll: release code", "device", dev.ID, "err", err)
		}
	}
}

// ResendSetupPush republishes the setup push for username's device while it awaits setup.
func (s *Service) ResendSetupPush(ctx context.Context, deviceID, username string) error {
	d, err := s.ownedDevice(ctx, username, deviceID)
	if err != nil {
		return err
	}
	verifyToken := token.Random(24)
	ok, err := s.store.SetVerifyToken(ctx, d.ID, token.Hash(verifyToken))
	if err != nil {
		return err
	}
	if !ok {
		return ErrSetupDone
	}
	return s.publishSetup(ctx, d, verifyToken)
}

// ownedDevice is username's device deviceID. Another user's device is ErrUnknownDevice, the same
// as one that does not exist.
func (s *Service) ownedDevice(ctx context.Context, username, deviceID string) (*model.Device, error) {
	d, err := s.store.Device(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && d.Username != username) {
		return nil, ErrUnknownDevice
	}
	return d, err
}

func uuidString(b []byte) string {
	if id, err := uuid.FromBytes(b); err == nil {
		return id.String()
	}
	return ""
}

// VerifyDevice activates a device once its owner opened the setup push.
func (s *Service) VerifyDevice(ctx context.Context, deviceID, verifyToken string) error {
	if verifyToken == "" {
		return ErrSetupLinkUsed
	}
	ok, err := s.store.VerifyDevice(ctx, deviceID, token.Hash(verifyToken))
	if err != nil {
		return err
	}
	if !ok {
		return ErrSetupLinkUsed
	}
	if d, err := s.store.Device(ctx, deviceID); err == nil {
		s.store.Audit(ctx, d.Username, "device_verified", map[string]any{"device": deviceID})
	}
	return nil
}
