package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/babraham123/ntfy-idp-push/internal/challenge"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

// CreateEnrollCode mints a single-use /enroll?code=… link for username, which stands in for the
// user's identity on the enrollment page.
func (s *Service) CreateEnrollCode(ctx context.Context, username string, ttl time.Duration) (code, link string, err error) {
	if err := ValidUsername(username); err != nil {
		return "", "", err
	}
	code = challenge.RandomToken(24)
	err = s.Store.CreateEnrollCode(ctx, challenge.Hash(code), store.EnrollCode{Username: username, ExpiresAt: time.Now().Add(ttl)})
	if err != nil {
		return "", "", err
	}
	s.Store.Audit(ctx, username, "enroll_link", map[string]any{"ttl": ttl.String()})
	return code, s.EnrollURL(code), nil
}

func (s *Service) EnrollURL(code string) string {
	return s.Config().PublicURL + "/enroll?code=" + url.QueryEscape(code)
}

// ResolveEnrollCode returns the username an unused, unexpired code was issued for.
func (s *Service) ResolveEnrollCode(ctx context.Context, code string) (*store.EnrollCode, error) {
	ec, err := s.Store.EnrollCode(ctx, challenge.Hash(code))
	if errors.Is(err, store.ErrNotFound) || (err == nil && (ec.UsedAt != nil || !time.Now().Before(ec.ExpiresAt))) {
		return nil, ErrInvalidCode
	}
	return ec, err
}

// BeginEnrollment starts passkey registration for a new device of username.
func (s *Service) BeginEnrollment(ctx context.Context, username, deviceName string) (json.RawMessage, webauthn.Session, error) {
	if err := ValidUsername(username); err != nil {
		return nil, webauthn.Session{}, err
	}
	u, err := s.Store.EnsureUser(ctx, username, uuid.NewString())
	if err != nil {
		return nil, webauthn.Session{}, err
	}
	if u.DisabledAt != nil {
		return nil, webauthn.Session{}, ErrUserDisabled
	}
	return s.RP.BeginRegistration(u, deviceName)
}

type Enrollment struct {
	Device   *store.Device
	NtfyLink string
	// Code is nil when ntfy lacks the enroll endpoint. Stock ntfy apps ignore a code too, so the
	// manual sign-in path is offered either way.
	Code *ntfy.EnrollCode
	// ResultToken lets the result page act for this device for EnrollResultTTL (see EnrolledDevice).
	ResultToken string
}

// EnrollResultTTL bounds how long the enrollment result page keeps working; after that the user
// re-enrolls.
const EnrollResultTTL = time.Hour

// CompleteEnrollment verifies the passkey, creates the device and its ntfy topic grant, and sends
// the test push whose action verifies the device. enrollCode, when set, is claimed together with
// the device; a failure anywhere undoes the enrollment and releases the code for a retry.
func (s *Service) CompleteEnrollment(ctx context.Context, username, deviceName string, session webauthn.Session, attestation io.Reader, enrollCode string) (*Enrollment, error) {
	cfg := s.Config()
	u, err := s.Store.UserByName(ctx, username)
	if err != nil {
		return nil, err
	}
	if u.DisabledAt != nil {
		return nil, ErrUserDisabled
	}
	pk, attestationFormat, err := s.RP.FinishRegistration(u, session, attestation)
	if err != nil {
		return nil, err
	}
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		deviceName = "Phone"
	}
	dev := &store.Device{ID: uuid.NewString(), UserID: u.ID, Username: username, Name: deviceName}
	dev.NtfyTopic = cfg.NtfyTopicPrefix + dev.ID
	pk.DeviceID = dev.ID
	var codeHash []byte
	if enrollCode != "" {
		codeHash = challenge.Hash(enrollCode)
	}
	verifyToken, resultToken := challenge.RandomToken(24), challenge.RandomToken(24)
	err = s.Store.CreateEnrollment(ctx, dev, challenge.Hash(verifyToken), challenge.Hash(resultToken), &pk, codeHash)
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
	s.Store.Audit(ctx, username, "device_enrolled", map[string]any{"device": dev.ID, "name": deviceName,
		"aaguid": uuidString(pk.AAGUID), "attestation": attestationFormat})
	res.ResultToken = resultToken
	return res, nil
}

// EnrolledDevice resolves the token the enrollment result page holds, which stands in for the
// user's identity once a single-use enrollment code is spent.
func (s *Service) EnrolledDevice(ctx context.Context, resultToken string) (*store.Device, error) {
	d, err := s.Store.DeviceByResultToken(ctx, challenge.Hash(resultToken), time.Now(), EnrollResultTTL)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrInvalidCode
	}
	return d, err
}

// connectDevice does enrollment's ntfy side: account, topic grant, sign-in code and setup push.
func (s *Service) connectDevice(ctx context.Context, dev *store.Device, verifyToken string) (*Enrollment, error) {
	if _, err := s.Provision(ctx, dev.Username); err != nil {
		return nil, err
	}
	if err := s.Ntfy.AllowAccess(ctx, dev.Username, dev.NtfyTopic, config.PermReadOnly); err != nil {
		return nil, err
	}
	code, err := s.MintNtfyCode(ctx, dev.Username)
	if err != nil {
		return nil, err
	}
	if err := s.publishSetup(ctx, dev, verifyToken); err != nil {
		return nil, err
	}
	link := ""
	if code != nil {
		link = code.Code
	}
	return &Enrollment{Device: dev, NtfyLink: s.NtfyLink(dev.NtfyTopic, dev.Username, link), Code: code}, nil
}

func (s *Service) publishSetup(ctx context.Context, dev *store.Device, verifyToken string) error {
	verifyURL := fmt.Sprintf("%s/enroll/verify/%s?t=%s", s.Config().PublicURL, dev.ID, url.QueryEscape(verifyToken))
	return s.Ntfy.Publish(ctx, &ntfy.Message{
		Topic:    dev.NtfyTopic,
		Title:    "Finish setup",
		Message:  "Tap to finish enrolling " + dev.Name + " for sign-in approvals.",
		Priority: 4,
		Tags:     []string{"key"},
		Click:    verifyURL,
		Actions:  []ntfy.Action{{Action: "view", Label: "Finish setup", URL: verifyURL, Clear: true}},
	})
}

// undoEnrollment removes a half-built enrollment. Whatever it cannot remove is an unverified
// device, which Purge removes later.
func (s *Service) undoEnrollment(ctx context.Context, dev *store.Device, codeHash []byte) {
	if err := s.removeDevice(ctx, dev); err != nil {
		s.Log.Warn("enroll: undo", "device", dev.ID, "err", err)
	}
	if codeHash != nil {
		if err := s.Store.ReleaseEnrollCode(ctx, codeHash); err != nil {
			s.Log.Warn("enroll: release code", "device", dev.ID, "err", err)
		}
	}
}

// ResendSetupPush publishes a fresh "Finish setup" push to a device still awaiting setup, for when
// the first one was missed (e.g. the app was not signed in yet).
func (s *Service) ResendSetupPush(ctx context.Context, deviceID, username string) error {
	d, err := s.Store.Device(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && d.Username != username) {
		return ErrInvalidCode
	} else if err != nil {
		return err
	}
	verifyToken := challenge.RandomToken(24)
	ok, err := s.Store.SetVerifyToken(ctx, d.ID, challenge.Hash(verifyToken))
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCode
	}
	return s.publishSetup(ctx, d, verifyToken)
}

func uuidString(b []byte) string {
	if id, err := uuid.FromBytes(b); err == nil {
		return id.String()
	}
	return ""
}

// VerifyDevice activates a device once its owner opened the test push.
func (s *Service) VerifyDevice(ctx context.Context, deviceID, token string) error {
	ok, err := s.Store.VerifyDevice(ctx, deviceID, challenge.Hash(token))
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCode
	}
	if d, err := s.Store.Device(ctx, deviceID); err == nil {
		s.Store.Audit(ctx, d.Username, "device_verified", map[string]any{"device": deviceID})
	}
	return nil
}

// EnrollStatus reports IdP-driven enrollment progress: waiting, success or invalid.
func (s *Service) EnrollStatus(ctx context.Context, userID, code string) string {
	ec, err := s.Store.EnrollCode(ctx, challenge.Hash(code))
	if err != nil {
		return "invalid"
	}
	u, err := s.Store.UserByName(ctx, ec.Username)
	if err != nil || u.ID != userID {
		return "invalid"
	}
	if ec.DeviceID != "" {
		d, err := s.Store.Device(ctx, ec.DeviceID)
		switch {
		case err != nil || d.RevokedAt != nil:
			return "invalid"
		case d.VerifiedAt != nil:
			return "success"
		}
		// Enrolled but not yet verified: still waiting until the unverified device is purged.
		return "waiting"
	}
	if !time.Now().Before(ec.ExpiresAt) {
		return "invalid"
	}
	return "waiting"
}
