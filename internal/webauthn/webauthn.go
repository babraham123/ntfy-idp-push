// Package webauthn binds approvals to a device-bound passkey on the enrolled phone. Callers deal
// only in store passkeys, browser options as JSON and an opaque registration Session, so
// go-webauthn's types and credential bookkeeping stay here.
package webauthn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/babraham123/ntfy-idp-push/internal/store"
)

var (
	ErrSynced          = errors.New("synced passkeys are not allowed; use a device-bound passkey")
	ErrNoAttestation   = errors.New("authenticator did not provide attestation")
	ErrNotUserVerified = errors.New("user verification is required")
	// ErrNoUsableCredential means every passkey of the device is excluded by policy (synced).
	ErrNoUsableCredential = errors.New("no passkey of this device is allowed; enroll a device-bound passkey")
)

type Config struct {
	RPID               string
	Origin             string
	AllowSynced        bool
	RequireAttestation bool
}

type RP struct {
	wa  *gowebauthn.WebAuthn
	cfg Config
}

// Session is a registration in progress, held by the caller between BeginRegistration and
// FinishRegistration.
type Session struct{ data gowebauthn.SessionData }

// owner is the WebAuthn user entity: the user handle is the shim's user ID, and credentials are
// only those of the one device being registered or asserted against.
type owner struct {
	id, name, displayName string
	creds                 []gowebauthn.Credential
}

func (o owner) WebAuthnID() []byte                           { return []byte(o.id) }
func (o owner) WebAuthnName() string                         { return o.name }
func (o owner) WebAuthnDisplayName() string                  { return o.displayName }
func (o owner) WebAuthnCredentials() []gowebauthn.Credential { return o.creds }

func New(cfg Config) (*RP, error) {
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         "ntfy-idp-push",
		RPOrigins:             []string{cfg.Origin},
		AttestationPreference: protocol.PreferDirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			ResidentKey:             protocol.ResidentKeyRequirementDiscouraged,
			UserVerification:        protocol.VerificationRequired,
		},
		Timeouts: gowebauthn.TimeoutsConfig{
			Login:        gowebauthn.TimeoutConfig{Enforce: true, Timeout: 2 * time.Minute},
			Registration: gowebauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute},
		},
		Filtering: &gowebauthn.FilteringConfig{ProhibitBackupEligibility: !cfg.AllowSynced},
	})
	if err != nil {
		return nil, err
	}
	return &RP{wa: wa, cfg: cfg}, nil
}

func registrant(u *store.User, deviceName string) owner {
	return owner{id: u.ID, name: u.Username, displayName: u.Username + " (" + deviceName + ")"}
}

// BeginRegistration returns the navigator.credentials.create() options for a new device of u.
func (rp *RP) BeginRegistration(u *store.User, deviceName string) (json.RawMessage, Session, error) {
	opts, session, err := rp.wa.BeginRegistration(registrant(u, deviceName))
	if err != nil {
		return nil, Session{}, err
	}
	b, err := json.Marshal(opts)
	return b, Session{*session}, err
}

// FinishRegistration verifies an attestation response under the device-binding policy and returns
// the passkey to store (without its DeviceID) and the attestation format.
func (rp *RP) FinishRegistration(u *store.User, session Session, attestation io.Reader) (_ store.Passkey, attestationFormat string, _ error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(attestation)
	if err != nil {
		return store.Passkey{}, "", describe(err)
	}
	if !rp.cfg.AllowSynced && parsed.Response.AttestationObject.AuthData.Flags.HasBackupEligible() {
		return store.Passkey{}, "", ErrSynced
	}
	cred, err := rp.wa.CreateCredential(registrant(u, ""), session.data, parsed)
	if err != nil {
		return store.Passkey{}, "", describe(err)
	}
	if !cred.Flags.UserVerified {
		return store.Passkey{}, "", ErrNotUserVerified
	}
	if rp.cfg.RequireAttestation && (cred.AttestationFormat == "" || cred.AttestationFormat == "none") {
		return store.Passkey{}, "", ErrNoAttestation
	}
	b, err := json.Marshal(cred)
	if err != nil {
		return store.Passkey{}, "", err
	}
	return store.Passkey{CredID: cred.ID, CredentialJSON: b, AAGUID: cred.Authenticator.AAGUID, SignCount: cred.Authenticator.SignCount},
		cred.AttestationFormat, nil
}

// asserter is the WebAuthn user for a login, holding only the passkeys the device-binding policy
// still allows. go-webauthn applies its Filtering only at registration, so login filters here.
func (rp *RP) asserter(userID string, passkeys []store.Passkey) (owner, error) {
	o := owner{id: userID}
	for _, p := range passkeys {
		cred, err := unmarshal(p.CredentialJSON)
		if err != nil {
			return owner{}, err
		}
		if rp.cfg.AllowSynced || !cred.Flags.BackupEligible {
			o.creds = append(o.creds, cred)
		}
	}
	if len(o.creds) == 0 {
		return owner{}, ErrNoUsableCredential
	}
	return o, nil
}

// loginSession is derived from the nonce, so nothing about a pending login needs to be kept
// outside the challenge row.
func (rp *RP) loginSession(userID string, passkeys []store.Passkey, nonce []byte) (owner, *protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	o, err := rp.asserter(userID, passkeys)
	if err != nil {
		return owner{}, nil, nil, err
	}
	opts, session, err := rp.wa.BeginLogin(o, gowebauthn.WithChallenge(nonce), gowebauthn.WithUserVerification(protocol.VerificationRequired))
	return o, opts, session, err
}

// BeginLogin returns the navigator.credentials.get() options for an assertion over nonce by one
// of passkeys.
func (rp *RP) BeginLogin(userID string, passkeys []store.Passkey, nonce []byte) (json.RawMessage, error) {
	_, opts, _, err := rp.loginSession(userID, passkeys, nonce)
	if err != nil {
		return nil, err
	}
	return json.Marshal(opts)
}

// FinishLogin verifies an assertion over nonce by one of passkeys (UP and UV required, BE refused
// unless synced passkeys are allowed) and returns that passkey with its new sign count.
// signCountRegressed reports a counter that did not advance; passkeys commonly report zero, so
// that is for the caller to log rather than a refusal.
func (rp *RP) FinishLogin(userID string, passkeys []store.Passkey, nonce []byte, assertion io.Reader) (_ store.Passkey, signCountRegressed bool, _ error) {
	o, _, session, err := rp.loginSession(userID, passkeys, nonce)
	if err != nil {
		return store.Passkey{}, false, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(assertion)
	if err != nil {
		return store.Passkey{}, false, describe(err)
	}
	cred, err := rp.wa.ValidateLogin(o, *session, parsed)
	if err != nil {
		return store.Passkey{}, false, describe(err)
	}
	if !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return store.Passkey{}, false, ErrNotUserVerified
	}
	if !rp.cfg.AllowSynced && parsed.Response.AuthenticatorData.Flags.HasBackupEligible() {
		return store.Passkey{}, false, ErrSynced
	}
	for _, p := range passkeys {
		if !bytes.Equal(p.CredID, cred.ID) {
			continue
		}
		// Only the counter moves; the rest of the record stays as registered.
		stored, err := unmarshal(p.CredentialJSON)
		if err != nil {
			return store.Passkey{}, false, err
		}
		stored.Authenticator.SignCount = cred.Authenticator.SignCount
		if p.CredentialJSON, err = json.Marshal(stored); err != nil {
			return store.Passkey{}, false, err
		}
		p.SignCount = cred.Authenticator.SignCount
		return p, cred.Authenticator.CloneWarning, nil
	}
	return store.Passkey{}, false, errors.New("asserted credential is not among the device's passkeys")
}

func unmarshal(b []byte) (gowebauthn.Credential, error) {
	var c gowebauthn.Credential
	return c, json.Unmarshal(b, &c)
}

// describe surfaces go-webauthn's DevInfo, which carries the actual reason a check failed.
func describe(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return fmt.Errorf("%s: %s", pe.Details, pe.DevInfo)
	}
	return err
}
