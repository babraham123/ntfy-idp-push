// Package webauthn binds approvals to a device-bound passkey on the enrolled phone.
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

// Owner is the WebAuthn user entity for a device: the user handle is the shim's user ID, and
// credentials are only those of the one device being registered or asserted against.
type Owner struct {
	UserID      string
	Username    string
	DisplayName string
	Credentials []gowebauthn.Credential
}

func (o Owner) WebAuthnID() []byte                           { return []byte(o.UserID) }
func (o Owner) WebAuthnName() string                         { return o.Username }
func (o Owner) WebAuthnDisplayName() string                  { return o.DisplayName }
func (o Owner) WebAuthnCredentials() []gowebauthn.Credential { return o.Credentials }

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

func (rp *RP) BeginRegistration(o Owner) (*protocol.CredentialCreation, *gowebauthn.SessionData, error) {
	return rp.wa.BeginRegistration(o, gowebauthn.WithExclusions(gowebauthn.Credentials(o.Credentials).CredentialDescriptors()))
}

// FinishRegistration verifies an attestation response and applies the device-binding policy.
func (rp *RP) FinishRegistration(o Owner, session gowebauthn.SessionData, body io.Reader) (*gowebauthn.Credential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(body)
	if err != nil {
		return nil, describe(err)
	}
	if !rp.cfg.AllowSynced && parsed.Response.AttestationObject.AuthData.Flags.HasBackupEligible() {
		return nil, ErrSynced
	}
	cred, err := rp.wa.CreateCredential(o, session, parsed)
	if err != nil {
		return nil, describe(err)
	}
	if !cred.Flags.UserVerified {
		return nil, ErrNotUserVerified
	}
	if rp.cfg.RequireAttestation && (cred.AttestationFormat == "" || cred.AttestationFormat == "none") {
		return nil, ErrNoAttestation
	}
	return cred, nil
}

// assertionSession is derived from the stored challenge, so nothing about a pending login needs
// to be kept outside the challenge row.
func (rp *RP) assertionSession(o Owner, nonce []byte) (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	return rp.wa.BeginLogin(o, gowebauthn.WithChallenge(nonce), gowebauthn.WithUserVerification(protocol.VerificationRequired))
}

func (rp *RP) BeginAssertion(o Owner, nonce []byte) (*protocol.CredentialAssertion, error) {
	a, _, err := rp.assertionSession(o, nonce)
	return a, err
}

// Allowed reports whether a stored credential may still be used under the device-binding policy.
// go-webauthn applies its Filtering only at registration, so login checks it here.
func (rp *RP) Allowed(c *gowebauthn.Credential) bool {
	return rp.cfg.AllowSynced || !c.Flags.BackupEligible
}

// FinishAssertion verifies an assertion over nonce by one of o's credentials (UP and UV required,
// BE refused unless synced passkeys are allowed).
func (rp *RP) FinishAssertion(o Owner, nonce []byte, body io.Reader) (*gowebauthn.Credential, error) {
	_, session, err := rp.assertionSession(o, nonce)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(body)
	if err != nil {
		return nil, describe(err)
	}
	cred, err := rp.wa.ValidateLogin(o, *session, parsed)
	if err != nil {
		return nil, describe(err)
	}
	if !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return nil, ErrNotUserVerified
	}
	if !rp.cfg.AllowSynced && parsed.Response.AuthenticatorData.Flags.HasBackupEligible() {
		return nil, ErrSynced
	}
	return cred, nil
}

// FindCredential returns the stored credential matching id.
func FindCredential(creds []gowebauthn.Credential, id []byte) *gowebauthn.Credential {
	for i := range creds {
		if bytes.Equal(creds[i].ID, id) {
			return &creds[i]
		}
	}
	return nil
}

func MarshalCredential(c *gowebauthn.Credential) ([]byte, error) { return json.Marshal(c) }

func UnmarshalCredential(b []byte) (gowebauthn.Credential, error) {
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
