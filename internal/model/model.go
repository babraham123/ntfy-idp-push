// Package model holds the records the shim keeps about users, devices, passkeys, challenges and
// enrollment codes. core reasons about them and store persists them; the adapters (web, duoapi,
// webauthn, the CLI) see them only through core.
package model

import (
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
)

type User struct {
	ID         string
	Username   string
	Grants     []config.Grant // ntfy grants the shim applied from enroll-access
	DisabledAt *time.Time
	CreatedAt  time.Time
}

// Enabled reports whether the user may enroll and sign in.
func (u *User) Enabled() bool { return u.DisabledAt == nil }

// Device is a phone enrolled for push. It is pending until its owner opens the setup push, active
// until revoked, and keeps its row after revocation until its ntfy grant is cleaned up.
type Device struct {
	ID         string
	UserID     string
	Username   string
	Name       string
	NtfyTopic  string
	VerifiedAt *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// Active reports whether d can receive and approve logins: set up on the phone and not revoked.
func (d *Device) Active() bool { return d.VerifiedAt != nil && d.RevokedAt == nil }

// Pending reports whether d still awaits setup on the phone.
func (d *Device) Pending() bool { return d.VerifiedAt == nil && d.RevokedAt == nil }

type Passkey struct {
	CredID         []byte
	DeviceID       string
	CredentialJSON []byte
	AAGUID         []byte
	SignCount      uint32
}

// ChallengeState is where a login stands. Pending challenges are decided exactly once.
type ChallengeState string

const (
	StatePending ChallengeState = "pending"
	StateAllow   ChallengeState = "allow"
	StateDeny    ChallengeState = "deny"
	StateFraud   ChallengeState = "fraud"
	StateTimeout ChallengeState = "timeout"
)

type Challenge struct {
	ID              string
	Username        string
	DeviceID        string
	Nonce           []byte
	IPAddr          string
	TargetURL       string
	DisplayUsername string
	State           ChallengeState
	DenyTokenHash   []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       *time.Time
}

// Decidable reports whether the challenge can still be decided at now.
func (c *Challenge) Decidable(now time.Time) bool {
	return c.State == StatePending && now.Before(c.ExpiresAt)
}

type EnrollCode struct {
	Username  string
	DeviceID  string // set once a device enrolled with the code
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// Usable reports whether the code can still start an enrollment at now.
func (e *EnrollCode) Usable(now time.Time) bool { return e.UsedAt == nil && now.Before(e.ExpiresAt) }

type AuditEntry struct {
	TS       time.Time
	Username string
	Event    string
	Detail   string
}
