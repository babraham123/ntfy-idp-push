package core

import "errors"

// Every exported operation fails with one of these, or with an internal error. Adapters map the
// Kind to a status or message in one place and never show internal errors to clients.
var (
	// Refused: the request was understood and policy says no.
	ErrUserDisabled    = errors.New("user disabled")
	ErrPushDisabled    = errors.New("push disabled")
	ErrDeviceRevoked   = errors.New("device revoked or not active")
	ErrNotOwner        = errors.New("device does not belong to user")
	ErrForeignGrants   = errors.New("ntfy user has grants the shim did not make; use --force")
	ErrIdentityChanged = errors.New("identity changed during enrollment")
	// ErrPasskeyPolicy is a webauthn refusal of the passkey (synced, no attestation, no user
	// verification, or none usable); the text names the reason.
	ErrPasskeyPolicy = errors.New("passkey refused by policy")
	// ErrPasskeyRejected: the attestation or assertion did not verify (wrong origin, nonce,
	// credential, or signature).
	ErrPasskeyRejected    = errors.New("passkey verification failed")
	ErrBadToken           = errors.New("invalid deny token")
	ErrEnrollmentRequired = errors.New("enrollment required")

	// Gone: something that was valid once no longer is.
	ErrGone              = errors.New("challenge already decided or expired")
	ErrInvalidCode       = errors.New("this enrollment link is invalid or has expired; ask for a new one")
	ErrEnrollmentExpired = errors.New("registration expired; start again")
	ErrResultExpired     = errors.New("this page has expired; enroll again")
	ErrSetupLinkUsed     = errors.New("this setup link was already used or is invalid")
	ErrSetupDone         = errors.New("this phone is already set up or was removed")

	// NotFound: the named user or device does not exist for the caller.
	ErrUnknownUser   = errors.New("unknown user")
	ErrUnknownDevice = errors.New("unknown device")

	// Invalid: the input itself is unacceptable.
	ErrInvalidName = errors.New("invalid username")
	ErrMalformed   = errors.New("malformed passkey response")
)

// Kind classifies a failure for the adapters.
type Kind int

const (
	// Internal is any error not listed above: a store, ntfy or programming failure. Adapters log it
	// and answer generically.
	Internal Kind = iota
	Refused
	Gone
	NotFound
	Invalid
)

var kinds = map[Kind][]error{
	Refused:  {ErrUserDisabled, ErrPushDisabled, ErrDeviceRevoked, ErrNotOwner, ErrForeignGrants, ErrIdentityChanged, ErrPasskeyPolicy, ErrPasskeyRejected, ErrBadToken, ErrEnrollmentRequired},
	Gone:     {ErrGone, ErrInvalidCode, ErrEnrollmentExpired, ErrResultExpired, ErrSetupLinkUsed, ErrSetupDone},
	NotFound: {ErrUnknownUser, ErrUnknownDevice},
	Invalid:  {ErrInvalidName, ErrMalformed},
}

// KindOf classifies err; nil is not a failure and classifies as Internal.
func KindOf(err error) Kind {
	for k, errs := range kinds {
		for _, e := range errs {
			if errors.Is(err, e) {
				return k
			}
		}
	}
	return Internal
}
