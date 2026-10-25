package core

import "errors"

// Every exported operation fails with a Failure, or with an internal error. A Failure says what
// kind of answer the adapter gives (Kind), which failure it is (Reason, a stable code the adapters
// key their wording on) and what a user may be told. Adapters never show internal errors to
// clients; they log them and answer generically.
type Failure struct {
	Kind   Kind
	Reason Reason
	text   string
	cause  error
}

// Reason identifies a failure across wrapping and copies: the adapters' tables are keyed by it.
type Reason string

// Kind classifies a failure for the adapters.
type Kind int

const (
	// Internal is any error that is not a Failure: a store, ntfy or programming failure.
	Internal Kind = iota
	// Refused: the request was understood and policy says no.
	Refused
	// Gone: something that was valid once no longer is.
	Gone
	// NotFound: the named user, device or link does not exist for the caller.
	NotFound
	// Invalid: the input itself is unacceptable.
	Invalid
)

func (f *Failure) Error() string   { return f.text }
func (f *Failure) Unwrap() error   { return f.cause }
func (f *Failure) Is(e error) bool { t, ok := e.(*Failure); return ok && t.Reason == f.Reason }

// because is f with cause behind it. With detail, the cause's text joins f's: the reason a user
// may act on. Without, the cause is only for the log.
func (f *Failure) because(cause error, detail bool) error {
	c := *f
	c.cause = cause
	if detail {
		c.text += ": " + cause.Error()
	}
	return &c
}

func fail(k Kind, r Reason, text string) *Failure { return &Failure{Kind: k, Reason: r, text: text} }

var (
	ErrUserDisabled    = fail(Refused, "user_disabled", "user disabled")
	ErrPushDisabled    = fail(Refused, "push_disabled", "push disabled")
	ErrDeviceRevoked   = fail(Refused, "device_revoked", "device revoked or not active")
	ErrNotOwner        = fail(Refused, "not_owner", "device does not belong to user")
	ErrForeignGrants   = fail(Refused, "foreign_grants", "ntfy user has grants the shim did not make; use --force")
	ErrIdentityChanged = fail(Refused, "identity_changed", "identity changed during enrollment")
	// ErrPasskeyPolicy is a webauthn refusal of the passkey (synced, no attestation, no user
	// verification, or none usable); the text names the reason.
	ErrPasskeyPolicy = fail(Refused, "passkey_policy", "passkey refused by policy")
	// ErrPasskeyRejected: the attestation or assertion did not verify (wrong origin, nonce,
	// credential, or signature). The detail is logged, never shown.
	ErrPasskeyRejected = fail(Refused, "passkey_rejected", "passkey verification failed")
	// ErrPasskeyCloned: the assertion's signature counter did not advance, so another copy of the
	// passkey has been signing. The device must be revoked and re-enrolled.
	ErrPasskeyCloned       = fail(Refused, "passkey_cloned", "this passkey may have been cloned; revoke the device and enroll it again")
	ErrBadToken            = fail(Refused, "bad_token", "invalid deny token")
	ErrEnrollmentRequired  = fail(Refused, "enrollment_required", "enrollment required")
	ErrTooManyPushes       = fail(Refused, "too_many_pushes", "too many sign-in requests; wait before trying again")
	ErrPushPending         = fail(Refused, "push_pending", "a sign-in request from another address is waiting on the phone")
	ErrNotInDirectory      = fail(Refused, "not_in_directory", "user is not in the directory")
	ErrNoDirectory         = fail(Refused, "no_directory", "no directory is configured")
	ErrDirectoryConfigured = fail(Refused, "directory_configured", "a directory is configured and decides each user's email")
	ErrNoEmail             = fail(Refused, "no_email", "user has no email address")

	ErrGone              = fail(Gone, "gone", "challenge already decided or expired")
	ErrInvalidCode       = fail(Gone, "invalid_code", "this enrollment link is invalid or has expired; ask for a new one")
	ErrEnrollmentExpired = fail(Gone, "enrollment_expired", "registration expired; start again")
	ErrResultExpired     = fail(Gone, "result_expired", "this page has expired; enroll again")
	ErrSetupLinkUsed     = fail(Gone, "setup_link_used", "this setup link was already used or is invalid")
	ErrSetupDone         = fail(Gone, "setup_done", "this phone is already set up or was removed")

	ErrUnknownUser   = fail(NotFound, "unknown_user", "unknown user")
	ErrUnknownDevice = fail(NotFound, "unknown_device", "unknown device")
	ErrUnknownTopic  = fail(NotFound, "unknown_topic", "not one of your default topics")

	ErrInvalidName  = fail(Invalid, "invalid_name", "invalid username")
	ErrInvalidEmail = fail(Invalid, "invalid_email", "invalid email address")
	ErrMalformed    = fail(Invalid, "malformed", "malformed passkey response")
)

// KindOf classifies err; nil and everything that is not a Failure classify as Internal.
func KindOf(err error) Kind {
	var f *Failure
	if errors.As(err, &f) {
		return f.Kind
	}
	return Internal
}

// ReasonOf is the Reason of the Failure behind err, or "" for an internal error.
func ReasonOf(err error) Reason {
	var f *Failure
	if errors.As(err, &f) {
		return f.Reason
	}
	return ""
}

// notFound turns the store's not-found into the failure naming what is missing.
func notFound(err error, missing *Failure) error {
	if errors.Is(err, errNotFound) {
		return missing
	}
	return err
}
