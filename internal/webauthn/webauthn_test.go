package webauthn_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

var alice = &model.User{ID: "user-alice", Username: "alice"}

// newRP builds a relying party with the default policy: device-bound and attested, except the
// phones' built-in providers.
func newRP(t *testing.T) *webauthn.RP {
	t.Helper()
	var exempt []uuid.UUID
	for _, a := range config.PhonePasskeyProviders {
		exempt = append(exempt, uuid.MustParse(a))
	}
	return newRPWith(t, webauthn.Config{RequireAttestation: true, Exempt: exempt})
}

func newRPWith(t *testing.T, cfg webauthn.Config) *webauthn.RP {
	t.Helper()
	cfg.RPID, cfg.Origin = "push.test", testutil.PublicURL
	rp, err := webauthn.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func login(t *testing.T, rp *webauthn.RP, a *testutil.Authenticator, pk model.Passkey) error {
	t.Helper()
	n := nonce(t)
	_, err := rp.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(a.Get(t, loginOptions(t, rp, []model.Passkey{pk}, n))))
	return err
}

func register(t *testing.T, rp *webauthn.RP, a *testutil.Authenticator) (model.Passkey, error) {
	t.Helper()
	opts, session, err := rp.BeginRegistration(alice, "Pixel")
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := rp.FinishRegistration(alice, session, bytes.NewReader(a.Create(t, opts)))
	return pk, err
}

func nonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 32)
	rand.Read(n)
	return n
}

func loginOptions(t *testing.T, rp *webauthn.RP, pks []model.Passkey, n []byte) json.RawMessage {
	t.Helper()
	opts, err := rp.BeginLogin(alice.ID, pks, n)
	if err != nil {
		t.Fatal(err)
	}
	return opts
}

func TestRegisterThenLogin(t *testing.T) {
	rp := newRP(t)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	pk, err := register(t, rp, a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk.CredID, a.CredID) {
		t.Fatalf("registered credential %x, want %x", pk.CredID, a.CredID)
	}

	n := nonce(t)
	opts := loginOptions(t, rp, []model.Passkey{pk}, n)
	var o struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(opts, &o); err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	if o.PublicKey.Challenge != enc.EncodeToString(n) {
		t.Fatalf("challenge %q is not the nonce", o.PublicKey.Challenge)
	}
	if o.PublicKey.UserVerification != "required" {
		t.Fatalf("userVerification %q", o.PublicKey.UserVerification)
	}
	if len(o.PublicKey.AllowCredentials) != 1 || o.PublicKey.AllowCredentials[0].ID != enc.EncodeToString(a.CredID) {
		t.Fatalf("allowCredentials %+v", o.PublicKey.AllowCredentials)
	}

	first, second := a.Get(t, opts), a.Get(t, opts) // counters 1 and 2
	pk2, err := rp.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	if pk2.SignCount != 2 || !bytes.Equal(pk2.CredID, pk.CredID) {
		t.Fatalf("after login: sign count %d", pk2.SignCount)
	}

	// The returned record is what gets stored, so the next login must see its counter: one that
	// has not advanced past it is a clone's.
	if _, err := rp.FinishLogin(alice.ID, []model.Passkey{pk2}, n, bytes.NewReader(first)); !errors.Is(err, webauthn.ErrCloned) {
		t.Fatalf("stale counter: %v", err)
	}
}

func TestLoginRefusals(t *testing.T) {
	rp := newRP(t)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	pk, err := register(t, rp, a)
	if err != nil {
		t.Fatal(err)
	}
	other, err := register(t, rp, testutil.NewAuthenticator(t, testutil.PublicURL))
	if err != nil {
		t.Fatal(err)
	}
	n := nonce(t)
	assertion := a.Get(t, loginOptions(t, rp, []model.Passkey{pk}, n))

	if _, err := rp.FinishLogin(alice.ID, []model.Passkey{other}, n, bytes.NewReader(assertion)); err == nil {
		t.Fatal("assertion by another device's passkey accepted")
	}
	if _, err := rp.FinishLogin(alice.ID, []model.Passkey{pk}, nonce(t), bytes.NewReader(assertion)); err == nil {
		t.Fatal("assertion over another nonce accepted")
	}
	a.Flags |= testutil.FlagBE | testutil.FlagBS
	if _, err := rp.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(a.Get(t, loginOptions(t, rp, []model.Passkey{pk}, n)))); err == nil {
		t.Fatal("backup-eligible assertion by a device-bound passkey accepted")
	}
	a.Flags = 0
	if _, err := rp.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(a.Get(t, loginOptions(t, rp, []model.Passkey{pk}, n)))); err == nil {
		t.Fatal("assertion without user verification accepted")
	}
}

// Passkeys must be device-bound and attested, except phone passkeys from the phones' built-in
// providers, which are synced and attest "none"; user verification is required of all.
func TestPasskeyPolicy(t *testing.T) {
	rp := newRP(t)
	for _, aaguid := range config.PhonePasskeyProviders {
		a := testutil.NewAuthenticator(t, testutil.PublicURL).AsPhonePasskey(t, aaguid)
		pk, err := register(t, rp, a)
		if err != nil {
			t.Fatalf("phone passkey from %s: %v", aaguid, err)
		}
		if err := login(t, rp, a, pk); err != nil {
			t.Fatalf("phone passkey login from %s: %v", aaguid, err)
		}
	}

	const otherProvider = "d548826e-79b4-db40-a3d8-11116f7e8349" // a third-party password manager
	// want is the policy error, or nil where go-webauthn refuses first.
	for name, tc := range map[string]struct {
		a    *testutil.Authenticator
		want error
	}{
		"synced, other provider": {testutil.NewAuthenticator(t, testutil.PublicURL).AsPhonePasskey(t, otherProvider), webauthn.ErrSynced},
		"synced, no provider":    {testutil.NewAuthenticator(t, testutil.PublicURL).AsPhonePasskey(t, uuid.Nil.String()), webauthn.ErrSynced},
		"device-bound, unattested": {func() *testutil.Authenticator {
			a := testutil.NewAuthenticator(t, testutil.PublicURL)
			a.Unattested = true
			return a
		}(), webauthn.ErrNoAttestation},
		"exempt, no user verification": {func() *testutil.Authenticator {
			a := testutil.NewAuthenticator(t, testutil.PublicURL).AsPhonePasskey(t, config.AAGUIDGooglePasswordManager)
			a.Flags &^= testutil.FlagUV
			return a
		}(), nil},
	} {
		if _, err := register(t, rp, tc.a); err == nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// A passkey enrolled under a looser policy is locked out once it is tightened.
	lenient := newRPWith(t, webauthn.Config{AllowSynced: true})
	a := testutil.NewAuthenticator(t, testutil.PublicURL).AsPhonePasskey(t, otherProvider)
	pk, err := register(t, lenient, a)
	if err != nil {
		t.Fatal(err)
	}
	if err := login(t, lenient, a, pk); err != nil {
		t.Fatalf("lenient login: %v", err)
	}
	if _, err := rp.BeginLogin(alice.ID, []model.Passkey{pk}, nonce(t)); !errors.Is(err, webauthn.ErrNoUsableCredential) {
		t.Fatalf("strict begin with a synced passkey: %v", err)
	}
}
