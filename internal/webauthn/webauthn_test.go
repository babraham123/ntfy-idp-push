package webauthn_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

var alice = &model.User{ID: "user-alice", Username: "alice"}

func newRP(t *testing.T, allowSynced bool) *webauthn.RP {
	t.Helper()
	rp, err := webauthn.New(webauthn.Config{RPID: "push.test", Origin: testutil.PublicURL, AllowSynced: allowSynced})
	if err != nil {
		t.Fatal(err)
	}
	return rp
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
	rp := newRP(t, false)
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
	rp := newRP(t, false)
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
		t.Fatal("backup-eligible assertion accepted")
	}
	a.Flags = 0
	if _, err := rp.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(a.Get(t, loginOptions(t, rp, []model.Passkey{pk}, n)))); err == nil {
		t.Fatal("assertion without user verification accepted")
	}
}

func TestSyncedPasskeyPolicy(t *testing.T) {
	strict, lenient := newRP(t, false), newRP(t, true)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	a.Flags |= testutil.FlagBE | testutil.FlagBS

	if _, err := register(t, strict, a); !errors.Is(err, webauthn.ErrSynced) {
		t.Fatalf("strict registration of a synced passkey: %v", err)
	}
	pk, err := register(t, lenient, a)
	if err != nil {
		t.Fatal(err)
	}
	n := nonce(t)
	assertion := a.Get(t, loginOptions(t, lenient, []model.Passkey{pk}, n))
	if _, err := lenient.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(assertion)); err != nil {
		t.Fatalf("lenient login with a synced passkey: %v", err)
	}

	// A synced passkey enrolled while allowed is locked out once the policy is tightened.
	if _, err := strict.BeginLogin(alice.ID, []model.Passkey{pk}, n); !errors.Is(err, webauthn.ErrNoUsableCredential) {
		t.Fatalf("strict begin with a synced passkey: %v", err)
	}
	if _, err := strict.FinishLogin(alice.ID, []model.Passkey{pk}, n, bytes.NewReader(assertion)); !errors.Is(err, webauthn.ErrNoUsableCredential) {
		t.Fatalf("strict finish with a synced passkey: %v", err)
	}
}
