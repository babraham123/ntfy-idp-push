package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator flags (WebAuthn §6.1).
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
)

// Authenticator is a software platform authenticator with one ES256 credential, producing the
// JSON a browser would POST after navigator.credentials.create()/get().
type Authenticator struct {
	Origin string
	// Flags are set on every response in addition to UP (and AT on registration).
	Flags  byte
	CredID []byte
	key    *ecdsa.PrivateKey
	count  uint32
}

func NewAuthenticator(t *testing.T, origin string) *Authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	rand.Read(id)
	return &Authenticator{Origin: origin, Flags: FlagUV, CredID: id, key: key}
}

var b64 = base64.RawURLEncoding

type publicKeyOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
	} `json:"publicKey"`
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) authData(rpID string, flags byte, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	return append(out, attested...)
}

// Create answers credential creation options ({"publicKey": …}) with an attestation response.
func (a *Authenticator) Create(t *testing.T, options json.RawMessage) []byte {
	t.Helper()
	var o publicKeyOptions
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	pub, err := a.key.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		t.Fatal(err)
	}
	x, y := pub[1:33], pub[33:]
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	attested := make([]byte, 16) // zero AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.CredID)))
	attested = append(attested, a.CredID...)
	attested = append(attested, cose...)
	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(o.PublicKey.RP.ID, FlagUP|FlagAT|a.Flags, attested),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(a.CredID),
		"rawId":                   b64.EncodeToString(a.CredID),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", o.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal"},
		},
	})
	return b
}

// Get answers credential request options with an assertion signed by this credential.
func (a *Authenticator) Get(t *testing.T, options json.RawMessage) []byte {
	t.Helper()
	var o publicKeyOptions
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	a.count++
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	ad := a.authData(o.PublicKey.RPID, FlagUP|a.Flags, nil)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(a.CredID),
		"rawId":                   b64.EncodeToString(a.CredID),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
		},
	})
	return b
}
