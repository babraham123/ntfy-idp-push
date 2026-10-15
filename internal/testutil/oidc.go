package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

const (
	OIDCClientID     = "ntfy-idp-push"
	OIDCClientSecret = "oidc-secret"
)

// FakeOIDC is an OpenID provider that signs in whoever it is told to, without a login page: its
// authorization endpoint redirects straight back with a code.
type FakeOIDC struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu sync.Mutex
	// Claims are put in the next ID tokens; "sub" defaults to preferred_username.
	claims map[string]any
	codes  map[string]pendingCode
}

type pendingCode struct{ challenge, redirect string }

func NewFakeOIDC(t *testing.T) *FakeOIDC {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &FakeOIDC{key: key, codes: map[string]pendingCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/authorize",
			"token_endpoint":                        f.URL + "/token",
			"jwks_uri":                              f.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64.EncodeToString(key.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// SignIn sets the claims of the ID tokens issued from now on.
func (f *FakeOIDC) SignIn(claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = claims
}

func (f *FakeOIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != OIDCClientID || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	f.mu.Lock()
	f.codes[code] = pendingCode{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	f.mu.Unlock()
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
}

func (f *FakeOIDC) token(w http.ResponseWriter, r *http.Request) {
	id, secret, _ := r.BasicAuth()
	if id == "" {
		id, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	f.mu.Lock()
	pc, ok := f.codes[r.FormValue("code")]
	delete(f.codes, r.FormValue("code"))
	claims := map[string]any{}
	for k, v := range f.claims {
		claims[k] = v
	}
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
	if !ok || id != OIDCClientID || secret != OIDCClientSecret || b64.EncodeToString(sum[:]) != pc.challenge ||
		r.FormValue("redirect_uri") != pc.redirect {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	now := time.Now()
	std := map[string]any{"iss": f.URL, "aud": OIDCClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range std {
		if _, set := claims[k]; !set {
			claims[k] = v
		}
	}
	if _, set := claims["sub"]; !set {
		claims["sub"] = claims["preferred_username"]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": f.sign(claims),
	})
}

func (f *FakeOIDC) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	signed := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	return signed + "." + b64.EncodeToString(sig)
}
