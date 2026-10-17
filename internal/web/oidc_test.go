package web_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

func oidcHarness(t *testing.T) (*testutil.Harness, *testutil.FakeOIDC) {
	t.Helper()
	idp := testutil.NewFakeOIDC(t)
	h := testutil.NewHarness(t, func(c *config.Config) {
		c.AuthMode = "oidc"
		c.OIDCIssuer, c.OIDCClientID, c.OIDCClientSecret = idp.URL, testutil.OIDCClientID, testutil.OIDCClientSecret
	})
	return h, idp
}

func cookie(resp *http.Response, name string) string {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c.Value
		}
	}
	return ""
}

// signIn simulates the OIDC browser login, allowing tamper on the callback.
func signIn(t *testing.T, h *testutil.Harness, next string, tamper func(q url.Values)) *http.Response {
	t.Helper()
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/oidc/login?next=" + url.QueryEscape(next)})
	flow := cookie(resp, "nip_oidc")
	if resp.StatusCode != http.StatusFound || flow == "" {
		t.Fatalf("login: %d, flow cookie %q", resp.StatusCode, flow)
	}
	resp, err := h.Client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("provider refused the authorization request: %d", resp.StatusCode)
	}
	cb, err := url.Parse(testutil.LocalPath(t, resp.Header.Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	q := cb.Query()
	if tamper != nil {
		tamper(q)
	}
	cb.RawQuery = q.Encode()
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: cb.String(), Header: map[string]string{"Cookie": "nip_oidc=" + flow}})
	return resp
}

func TestOIDCSignIn(t *testing.T) {
	h, idp := oidcHarness(t)
	idp.SignIn(map[string]any{"preferred_username": "dana"})

	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/provision"})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/oidc/login?next=%2Fprovision" {
		t.Fatalf("unauthenticated page: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = signIn(t, h, "/provision", nil)
	session := cookie(resp, "nip_session")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/provision" || session == "" {
		t.Fatalf("callback: %d %s, session %q", resp.StatusCode, resp.Header.Get("Location"), session)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/provision", Header: map[string]string{"Cookie": "nip_session=" + session}})
	if resp.StatusCode != http.StatusOK || h.Ntfy.User("dana") == nil {
		t.Fatalf("provision as the signed-in user: %d", resp.StatusCode)
	}
	// The page embeds a redeemable ntfy sign-in code.
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}

	// The user is whoever the provider says; a forged Remote-User means nothing in this mode.
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/provision", User: "dana"})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Remote-User honored under oidc: %d", resp.StatusCode)
	}

	if err := h.Store.CreateSession(context.Background(), "stale", "dana", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/provision", Header: map[string]string{"Cookie": "nip_session=stale"}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expired session: %d", resp.StatusCode)
	}
}

func TestOIDCRedirectStaysLocal(t *testing.T) {
	h, idp := oidcHarness(t)
	idp.SignIn(map[string]any{"preferred_username": "dana"})
	for next, want := range map[string]string{
		"/devices?tab=1":         "/devices?tab=1",
		"/\\evil.example/":       "/devices", // browsers read "\" as "/"
		"//evil.example/":        "/devices",
		"https://evil.example/":  "/devices",
		"/\t/evil.example/":      "/devices", // browsers drop tabs
		"devices":                "/devices",
		"/%5Cevil.example/":      "/%5Cevil.example/", // stays a path once decoded by the browser
		"/provision\n/x":         "/devices",
		"":                       "/devices",
		"/enroll?code=abc&x=%2F": "/enroll?code=abc&x=%2F",
	} {
		resp := signIn(t, h, next, nil)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
			t.Errorf("next %q: %d %q, want %q", next, resp.StatusCode, resp.Header.Get("Location"), want)
		}
	}
}

func TestOIDCCallbackRefusals(t *testing.T) {
	h, idp := oidcHarness(t)
	for name, c := range map[string]struct {
		claims map[string]any
		tamper func(url.Values)
	}{
		"state mismatch":        {claims: map[string]any{"preferred_username": "dana"}, tamper: func(q url.Values) { q.Set("state", "forged") }},
		"code replaced":         {claims: map[string]any{"preferred_username": "dana"}, tamper: func(q url.Values) { q.Set("code", "forged") }},
		"no preferred_username": {claims: map[string]any{"sub": "u1"}},
		"wrong audience":        {claims: map[string]any{"preferred_username": "dana", "aud": "another-client"}},
		"expired id token":      {claims: map[string]any{"preferred_username": "dana", "exp": time.Now().Add(-time.Hour).Unix()}},
		"wrong issuer":          {claims: map[string]any{"preferred_username": "dana", "iss": "https://evil.example"}},
	} {
		idp.SignIn(c.claims)
		resp := signIn(t, h, "/devices", c.tamper)
		if resp.StatusCode != http.StatusUnauthorized || cookie(resp, "nip_session") != "" {
			t.Errorf("%s: %d, session %q", name, resp.StatusCode, cookie(resp, "nip_session"))
		}
	}
	// A callback without the flow cookie set by /oidc/login is refused.
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/oidc/callback?code=x&state=y"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("callback without flow cookie: %d", resp.StatusCode)
	}
}
