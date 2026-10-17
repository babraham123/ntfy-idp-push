package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// The self-service pages know the user only from the identity header, and only when a trusted
// proxy sent it. Nothing redirects to a login: the proxy's forward-auth step runs before the shim.
func TestPagesRequireProxyIdentity(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	for name, req := range map[string]testutil.Request{
		"anonymous page":   {Method: "GET", Path: "/devices"},
		"anonymous action": {Method: "POST", Path: "/devices/x/revoke"},
		"anonymous enroll": {Method: "GET", Path: "/enroll"},
		"anonymous begin":  {Method: "POST", Path: "/enroll/begin", Body: []byte(`{"name":"Phone"}`)},
		"blank header":     {Method: "GET", Path: "/provision", Header: map[string]string{"Remote-User": " "}},
		"other header":     {Method: "GET", Path: "/provision", Header: map[string]string{"X-Forwarded-User": "alice"}},
	} {
		if resp, _ := h.Do(t, req); resp.StatusCode != 401 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/devices", User: "alice"})
	if resp.StatusCode != 200 {
		t.Fatalf("signed in through the proxy: %d", resp.StatusCode)
	}

	// The same header from a peer that is not the proxy names nobody.
	h.Restart(t, func(c *config.Config) { c.TrustedProxies = []string{"10.0.0.0/8"} })
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/devices", User: "alice"})
	if resp.StatusCode != 401 {
		t.Fatalf("header from an untrusted peer: %d", resp.StatusCode)
	}

	// The header name follows the proxy in use.
	h.Restart(t, func(c *config.Config) {
		c.TrustedProxies, c.IdentityHeader = []string{"127.0.0.1/32", "::1/128"}, "X-authentik-username"
	})
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/devices", Header: map[string]string{"Remote-User": "alice"}})
	if resp.StatusCode != 401 {
		t.Fatalf("header the config does not name: %d", resp.StatusCode)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/devices", User: "alice"})
	if resp.StatusCode != 200 {
		t.Fatalf("configured header: %d", resp.StatusCode)
	}
}

// Token routes are bypassed at the proxy, so a client-sent identity header must mean nothing there:
// the enrollment code is the only credential, and the same handle cannot cross between the two
// route families.
func TestTokenRoutesIgnoreIdentity(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	forged := map[string]string{"Remote-User": "alice"}
	for name, req := range map[string]testutil.Request{
		"page":      {Method: "GET", Path: "/token/nosuchcode", Header: forged},
		"begin":     {Method: "POST", Path: "/token/begin", Body: []byte(`{"name":"Phone"}`), Header: forged},
		"bad begin": {Method: "POST", Path: "/token/begin", Body: []byte(`{"name":"Phone","code":"forged"}`), Header: forged},
		"finish":    {Method: "POST", Path: "/token/finish?token=nosuchhandle", Body: []byte(`{}`), Header: forged},
		"resend":    {Method: "POST", Path: "/token/resend", Body: []byte(`{"token":"forged"}`), Header: forged},
		"password":  {Method: "POST", Path: "/token/password", Body: []byte(`{"token":"forged"}`), Header: forged},
		"verify":    {Method: "POST", Path: "/token/verify/x", Body: []byte("t=forged"), Header: map[string]string{"Remote-User": "alice", "Content-Type": "application/x-www-form-urlencoded"}},
	} {
		resp, _ := h.Do(t, req)
		if resp.StatusCode != 410 && resp.StatusCode != 400 {
			t.Errorf("%s with a forged header: %d", name, resp.StatusCode)
		}
	}
	if _, _, err := h.Svc.DevicesOf(context.Background(), "alice"); err == nil {
		t.Fatal("a token route created alice from the forged header")
	}

	// A ceremony begun with identity cannot be finished on the bypassed route.
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	handle, opts, st := h.BeginEnroll(t, "alice", "", "Phone")
	if st != 200 {
		t.Fatalf("begin: %d", st)
	}
	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: "/token/finish?token=" + url.QueryEscape(handle), Body: a.Create(t, opts), Header: forged})
	if resp.StatusCode != 403 {
		t.Fatalf("identity ceremony finished on /token: %d", resp.StatusCode)
	}

	// A code ceremony runs entirely on /token, forged header or not, and the page names the code's
	// user rather than the header's.
	code, link, err := h.Svc.CreateEnrollCode(context.Background(), "erin", core.EnrollCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	resp, page := h.Do(t, testutil.Request{Method: "GET", Path: testutil.LocalPath(t, link), Header: forged})
	if resp.StatusCode != 200 || !strings.Contains(string(page), "<strong>erin</strong>") || !strings.Contains(string(page), `data-base="/token"`) {
		t.Fatalf("token page: %d %s", resp.StatusCode, page)
	}
	e, st, b := h.FinishEnroll(t, "", code, testutil.NewAuthenticator(t, testutil.PublicURL))
	if st != 200 || !e.HasCode {
		t.Fatalf("enroll by code: %d %s", st, b)
	}
	var out struct{ Username string }
	_ = json.Unmarshal(b, &out)
	if out.Username != "erin" {
		t.Fatalf("enrolled as %q", out.Username)
	}
}

// Links from before the route split carried the code as a query parameter.
func TestOldEnrollLinkRedirects(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/enroll?code=abc%2Fdef"})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/token/abc%2Fdef" {
		t.Fatalf("old link: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}
