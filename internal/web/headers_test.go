package web_test

import (
	"strings"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

func TestSecurityHeaders(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	for _, path := range []string{"/enroll", "/static/app.js", "/auth/v2/ping", "/healthz", "/no-such-page"} {
		resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: path})
		for k, want := range map[string]string{
			"Strict-Transport-Security": "max-age=31536000",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
			"X-Robots-Tag":              "noindex, nofollow",
		} {
			if got := resp.Header.Get(k); got != want {
				t.Errorf("%s: %s %q, want %q", path, k, got, want)
			}
		}
	}
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/enroll", User: "alice"})
	csp := resp.Header.Get("Content-Security-Policy")
	for _, d := range []string{"form-action 'self'", "base-uri 'none'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP lacks %q: %s", d, csp)
		}
	}
}

func TestStaticServesOnlyFiles(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	resp, body := h.Do(t, testutil.Request{Method: "GET", Path: "/static/app.js"})
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") ||
		resp.Header.Get("ETag") == "" || !strings.Contains(resp.Header.Get("Cache-Control"), "max-age") || !strings.Contains(string(body), "navigator.credentials") {
		t.Fatalf("app.js: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/static/app.js", Header: map[string]string{"If-None-Match": resp.Header.Get("ETag")}})
	if resp.StatusCode != 304 {
		t.Fatalf("revalidation: %d", resp.StatusCode)
	}
	for _, p := range []string{"/static/", "/static/nope.js", "/templates/enroll.html"} {
		if resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: p}); resp.StatusCode != 404 {
			t.Errorf("%s: %d, want 404", p, resp.StatusCode)
		}
	}
}
