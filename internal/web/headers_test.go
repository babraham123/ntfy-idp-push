package web_test

import (
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
		} {
			if got := resp.Header.Get(k); got != want {
				t.Errorf("%s: %s %q, want %q", path, k, got, want)
			}
		}
	}
}
