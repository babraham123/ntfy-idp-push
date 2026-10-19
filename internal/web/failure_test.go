package web_test

import (
	"strings"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// Clients learn core's reason for a classified failure and nothing but "internal error" for the
// rest: an ntfy outage must not leak ntfy's response into the page.
func TestInternalErrorsAreNotEchoed(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	e, st, b := h.FinishEnroll(t, "alice", "", testutil.NewAuthenticator(t, testutil.PublicURL))
	if st != 200 {
		t.Fatalf("enroll: %d %s", st, b)
	}
	h.Ntfy.NextPublish(t)
	h.Ntfy.FailNext("POST", "/", 1)
	resp, b := h.Do(t, testutil.Request{Method: "POST", Path: "/token/resend", Body: []byte(`{"token":"` + e.ResultToken + `"}`)})
	if resp.StatusCode != 500 || strings.TrimSpace(string(b)) != `{"error":"internal error"}` {
		t.Fatalf("ntfy failure: %d %s", resp.StatusCode, b)
	}
	// A classified failure carries its reason.
	resp, b = h.Do(t, testutil.Request{Method: "POST", Path: "/token/resend", Body: []byte(`{"token":"forged"}`)})
	if resp.StatusCode != 410 || !strings.Contains(string(b), "expired") {
		t.Fatalf("forged result token: %d %s", resp.StatusCode, b)
	}
	resp, b = h.Do(t, testutil.Request{Method: "GET", Path: "/token/nosuchcode"})
	if resp.StatusCode != 410 || !strings.Contains(string(b), "Link expired") || !strings.Contains(string(b), "ask for a new one") {
		t.Fatalf("unknown code page: %d %s", resp.StatusCode, b)
	}
}
