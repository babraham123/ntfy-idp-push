package web_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/duosecurity/duo_api_golang/authapi"

	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// The devices page says the phone is cut off only when it is: a revoke that fails before the
// local revocation leaves the phone able to approve and asks to try again, and one that fails in
// the ntfy cleanup after it says the phone can no longer approve.
func TestRevokeFailureMessages(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	revoke := func(extra url.Values) (int, string) {
		t.Helper()
		resp, b := h.SubmitForm(t, "/devices", "alice", "/devices/"+dev.DeviceID+"/revoke", extra)
		return resp.StatusCode, string(b)
	}
	canApprove := func() bool {
		t.Helper()
		pre, err := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
		if err != nil {
			t.Fatal(err)
		}
		return len(pre.Response.Devices) == 1 && pre.Response.Devices[0].Device == dev.DeviceID
	}
	const cutOff, notRevoked = "can no longer approve sign-ins", "revoke the phone. Try again."

	// ntfy unreachable for the foreign-grant check a reset runs before anything is revoked.
	h.Ntfy.FailNext("GET", "/v1/users", 1)
	st, b := revoke(url.Values{"reset_ntfy": {"1"}})
	if st != 500 || !strings.Contains(b, notRevoked) || strings.Contains(b, cutOff) {
		t.Fatalf("failure before the local revocation: %d\n%s", st, b)
	}
	if !canApprove() {
		t.Fatal("the phone was revoked")
	}

	h.Ntfy.FailNext("DELETE", "/v1/users/access", 1)
	st, b = revoke(nil)
	if st != 500 || !strings.Contains(b, cutOff) || strings.Contains(b, notRevoked) {
		t.Fatalf("failure after the local revocation: %d\n%s", st, b)
	}
	if canApprove() {
		t.Fatal("the phone can still approve")
	}
}

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
