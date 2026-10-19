package ntfy

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveServer exercises the client against a real ntfy server (requires auth-default-access:
// deny-all, NTFY_IDP_PUSH_TEST_NTFY_URL, and _TOKEN).
func TestLiveServer(t *testing.T) {
	base, token := os.Getenv("NTFY_IDP_PUSH_TEST_NTFY_URL"), os.Getenv("NTFY_IDP_PUSH_TEST_NTFY_TOKEN")
	if base == "" || token == "" {
		t.Skip("NTFY_IDP_PUSH_TEST_NTFY_URL / _TOKEN not set")
	}
	ctx := context.Background()
	c := New(base, token)
	user := "live-" + time.Now().Format("150405")
	t.Cleanup(func() { _ = c.DeleteUser(ctx, user) })

	if a, err := c.Account(ctx); err != nil || a.Role != "admin" {
		t.Fatalf("account: %+v %v", a, err)
	}
	if st, err := c.AnonymousReadStatus(ctx, "push-probe"); err != nil || (st != 401 && st != 403) {
		t.Fatalf("anonymous read: %d %v", st, err)
	}
	if err := c.AddUser(ctx, user, "pw-"+user); err != nil {
		t.Fatal(err)
	}
	if err := c.AllowAccess(ctx, user, "push-"+user, "read-only"); err != nil {
		t.Fatal(err)
	}
	if err := c.AllowAccess(ctx, user, user+"-*", "read-write"); err != nil {
		t.Fatal(err)
	}
	u, err := c.Accounts().Get(ctx, user)
	if err != nil || u == nil || len(u.Grants) != 2 {
		t.Fatalf("user: %+v %v", u, err)
	}
	if err := c.ResetAccess(ctx, user, user+"-*"); err != nil {
		t.Fatal(err)
	}

	// The user reads its push topic with its password; the push is published and then deleted by
	// sequence ID.
	if err := c.Publish(ctx, &Message{Topic: "push-" + user, SequenceID: "seq1", Message: "hi",
		Actions: []Action{{Action: "http", Label: "Deny", URL: "https://push.example.com/c/x/deny", Method: "POST", Body: "t", Clear: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteMessage(ctx, "push-"+user, "seq1"); err != nil {
		t.Fatal(err)
	}
	// asUser is the user's own app, signed in with its password.
	asUser := func(method, path, body string) int {
		req, err := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(user, "pw-"+user)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := asUser(http.MethodGet, "/push-"+user+"/json?poll=1", ""); st != http.StatusOK {
		t.Fatalf("user read: %d", st)
	}
	if st := asUser(http.MethodPost, "/push-"+user, "forged"); st != http.StatusForbidden {
		t.Fatalf("user publishing to its read-only push topic: %d", st)
	}
}
