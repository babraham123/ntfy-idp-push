package ntfy

import (
	"context"
	"net/http"
	"os"
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
	u, err := c.User(ctx, user)
	if err != nil || u == nil || len(u.Grants) != 2 {
		t.Fatalf("user: %+v %v", u, err)
	}
	if err := c.ResetAccess(ctx, user, user+"-*"); err != nil {
		t.Fatal(err)
	}

	first, err := c.MintEnrollCode(ctx, user)
	if err != nil {
		t.Fatalf("mint (needs ntfy#597): %v", err)
	}
	if d := time.Until(first.ExpiresAt()); d <= 0 || d > 11*time.Minute {
		t.Fatalf("expiry %s", d)
	}
	second, err := c.MintEnrollCode(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RedeemEnrollCode(ctx, first.Code, "x"); !IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("superseded code: %v", err)
	}
	tok, err := c.RedeemEnrollCode(ctx, second.Code, "Pixel")
	if err != nil || tok.Username != user || tok.Token == "" {
		t.Fatalf("redeem: %+v %v", tok, err)
	}
	if _, err := c.RedeemEnrollCode(ctx, second.Code, "Pixel"); err == nil {
		t.Fatal("redeemed twice")
	}
	if _, err := c.MintEnrollCode(ctx, "no-such-user-"+user); !IsStatus(err, http.StatusBadRequest) {
		t.Fatalf("unknown user: %v", err)
	}
	if a, _ := c.Account(ctx); a != nil {
		if _, err := c.MintEnrollCode(ctx, a.Username); !IsStatus(err, http.StatusUnauthorized) {
			t.Fatalf("admin user: %v", err)
		}
	}

	// The redeemed token reads its push topic; the push is published and then deleted by sequence ID.
	if err := c.Publish(ctx, &Message{Topic: "push-" + user, SequenceID: "seq1", Message: "hi",
		Actions: []Action{{Action: "http", Label: "Deny", URL: "https://push.example.com/c/x/deny", Method: "POST", Body: "t", Clear: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteMessage(ctx, "push-"+user, "seq1"); err != nil {
		t.Fatal(err)
	}
	phone := New(base, tok.Token)
	if err := phone.do(ctx, http.MethodGet, "/push-"+user+"/json?poll=1", nil, nil, true); err != nil {
		t.Fatalf("phone read: %v", err)
	}
	if err := phone.Publish(ctx, &Message{Topic: "push-" + user, Message: "forged"}); !IsStatus(err, http.StatusForbidden) {
		t.Fatalf("phone publishing to its read-only push topic: %v", err)
	}
}
