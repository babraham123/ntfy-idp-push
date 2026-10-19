package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/duosecurity/duo_api_golang/authapi"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/mail"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

var (
	carol = directory.Person{Username: "carol", Email: "carol@example.com", DisplayName: "Carol Danvers"}
	dave  = directory.Person{Username: "dave", Email: "dave@example.com", DisplayName: "Dave Lister"}
)

var passwordRe = regexp.MustCompile(`Password:\s+(\S+)`)

// welcomeTo asserts that addr has received want emails and returns the latest.
func welcomeTo(t *testing.T, h *testutil.Harness, addr string, want int) mail.Message {
	t.Helper()
	got := h.Mail.To(addr)
	if len(got) != want {
		t.Fatalf("%d emails to %s, want %d", len(got), addr, want)
	}
	return got[want-1]
}

// checkWelcome asserts that m carries everything p needs to sign the ntfy app in and subscribe
// to the default topics, with the password ntfy now holds.
func checkWelcome(t *testing.T, h *testutil.Harness, m mail.Message, p directory.Person) string {
	t.Helper()
	if m.To != p.Email || m.ToName != p.DisplayName {
		t.Fatalf("welcome addressed to %q <%s>, want %q <%s>", m.ToName, m.To, p.DisplayName, p.Email)
	}
	pw := passwordRe.FindStringSubmatch(m.Text)
	if pw == nil {
		t.Fatalf("welcome has no password:\n%s", m.Text)
	}
	if pw[1] != h.Ntfy.Password(p.Username) {
		t.Fatalf("welcome password %q, ntfy has %q", pw[1], h.Ntfy.Password(p.Username))
	}
	for _, want := range []string{
		"Username:   " + p.Username,
		"Server URL: " + h.Cfg.NtfyBaseURL,
		ntfyLink(h, "alerts", p.Username),
		ntfyLink(h, p.Username+"-inbox", p.Username),
	} {
		if !strings.Contains(m.Text, want) {
			t.Fatalf("welcome lacks %q:\n%s", want, m.Text)
		}
	}
	return pw[1]
}

func userNamed(t *testing.T, h *testutil.Harness, name string) core.UserSummary {
	t.Helper()
	users, err := h.Svc.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == name {
			return u
		}
	}
	t.Fatalf("no user %q", name)
	return core.UserSummary{}
}

// lastAudit returns the newest audit entry for event, decoded.
func lastAudit(t *testing.T, h *testutil.Harness, event string) map[string]any {
	t.Helper()
	entries, err := h.Svc.AuditLog(context.Background(), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Event == event {
			var d map[string]any
			if err := json.Unmarshal([]byte(e.Detail), &d); err != nil {
				t.Fatal(err)
			}
			return d
		}
	}
	t.Fatalf("no %s audit entry", event)
	return nil
}

func auditCount(t *testing.T, h *testutil.Harness, user, event string) int {
	t.Helper()
	entries, err := h.Svc.AuditLog(context.Background(), user, 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Event == event {
			n++
		}
	}
	return n
}

func wantSyncCounts(t *testing.T, h *testutil.Harness, created, welcomed, disabled, enabled, updated int) {
	t.Helper()
	got := lastAudit(t, h, "sync")
	want := map[string]any{"created": created, "welcomed": welcomed, "disabled": disabled, "enabled": enabled, "updated": updated}
	for k, v := range want {
		if got[k] != float64(v.(int)) {
			t.Fatalf("sync counts %v, want %v", got, want)
		}
	}
}

func preauthResult(t *testing.T, h *testutil.Harness, user string) *authapi.PreauthResult {
	t.Helper()
	pre, err := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername(user))
	if err != nil {
		t.Fatal(err)
	}
	return pre
}

// A person new to the directory gets an ntfy account with enroll-access and exactly one welcome
// email whose password signs the app in; later rounds send nothing and only track profile changes.
func TestSyncProvisionsAndWelcomesOnce(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol, dave)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []directory.Person{carol, dave} {
		if h.Ntfy.Grant(p.Username, p.Username+"-*") != config.PermReadWrite || h.Ntfy.Grant(p.Username, "alerts") != config.PermReadOnly {
			t.Fatalf("enroll-access not applied to %s: %+v", p.Username, h.Ntfy.User(p.Username))
		}
		checkWelcome(t, h, welcomeTo(t, h, p.Email, 1), p)
		u := userNamed(t, h, p.Username)
		if u.Email != p.Email || u.DisplayName != p.DisplayName || u.WelcomedAt == nil || u.SyncedAt == nil {
			t.Fatalf("stored profile %+v", u.User)
		}
		if pre := preauthResult(t, h, p.Username); pre.Response.Result != "enroll" {
			t.Fatalf("preauth after sync: %+v", pre.Response)
		}
	}
	wantSyncCounts(t, h, 2, 2, 0, 0, 0)

	password := h.Ntfy.Password("carol")
	moved := carol
	moved.Email, moved.DisplayName = "carol@elsewhere.example", "Carol D."
	h.Dir.Set(moved, dave)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(h.Mail.Sent()); n != 2 {
		t.Fatalf("%d emails after the second round, want the 2 welcomes", n)
	}
	if h.Ntfy.Password("carol") != password {
		t.Fatal("a later round changed the ntfy password")
	}
	if u := userNamed(t, h, "carol"); u.Email != moved.Email || u.DisplayName != moved.DisplayName {
		t.Fatalf("profile not updated: %+v", u.User)
	}
	wantSyncCounts(t, h, 0, 0, 0, 0, 1)
}

// The directory decides who may sign in: a user it stops listing, or marks disabled, is disabled
// (never deleted) and enabled again when listed; a disable an admin made stays.
func TestSyncDisablesAndEnables(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "carol", testutil.NewAuthenticator(t, testutil.PublicURL))
	sync := func(people ...directory.Person) {
		t.Helper()
		h.Dir.Set(people...)
		if err := h.Svc.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	wantPreauth := func(result, msg string) {
		t.Helper()
		pre := preauthResult(t, h, "carol")
		if pre.Response.Result != result || (msg != "" && pre.Response.Status_Msg != msg) {
			t.Fatalf("preauth %+v, want %s %q", pre.Response, result, msg)
		}
	}

	// A user enrolled before the directory listed them is owed a welcome.
	sync(carol, dave)
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 1), carol)
	wantPreauth("auth", "")

	sync(dave)
	wantPreauth("deny", "user disabled")
	wantSyncCounts(t, h, 0, 0, 1, 0, 0)
	sync(dave)
	if n := auditCount(t, h, "carol", "user_disabled"); n != 1 {
		t.Fatalf("%d user_disabled entries for an absent user, want 1", n)
	}
	if !h.HasDevice(t, "carol", dev.DeviceID) || h.Ntfy.User("carol") == nil {
		t.Fatal("an absent user lost their device or ntfy account")
	}

	sync(carol, dave)
	wantPreauth("auth", "")
	wantSyncCounts(t, h, 0, 0, 0, 1, 0)

	off := carol
	off.Disabled = true
	sync(off, dave)
	wantPreauth("deny", "user disabled")
	sync(carol, dave)
	wantPreauth("auth", "")

	if err := h.Svc.SetUserDisabled(ctx, "carol", true); err != nil {
		t.Fatal(err)
	}
	sync(carol, dave)
	wantPreauth("deny", "user disabled")
	if n := len(h.Mail.To(carol.Email)); n != 1 {
		t.Fatalf("%d emails to carol, want only the first welcome", n)
	}
}

// A directory that fails or lists nobody changes nothing: disabling everyone on a broken directory
// would lock everyone out.
func TestSyncSkipsBrokenDirectory(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, broken := range []func(){
		func() { h.Dir.Set() },
		func() { h.Dir.Fail(errors.New("ldap: connection refused")) },
	} {
		broken()
		err := h.Svc.Sync(ctx)
		if err == nil {
			t.Fatal("sync with a broken directory succeeded")
		}
		if got := lastAudit(t, h, "sync_skipped")["error"]; got != err.Error() {
			t.Fatalf("sync_skipped error %q, want %q", got, err)
		}
		if u := userNamed(t, h, "carol"); !u.Enabled() {
			t.Fatal("a skipped round disabled a user")
		}
		if pre := preauthResult(t, h, "carol"); pre.Response.Result != "enroll" {
			t.Fatalf("preauth after a skipped round: %+v", pre.Response)
		}
	}
	if n := auditCount(t, h, "", "sync"); n != 1 {
		t.Fatalf("%d sync rounds audited, want only the first", n)
	}
}

// A welcome that cannot be delivered leaves the account in place and the welcome owed; the next
// round sends it.
func TestSyncRetriesFailedWelcome(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Mail.Fail(errors.New("smtp: connection refused"))
	h.Dir.Set(carol, dave)
	err := h.Svc.Sync(ctx)
	if err == nil {
		t.Fatal("sync hid the failed welcomes")
	}
	for _, p := range []directory.Person{carol, dave} {
		if h.Ntfy.User(p.Username) == nil {
			t.Fatalf("%s not provisioned when mail failed", p.Username)
		}
		if u := userNamed(t, h, p.Username); u.WelcomedAt != nil {
			t.Fatalf("%s marked welcomed though nothing was sent", p.Username)
		}
		if n := auditCount(t, h, p.Username, "welcome_failed"); n != 1 {
			t.Fatalf("%d welcome_failed entries for %s", n, p.Username)
		}
	}
	wantSyncCounts(t, h, 2, 0, 0, 0, 0)

	h.Mail.Fail(nil)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range []directory.Person{carol, dave} {
		checkWelcome(t, h, welcomeTo(t, h, p.Email, 1), p)
		if u := userNamed(t, h, p.Username); u.WelcomedAt == nil {
			t.Fatalf("%s not marked welcomed", p.Username)
		}
	}
	wantSyncCounts(t, h, 0, 2, 0, 0, 0)
}

// user welcome resends the welcome with a new password; the old one stops working.
func TestWelcomeRotatesPassword(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	first := checkWelcome(t, h, welcomeTo(t, h, carol.Email, 1), carol)
	if err := h.Svc.Welcome(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	second := checkWelcome(t, h, welcomeTo(t, h, carol.Email, 2), carol)
	if second == first {
		t.Fatal("resent welcome kept the old password")
	}

	// Someone enrolled outside the directory has no address to send to.
	if _, err := h.Svc.Provision(ctx, "erin"); err != nil {
		t.Fatal(err)
	}
	if err := h.Svc.Welcome(ctx, "erin"); !errors.Is(err, core.ErrNoEmail) || core.KindOf(err) != core.Refused {
		t.Fatalf("welcome without an email: %v", err)
	}
	if err := h.Svc.Welcome(ctx, "nobody"); !errors.Is(err, core.ErrUnknownUser) {
		t.Fatalf("welcome of an unknown user: %v", err)
	}

	// A failed resend leaves the welcome owed, so the next round sends a working password.
	h.Mail.Fail(errors.New("smtp: connection refused"))
	if err := h.Svc.Welcome(ctx, "carol"); err == nil || core.KindOf(err) != core.Internal {
		t.Fatalf("welcome with mail down: %v", err)
	}
	h.Mail.Fail(nil)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 3), carol)
}

// user provision takes only people the directory lists and welcomes them once.
func TestProvisionFromDirectory(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	gone := directory.Person{Username: "frank", Email: "frank@example.com", Disabled: true}
	h.Dir.Set(carol, gone)

	if _, err := h.Svc.ProvisionFromDirectory(ctx, "mallory"); !errors.Is(err, core.ErrNotInDirectory) || core.KindOf(err) != core.Refused {
		t.Fatalf("provision of a name the directory does not list: %v", err)
	}
	if _, err := h.Svc.ProvisionFromDirectory(ctx, "frank"); !errors.Is(err, core.ErrUserDisabled) {
		t.Fatalf("provision of a disabled directory user: %v", err)
	}
	for _, name := range []string{"mallory", "frank"} {
		if h.Ntfy.User(name) != nil {
			t.Fatalf("refused provision created ntfy user %s", name)
		}
	}

	u, err := h.Svc.ProvisionFromDirectory(ctx, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != carol.Email || len(u.Grants) != 2 || h.Ntfy.Grant("carol", "carol-*") != config.PermReadWrite {
		t.Fatalf("provisioned %+v, ntfy %+v", u, h.Ntfy.User("carol"))
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 1), carol)
	if _, err := h.Svc.ProvisionFromDirectory(ctx, "carol"); err != nil {
		t.Fatal(err)
	}
	welcomeTo(t, h, carol.Email, 1)

	h.Dir.Fail(errors.New("ldap: connection refused"))
	if _, err := h.Svc.ProvisionFromDirectory(ctx, "carol"); err == nil {
		t.Fatal("provision without a directory succeeded")
	}
}

// A reset recreates the ntfy account with a password nobody knows, so it ends in a new welcome.
func TestResetSendsWelcome(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	lost := h.Enroll(t, "carol", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Enroll(t, "carol", testutil.NewAuthenticator(t, testutil.PublicURL))

	if err := h.Svc.ResetNtfyUser(ctx, "carol", false); err != nil {
		t.Fatal(err)
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 2), carol)
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, true, false, "test"); err != nil {
		t.Fatal(err)
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 3), carol)

	// The reset stands when the welcome cannot be sent; the next round sends it.
	h.Mail.Fail(errors.New("smtp: connection refused"))
	before := h.Ntfy.Password("carol")
	if err := h.Svc.ResetNtfyUser(ctx, "carol", false); err != nil {
		t.Fatalf("reset failed with the welcome: %v", err)
	}
	if h.Ntfy.Password("carol") == before {
		t.Fatal("ntfy user not recreated")
	}
	if u := userNamed(t, h, "carol"); u.WelcomedAt != nil {
		t.Fatal("undelivered welcome marked as sent")
	}
	h.Mail.Fail(nil)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 4), carol)
}
