package core_test

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

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

func wantSyncCounts(t *testing.T, h *testutil.Harness, created, welcomed, deleted, updated int) {
	t.Helper()
	got := lastAudit(t, h, "sync")
	want := map[string]any{"created": created, "welcomed": welcomed, "deleted": deleted, "updated": updated}
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
	wantSyncCounts(t, h, 2, 2, 0, 0)

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
	wantSyncCounts(t, h, 0, 0, 0, 1)
}

// The directory decides who has an account: a user it stops listing, or marks disabled, is deleted
// with their phones and ntfy account, and a person who comes back starts over with a new account
// and welcome. A disable an admin made is the admin's: the sync leaves it.
func TestSyncDeletes(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
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
	off := carol
	off.Disabled = true

	sync(carol, dave)
	emails := 1
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, emails), carol)
	for i, dropped := range [][]directory.Person{{dave}, {off, dave}} {
		dev := h.Enroll(t, "carol", testutil.NewAuthenticator(t, testutil.PublicURL))
		wantPreauth("auth", "")

		sync(dropped...)
		wantSyncCounts(t, h, 0, 0, 1, 0)
		if h.HasDevice(t, "carol", dev.DeviceID) || h.Ntfy.User("carol") != nil || h.Ntfy.Grant("carol", dev.Topic) != "" {
			t.Fatalf("a dropped user kept a device or ntfy account: %+v", h.Ntfy.User("carol"))
		}
		if n := auditCount(t, h, "carol", "user_deleted"); n != i+1 {
			t.Fatalf("%d user_deleted entries, want %d", n, i+1)
		}
		wantPreauth("enroll", "")
		// Gone stays gone: nobody is deleted twice, and a disabled person is not created.
		sync(dropped...)
		wantSyncCounts(t, h, 0, 0, 0, 0)
		if h.Ntfy.User("carol") != nil {
			t.Fatal("a dropped user was recreated")
		}

		sync(carol, dave)
		wantSyncCounts(t, h, 1, 1, 0, 0)
		emails++
		checkWelcome(t, h, welcomeTo(t, h, carol.Email, emails), carol)
	}

	if err := h.Svc.SetUserDisabled(ctx, "carol", true); err != nil {
		t.Fatal(err)
	}
	sync(carol, dave)
	wantPreauth("deny", "user disabled")
	wantSyncCounts(t, h, 0, 0, 0, 0)
	welcomeTo(t, h, carol.Email, emails)
}

// Deletions come before welcomes in a round, so a stalled mail server does not keep a dropped user
// signed in.
func TestSyncDeletesBeforeWelcoming(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	held := h.Mail.Block()
	h.Dir.Set(dave)
	done := make(chan error, 1)
	go func() { done <- h.Svc.Sync(ctx) }()
	select {
	case m := <-held:
		if m.To != dave.Email {
			t.Fatalf("held email to %s, want the welcome to %s", m.To, dave.Email)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the round sent no welcome")
	}
	if h.Ntfy.User("carol") != nil || auditCount(t, h, "carol", "user_deleted") != 1 {
		t.Fatal("the dropped user waited for the mail server")
	}
	h.Mail.Unblock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	checkWelcome(t, h, welcomeTo(t, h, dave.Email, 1), dave)
	wantSyncCounts(t, h, 1, 1, 1, 0)
}

// A round asks ntfy for its user list once, however many accounts it creates and welcomes.
func TestSyncListsNtfyUsersOnce(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	erin := directory.Person{Username: "erin", Email: "erin@example.com"}
	people := []directory.Person{carol, dave, erin}
	h.Dir.Set(people...)
	for round := range 2 {
		before := h.Ntfy.UserLists()
		if err := h.Svc.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if n := h.Ntfy.UserLists() - before; n != 1 {
			t.Fatalf("round %d listed ntfy users %d times, want 1", round, n)
		}
	}
	for _, p := range people {
		checkWelcome(t, h, welcomeTo(t, h, p.Email, 1), p)
	}
	wantSyncCounts(t, h, 0, 0, 0, 0)
}

// A directory that fails changes nothing: deleting everyone on a broken directory could not be
// undone. One that lists nobody is believed, and deletes everyone.
func TestSyncSkipsBrokenDirectory(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	h.Dir.Fail(errors.New("ldap: connection refused"))
	err := h.Svc.Sync(ctx)
	if err == nil {
		t.Fatal("sync with a broken directory succeeded")
	}
	if got := lastAudit(t, h, "sync_skipped")["error"]; got != err.Error() {
		t.Fatalf("sync_skipped error %q, want %q", got, err)
	}
	if u := userNamed(t, h, "carol"); !u.Enabled() || h.Ntfy.User("carol") == nil {
		t.Fatal("a skipped round removed or disabled a user")
	}
	if pre := preauthResult(t, h, "carol"); pre.Response.Result != "enroll" {
		t.Fatalf("preauth after a skipped round: %+v", pre.Response)
	}
	if n := auditCount(t, h, "", "sync"); n != 1 {
		t.Fatalf("%d sync rounds audited, want only the first", n)
	}

	h.Dir.Fail(nil)
	h.Dir.Set()
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Svc.DevicesOf(ctx, "carol"); !errors.Is(err, core.ErrUnknownUser) {
		t.Fatalf("carol after an empty round: %v", err)
	}
	if h.Ntfy.User("carol") != nil {
		t.Fatal("an empty round kept the ntfy user")
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
	wantSyncCounts(t, h, 2, 0, 0, 0)

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
	wantSyncCounts(t, h, 0, 2, 0, 0)
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

// A welcome cut short, here by the browser hanging up on a revoke that signs out every ntfy app,
// stays owed: the next round sends one whose password works.
func TestInterruptedWelcomeStaysOwed(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	dev := h.Enroll(t, "carol", testutil.NewAuthenticator(t, testutil.PublicURL))
	before := h.Ntfy.Password("carol")

	held := h.Mail.Block()
	reqCtx, hangUp := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Do(t, testutil.Request{Method: "POST", Path: "/devices/" + dev.DeviceID + "/revoke", User: "carol",
			Body: []byte("reset_ntfy=1"), Ctx: reqCtx,
			Header: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
	}()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the reset sent no welcome")
	}
	hangUp()
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for auditCount(t, h, "carol", "welcome_failed") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the interrupted welcome was not audited")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.Mail.Unblock()
	if h.Ntfy.Password("carol") == before {
		t.Fatal("the reset did not change the password")
	}
	if u := userNamed(t, h, "carol"); u.WelcomedAt != nil {
		t.Fatal("an interrupted welcome was marked as sent")
	}

	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 2), carol)
	wantSyncCounts(t, h, 0, 1, 0, 0)
}

// Overlapping welcomes each send an email, and the last one sent carries the password ntfy holds.
func TestConcurrentWelcomes(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Dir.Set(carol)
	if err := h.Svc.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	held := h.Mail.Block()
	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- h.Svc.Welcome(ctx, "carol") }()
	}
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("no welcome sent")
	}
	// Give the other welcome time to reach the point where it could rotate the password.
	time.Sleep(50 * time.Millisecond)
	h.Mail.Unblock()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	checkWelcome(t, h, welcomeTo(t, h, carol.Email, 3), carol)
}
