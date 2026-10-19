package core_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duosecurity/duo_api_golang/authapi"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

var callSeq atomic.Int32

// authCall runs an Authelia-shaped auth request in the background. Calls differ by hostname to
// bypass replay guard.
func authCall(h *testutil.Harness, user, device string) <-chan *authapi.AuthResult {
	out := make(chan *authapi.AuthResult, 1)
	seq := callSeq.Add(1)
	go func() {
		r, err := h.Duo(testutil.IKey, testutil.SKey).Auth("push",
			authapi.AuthUsername(user),
			authapi.AuthDevice(device),
			authapi.AuthIpAddr("203.0.113.7"),
			func(v *url.Values) { v.Set("hostname", fmt.Sprintf("laptop-%d", seq)) },
			authapi.AuthDisplayUsername(user),
			// Authelia sends pushinfo as "target%20url=<url>".
			authapi.AuthPushinfo("target%20url=https://app.example.com/dashboard"))
		if err != nil {
			r = &authapi.AuthResult{}
			r.Response.Result = "error: " + err.Error()
		}
		out <- r
	}()
	return out
}

func wait(t *testing.T, ch <-chan *authapi.AuthResult) *authapi.AuthResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(20 * time.Second):
		t.Fatal("auth did not return")
		return nil
	}
}

func approve(t *testing.T, h *testutil.Harness, a *testutil.Authenticator, click string) int {
	t.Helper()
	path := testutil.LocalPath(t, click)
	resp, opts := h.Do(t, testutil.Request{Method: "GET", Path: path + "/options"})
	if resp.StatusCode != 200 {
		return resp.StatusCode
	}
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: path + "/assert", Body: a.Get(t, opts)})
	return resp.StatusCode
}

func pushAction(m ntfy.Message, label string) ntfy.Action {
	for _, a := range m.Actions {
		if a.Label == label {
			return a
		}
	}
	return ntfy.Action{}
}

func TestAutheliaLoginApprovedWithPasskey(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	dev := h.Enroll(t, "alice", a)

	// The phone gets a read-only grant on exactly its own topic, plus enroll-access.
	if p := h.Ntfy.Grant("alice", dev.Topic); p != config.PermReadOnly {
		t.Fatalf("topic grant %q", p)
	}
	if h.Ntfy.Grant("alice", "alice-*") != config.PermReadWrite || h.Ntfy.Grant("alice", "alerts") != config.PermReadOnly {
		t.Fatalf("enroll-access not applied: %+v", h.Ntfy.User("alice").Grants)
	}
	// The result page subscribes the app to the device's topic on the plain-HTTP fake ntfy; the
	// link names the user and carries no credentials.
	if want := ntfyLink(h, dev.Topic, "alice"); dev.NtfyLink != want || dev.Server != h.Cfg.NtfyBaseURL {
		t.Fatalf("ntfy link %q server %q, want %q", dev.NtfyLink, dev.Server, want)
	}

	pre, err := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if pre.Response.Result != "auth" || len(pre.Response.Devices) != 1 {
		t.Fatalf("preauth %+v", pre.Response)
	}
	d := pre.Response.Devices[0]
	if d.Device != dev.DeviceID || d.Type != "phone" || len(d.Capabilities) != 1 || d.Capabilities[0] != "push" {
		t.Fatalf("device %+v", d)
	}

	res := authCall(h, "alice", d.Device)
	m := h.Ntfy.NextPublish(t)
	if m.Topic != dev.Topic || m.Title != "Sign-in request" || m.Priority != 4 {
		t.Fatalf("push %+v", m)
	}
	if !strings.Contains(m.Message, "alice") || !strings.Contains(m.Message, "203.0.113.7") || !strings.Contains(m.Message, "app.example.com") {
		t.Fatalf("push message %q", m.Message)
	}
	if pushAction(m, "Approve").URL != m.Click || pushAction(m, "Deny").Method != "POST" || pushAction(m, "Deny").Body == "" {
		t.Fatalf("push actions %+v", m.Actions)
	}

	// The approve page shows the request.
	resp, page := h.Do(t, testutil.Request{Method: "GET", Path: testutil.LocalPath(t, m.Click)})
	if resp.StatusCode != 200 || !strings.Contains(string(page), "203.0.113.7") {
		t.Fatalf("approve page: %d", resp.StatusCode)
	}

	if st := approve(t, h, a, m.Click); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	r := wait(t, res)
	if r.Response.Result != "allow" || r.Response.Status != "allow" {
		t.Fatalf("auth %+v", r.Response)
	}

	// Single use: the page and a second assertion both answer 410, and the push is cleared.
	if st := approve(t, h, a, m.Click); st != 410 {
		t.Fatalf("reuse: %d", st)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: testutil.LocalPath(t, m.Click)})
	if resp.StatusCode != 410 {
		t.Fatalf("approve page after decision: %d", resp.StatusCode)
	}
	if got := h.Ntfy.Deleted(); len(got) != 1 || got[0] != dev.Topic+"/"+m.SequenceID {
		t.Fatalf("deleted pushes %v", got)
	}
}

func TestReadingThePushDoesNotApprove(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	phone := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	other := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	attacker := testutil.NewAuthenticator(t, testutil.PublicURL)

	res := authCall(h, "alice", phone.DeviceID)
	m := h.Ntfy.NextPublish(t)
	// A passkey from no device, and one from the user's other phone, are both refused.
	if st := approve(t, h, attacker, m.Click); st != 403 {
		t.Fatalf("unknown passkey: %d", st)
	}
	if st := approve(t, h, other.Auth, m.Click); st != 403 {
		t.Fatalf("other device's passkey: %d", st)
	}
	// A right passkey from the wrong origin (phishing page) is refused.
	phished := *phone.Auth
	phished.Origin = "https://push.test.evil.example"
	if st := approve(t, h, &phished, m.Click); st != 403 {
		t.Fatalf("wrong origin: %d", st)
	}
	// Without user verification it is refused too.
	noUV := *phone.Auth
	noUV.Flags &^= testutil.FlagUV
	if st := approve(t, h, &noUV, m.Click); st != 403 {
		t.Fatalf("no UV: %d", st)
	}
	// Cross-site posts are refused outright.
	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: testutil.LocalPath(t, m.Click) + "/assert", Body: []byte("{}"),
		Header: map[string]string{"Origin": "https://evil.example"}})
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin: %d", resp.StatusCode)
	}
	if st := approve(t, h, phone.Auth, m.Click); st != 200 {
		t.Fatalf("right passkey: %d", st)
	}
	if r := wait(t, res); r.Response.Result != "allow" {
		t.Fatalf("auth %+v", r.Response)
	}
}

func TestDenyFraudTimeout(t *testing.T) {
	h := testutil.NewHarness(t, func(c *config.Config) { c.PushTimeout = config.Duration(2 * time.Second) })
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))

	t.Run("deny action", func(t *testing.T) {
		res := authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		deny := pushAction(m, "Deny")
		// The ntfy app posts the token without an Origin header.
		noOrigin := map[string]string{"Origin": "", "Content-Type": "text/plain"}
		resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: testutil.LocalPath(t, deny.URL), Body: []byte("wrong"), Header: noOrigin})
		if resp.StatusCode != 403 {
			t.Fatalf("wrong token: %d", resp.StatusCode)
		}
		resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: testutil.LocalPath(t, deny.URL), Body: []byte(deny.Body), Header: noOrigin})
		if resp.StatusCode != 200 {
			t.Fatalf("deny: %d", resp.StatusCode)
		}
		if r := wait(t, res); r.Response.Result != "deny" || r.Response.Status != "deny" {
			t.Fatalf("auth %+v", r.Response)
		}
	})
	t.Run("fraud", func(t *testing.T) {
		res := authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: testutil.LocalPath(t, m.Click) + "/fraud", Body: []byte("{}")})
		if resp.StatusCode != 200 {
			t.Fatalf("fraud: %d", resp.StatusCode)
		}
		if r := wait(t, res); r.Response.Result != "deny" || r.Response.Status != "fraud" {
			t.Fatalf("auth %+v", r.Response)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		res := authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		if r := wait(t, res); r.Response.Result != "deny" || r.Response.Status != "timeout" {
			t.Fatalf("auth %+v", r.Response)
		}
		if st := approve(t, h, dev.Auth, m.Click); st != 410 {
			t.Fatalf("approve after timeout: %d", st)
		}
	})
}

func TestRetriedLoginJoinsPendingPush(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))

	first := authCall(h, "alice", dev.DeviceID)
	m := h.Ntfy.NextPublish(t)
	second := authCall(h, "alice", dev.DeviceID)
	// The second login waits on the same push: nothing new reaches the phone.
	h.Ntfy.NoPublish(t, 500*time.Millisecond)
	if st := approve(t, h, dev.Auth, m.Click); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	for _, res := range []<-chan *authapi.AuthResult{first, second} {
		if r := wait(t, res); r.Response.Result != "allow" {
			t.Fatalf("auth %+v", r.Response)
		}
	}
}

func TestPushesPerUserLimited(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	bob := h.Enroll(t, "bob", testutil.NewAuthenticator(t, testutil.PublicURL))

	// Each decided push frees the phone for the next, up to the burst.
	for i := 0; i < 3; i++ {
		res := authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		deny := pushAction(m, "Deny")
		h.Do(t, testutil.Request{Method: "POST", Path: testutil.LocalPath(t, deny.URL), Body: []byte(deny.Body),
			Header: map[string]string{"Origin": "", "Content-Type": "text/plain"}})
		if r := wait(t, res); r.Response.Status != "deny" {
			t.Fatalf("push %d: %+v", i, r.Response)
		}
	}
	if r := wait(t, authCall(h, "alice", dev.DeviceID)); r.Response.Result != "deny" || r.Response.Status_Msg != "Too many sign-in requests" {
		t.Fatalf("fourth push %+v", r.Response)
	}
	h.Ntfy.NoPublish(t, 200*time.Millisecond)
	// The allowance is per user.
	res := authCall(h, "bob", bob.DeviceID)
	m := h.Ntfy.NextPublish(t)
	if st := approve(t, h, bob.Auth, m.Click); st != 200 {
		t.Fatalf("approve bob: %d", st)
	}
	if r := wait(t, res); r.Response.Result != "allow" {
		t.Fatalf("bob %+v", r.Response)
	}
}

func TestAuthRefusals(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	alice := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Enroll(t, "bob", testutil.NewAuthenticator(t, testutil.PublicURL))
	duo := h.Duo(testutil.IKey, testutil.SKey)

	for _, c := range []struct {
		name   string
		factor string
		opts   []func(*url.Values)
		msg    string
	}{
		{"another user's device", "push", []func(*url.Values){authapi.AuthUsername("bob"), authapi.AuthDevice(alice.DeviceID)}, "Unknown device"},
		{"nonexistent device", "push", []func(*url.Values){authapi.AuthUsername("alice"), authapi.AuthDevice("nope")}, "Unknown device"},
		{"unknown user", "push", []func(*url.Values){authapi.AuthUsername("mallory"), authapi.AuthDevice("auto")}, "Unknown user"},
		{"sms factor", "sms", []func(*url.Values){authapi.AuthUsername("alice"), authapi.AuthDevice(alice.DeviceID)}, "Only push is supported"},
		{"passcode factor", "passcode", []func(*url.Values){authapi.AuthUsername("alice"), authapi.AuthPasscode("123456")}, "Only push is supported"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, err := duo.Auth(c.factor, c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if r.Stat != "OK" || r.Response.Result != "deny" || r.Response.Status_Msg != c.msg {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestDisableAndKillSwitch(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	duo := h.Duo(testutil.IKey, testutil.SKey)
	ctx := context.Background()

	if err := h.Svc.SetUserDisabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	pre, _ := duo.Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "deny" || pre.Response.Status_Msg != "user disabled" {
		t.Fatalf("preauth disabled: %+v", pre.Response)
	}
	if r, _ := duo.Auth("push", authapi.AuthUsername("alice"), authapi.AuthDevice(dev.DeviceID)); r.Response.Result != "deny" {
		t.Fatalf("auth disabled: %+v", r.Response)
	}
	if err := h.Svc.SetUserDisabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}

	h.Reload(t, func(c *config.Config) { c.PushDisabled = true })
	pre, _ = duo.Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "deny" {
		t.Fatalf("preauth with push disabled: %+v", pre.Response)
	}
	if r, _ := duo.Auth("push", authapi.AuthUsername("alice"), authapi.AuthDevice(dev.DeviceID), authapi.AuthIpAddr("198.51.100.1")); r.Response.Result != "deny" {
		t.Fatalf("auth with push disabled: %+v", r.Response)
	}
}

// Preauth logic: Unknown users or those without devices enroll (or get denied without
// enroll-portal-url). Disabled users/kill switch deny. Otherwise, active devices are listed MRU
// first; device=auto picks the first.
func TestPreauth(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, func(c *config.Config) { c.PushTimeout = config.Duration(5 * time.Second) })
	preauth := func(ref core.UserRef) core.PreauthResult {
		t.Helper()
		res, err := h.Svc.Preauth(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := preauth(core.UserRef{Username: "nobody"}); res.EnrollURL != testutil.PublicURL+"/enroll" || res.Deny != nil {
		t.Fatalf("unknown user: %+v", res)
	}

	older := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	newer := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	// Device times have one-second resolution; approving a login on older afterwards makes it the
	// most recent.
	time.Sleep(1100 * time.Millisecond)
	used := authCall(h, "alice", older.DeviceID)
	if st := approve(t, h, older.Auth, h.Ntfy.NextPublish(t).Click); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	if r := wait(t, used); r.Response.Result != "allow" {
		t.Fatalf("auth %+v", r.Response)
	}
	u, _, _ := h.Svc.DevicesOf(ctx, "alice")
	for _, ref := range []core.UserRef{{Username: "alice"}, {ID: u.ID}} {
		res := preauth(ref)
		if len(res.Devices) != 2 || res.Devices[0].ID != older.DeviceID || res.Devices[1].ID != newer.DeviceID {
			t.Fatalf("devices for %+v: %+v", ref, res)
		}
	}
	pending := authCall(h, "alice", "auto")
	if m := h.Ntfy.NextPublish(t); m.Topic != older.Topic {
		t.Fatalf("device=auto pushed to %s, want %s", m.Topic, older.Topic)
	}

	if err := h.Svc.SetUserDisabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	if r := wait(t, pending); r.Response.Result != "deny" {
		t.Fatalf("pending auth after disable: %+v", r.Response)
	}
	if res := preauth(core.UserRef{Username: "alice"}); !errors.Is(res.Deny, core.ErrUserDisabled) {
		t.Fatalf("disabled user: %+v", res)
	}

	h.Reload(t, func(c *config.Config) { c.EnrollPortalURL = "" })
	if res := preauth(core.UserRef{Username: "nobody"}); !errors.Is(res.Deny, core.ErrEnrollmentRequired) {
		t.Fatalf("unknown user without enroll-portal-url: %+v", res)
	}
	h.Reload(t, func(c *config.Config) { c.PushDisabled = true })
	if res := preauth(core.UserRef{Username: "nobody"}); !errors.Is(res.Deny, core.ErrPushDisabled) {
		t.Fatalf("kill switch: %+v", res)
	}
}

func TestRevokeDevice(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	res := authCall(h, "alice", dev.DeviceID)
	m := h.Ntfy.NextPublish(t)

	// Revoked from the self-service page: pending login denied, grant removed, device gone.
	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: "/devices/" + dev.DeviceID + "/revoke", User: "bob"})
	if resp.StatusCode != 404 {
		t.Fatalf("another user revoking: %d", resp.StatusCode)
	}
	resp, _ = h.SubmitForm(t, "/devices", "alice", "/devices/"+dev.DeviceID+"/revoke", nil)
	if resp.StatusCode != 303 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if h.HasDevice(t, "alice", dev.DeviceID) {
		t.Fatal("device row kept after a successful revoke")
	}
	if r := wait(t, res); r.Response.Result != "deny" {
		t.Fatalf("pending auth after revoke: %+v", r.Response)
	}
	if st := approve(t, h, dev.Auth, m.Click); st != 410 {
		t.Fatalf("approve after revoke: %d", st)
	}
	if p := h.Ntfy.Grant("alice", dev.Topic); p != "" {
		t.Fatalf("topic grant still %q", p)
	}
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "enroll" {
		t.Fatalf("preauth after revoke: %+v", pre.Response)
	}
}

// The device list includes all user devices. The user list only counts devices that can receive
// logins.
func TestUsersAndDevicesOf(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	active := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	unverified, st, b := h.FinishEnroll(t, "alice", "", testutil.NewAuthenticator(t, testutil.PublicURL))
	if st != 200 {
		t.Fatalf("enroll finish: %d %s", st, b)
	}
	if err := h.Svc.SetUserDisabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}

	u, devs, err := h.Svc.DevicesOf(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, d := range devs {
		ids[d.ID] = true
	}
	if u.DisabledAt == nil || len(devs) != 2 || !ids[active.DeviceID] || !ids[unverified.DeviceID] {
		t.Fatalf("DevicesOf: %+v %+v", u, devs)
	}
	if _, _, err := h.Svc.DevicesOf(ctx, "nobody"); !errors.Is(err, core.ErrUnknownUser) {
		t.Fatalf("DevicesOf unknown user: %v", err)
	}
	users, err := h.Svc.Users(ctx)
	if err != nil || len(users) != 1 || users[0].Username != "alice" || users[0].ActiveDevices != 1 {
		t.Fatalf("Users: %+v %v", users, err)
	}
}

func TestRevokeWithNtfyReset(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	ctx := context.Background()
	lost := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	kept := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))

	h.Ntfy.AddForeignGrant("alice", "manual-topic", config.PermReadWrite)
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, true, false, "test"); err == nil {
		t.Fatal("reset with a foreign grant must be refused without --force")
	}
	// The refusal left the device in place.
	if !h.HasDevice(t, "alice", lost.DeviceID) {
		t.Fatal("device removed despite refusal")
	}
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, true, true, "test"); err != nil {
		t.Fatal(err)
	}
	u := h.Ntfy.User("alice")
	if u == nil {
		t.Fatal("ntfy user not recreated")
	}
	grants := map[string]string{}
	for _, g := range u.Grants {
		grants[g.Topic] = g.Permission
	}
	want := map[string]string{"alice-*": config.PermReadWrite, "alerts": config.PermReadOnly, kept.Topic: config.PermReadOnly}
	if len(grants) != len(want) {
		t.Fatalf("grants after reset %v, want %v", grants, want)
	}
	for k, v := range want {
		if grants[k] != v {
			t.Fatalf("grants after reset %v, want %v", grants, want)
		}
	}
}

func TestSyncedPasskeyRefused(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	a.Flags |= testutil.FlagBE | testutil.FlagBS
	token, opts, _ := h.BeginEnroll(t, "alice", "", "Synced")
	resp, b := h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts), User: "alice"})
	if resp.StatusCode != 403 || !strings.Contains(string(b), "synced") {
		t.Fatalf("synced passkey: %d %s", resp.StatusCode, b)
	}

	h = testutil.NewHarness(t, func(c *config.Config) { c.WebAuthnAllowSynced = true })
	h.Enroll(t, "alice", a)
}

func TestRequireAttestationRefusesNone(t *testing.T) {
	h := testutil.NewHarness(t, func(c *config.Config) { c.WebAuthnRequireAttestation = true })
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	token, opts, _ := h.BeginEnroll(t, "alice", "", "Phone")
	resp, b := h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts), User: "alice"})
	if resp.StatusCode != 403 || !strings.Contains(string(b), "attestation") {
		t.Fatalf("attestation none accepted: %d %s", resp.StatusCode, b)
	}
}

func TestUnverifiedDeviceHidden(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	token, opts, _ := h.BeginEnroll(t, "alice", "", "Phone")
	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts), User: "alice"})
	if resp.StatusCode != 200 {
		t.Fatalf("finish: %d", resp.StatusCode)
	}
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "enroll" {
		t.Fatalf("unverified device listed: %+v", pre.Response)
	}
	// The verify link is single-use and bound to its token.
	m := h.Ntfy.NextPublish(t)
	path, _ := testutil.Fragment(t, m.Click)
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: path, Body: []byte("t=wrong"), Header: form})
	if resp.StatusCode != 410 {
		t.Fatalf("wrong verify token: %d", resp.StatusCode)
	}
	h.VerifyFromPush(t, m)
	if resp, _ := h.SubmitVerify(t, m); resp.StatusCode != 410 {
		t.Fatalf("verify reuse: %d", resp.StatusCode)
	}
}

func TestProvision(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	ctx := context.Background()
	if _, err := h.Svc.Provision(ctx, "dana"); err != nil {
		t.Fatal(err)
	}
	if h.Ntfy.User("dana") == nil || h.Ntfy.Grant("dana", "dana-*") != config.PermReadWrite || h.Ntfy.Grant("dana", "alerts") != config.PermReadOnly {
		t.Fatalf("enroll-access not applied: %+v", h.Ntfy.User("dana"))
	}
	// Provisioning creates no push device.
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("dana"))
	if pre.Response.Result != "enroll" {
		t.Fatalf("preauth after provision: %+v", pre.Response)
	}

	// The default handoff subscribes to every default topic, ${user} expanded.
	hd := h.Svc.DefaultHandoff("dana")
	if hd.Server != h.Cfg.NtfyBaseURL || len(hd.Links) != 2 ||
		hd.Links[0] != (core.TopicLink{Topic: "alerts", URL: ntfyLink(h, "alerts", "dana")}) ||
		hd.Links[1] != (core.TopicLink{Topic: "dana-inbox", URL: ntfyLink(h, "dana-inbox", "dana")}) {
		t.Fatalf("default handoff %+v", hd)
	}

	// A new ntfy password replaces the old one and is returned once.
	before := h.Ntfy.Password("dana")
	pw, err := h.Svc.SetNtfyPassword(ctx, "dana")
	if err != nil || pw == "" || pw == before || h.Ntfy.Password("dana") != pw {
		t.Fatalf("ntfy password: %q %v", pw, err)
	}
}

// ntfyLink is the subscribe link for topic as user on the harness's plain-HTTP ntfy server.
func ntfyLink(h *testutil.Harness, topic, user string) string {
	return "ntfy://" + strings.TrimPrefix(h.Cfg.NtfyBaseURL, "http://") + "/" + topic + "?secure=false&user=" + user
}

func TestProvisionRefusesUsernameThatReachesPushTopics(t *testing.T) {
	// "${user}-*" for a user named "push" would be "push-*": every push topic.
	h := testutil.NewHarness(t, nil)
	if _, err := h.Svc.Provision(context.Background(), "push"); err == nil {
		t.Fatal("provisioning user \"push\" must be refused")
	}
	if h.Ntfy.Grant("push", "push-*") != "" {
		t.Fatal("push-* granted")
	}
}

func TestEnrollLinkSingleUse(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	_, link, _, err := h.Svc.CreateEnrollCode(context.Background(), "erin", core.EnrollCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	if _, st, b := h.FinishEnroll(t, "", link, testutil.NewAuthenticator(t, testutil.PublicURL)); st != 200 {
		t.Fatalf("finish: %d %s", st, b)
	}
	// A used code surfaces at begin, the page's first call.
	if _, _, st := h.BeginEnroll(t, "", link, "Again"); st != 410 {
		t.Fatalf("used link: %d", st)
	}
}

func TestDeleteUser(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	ctx := context.Background()
	h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	if err := h.Svc.DeleteUser(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if h.Ntfy.User("alice") != nil {
		t.Fatal("ntfy user kept")
	}
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "enroll" {
		t.Fatalf("preauth after delete: %+v", pre.Response)
	}
	entries, _ := h.Svc.AuditLog(ctx, "alice", 100)
	events := map[string]bool{}
	for _, e := range entries {
		events[e.Event] = true
	}
	for _, want := range []string{"provision", "device_enrolled", "device_verified", "device_revoked", "user_deleted"} {
		if !events[want] {
			t.Fatalf("audit lacks %q: %v", want, events)
		}
	}
}

func TestStartupChecks(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	if err := h.Svc.StartupChecks(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, unsafe := range map[string]func(*testutil.Harness){
		"wrong admin token": func(h *testutil.Harness) {
			h.Restart(t, func(c *config.Config) { c.NtfyAdminToken = "tk_wrong" })
		},
		// A non-admin token could not manage users, and suggests the wrong token was configured.
		"non-admin token": func(h *testutil.Harness) { h.Ntfy.AdminRole = "user" },
		// Anyone could read the push topics, and with them the approve links and deny tokens.
		"anonymous read": func(h *testutil.Harness) { h.Ntfy.AnonymousRead = true },
	} {
		h := testutil.NewHarness(t, nil)
		unsafe(h)
		if err := h.Svc.StartupChecks(context.Background()); err == nil {
			t.Errorf("%s passed startup checks", name)
		}
	}
}

func TestResetResumesAfterNtfyUserDeleted(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))

	// ntfy deleted the user, then failed to recreate it.
	h.Ntfy.FailNext("POST", "/v1/users", 1)
	if err := h.Svc.ResetNtfyUser(ctx, "alice", false); err == nil {
		t.Fatal("reset reported success while ntfy failed")
	}
	if h.Ntfy.User("alice") != nil {
		t.Fatal("fake ntfy did not get past the delete")
	}
	if err := h.Svc.ResetNtfyUser(ctx, "alice", false); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if h.Ntfy.Grant("alice", dev.Topic) != config.PermReadOnly || h.Ntfy.Grant("alice", "alice-*") != config.PermReadWrite {
		t.Fatalf("grants after resumed reset: %+v", h.Ntfy.User("alice"))
	}
}

func TestCleanupWhenNtfyUserAlreadyGone(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	first := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	stale := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Ntfy.FailNext("DELETE", "/v1/users/access", 1)
	_ = h.Svc.RevokeDevice(ctx, stale.DeviceID, false, false, "test")

	// An ntfy admin removed the user by hand: there is nothing left to revoke there.
	h.Ntfy.DeleteUser("alice")
	if err := h.Svc.RevokeDevice(ctx, first.DeviceID, false, false, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if h.HasDevice(t, "alice", first.DeviceID) {
		t.Fatal("device row kept")
	}
	h.Svc.Purge(ctx)
	if h.HasDevice(t, "alice", stale.DeviceID) {
		t.Fatal("purge did not finish the revoke")
	}
	if err := h.Svc.DeleteUser(ctx, "alice", false); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if _, _, err := h.Svc.DevicesOf(ctx, "alice"); !errors.Is(err, core.ErrUnknownUser) {
		t.Fatalf("user row kept: %v", err)
	}
}

// Pushes orphaned by process restarts are timed out and cleared by the purge job.
func TestPurgeTimesOutOrphanedPush(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	// Left by a process that is gone: no auth call here waits on them.
	orphan := func(ttl time.Duration) *model.Challenge {
		now := time.Now()
		c := &model.Challenge{ID: token.Random(16), Username: "alice", DeviceID: dev.DeviceID, Nonce: []byte("n"),
			DenyTokenHash: token.Hash("deny"), CreatedAt: now, ExpiresAt: now.Add(ttl)}
		if err := h.Store.CreateChallenge(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	expired, live := orphan(-time.Second), orphan(time.Minute)

	h.Svc.Purge(ctx)
	if _, err := h.Svc.PendingChallenge(ctx, expired.ID); !errors.Is(err, core.ErrGone) {
		t.Fatalf("expired challenge still pending: %v", err)
	}
	if _, err := h.Svc.PendingChallenge(ctx, live.ID); err != nil {
		t.Fatalf("unexpired challenge: %v", err)
	}
	if got := h.Ntfy.Deleted(); len(got) != 1 || got[0] != dev.Topic+"/"+expired.ID {
		t.Fatalf("deleted pushes %v", got)
	}
}

func TestAuthOutlastsWriteTimeoutAfterReload(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Reload(t, func(c *config.Config) { c.PushTimeout = config.Duration(20 * time.Second) })

	res := authCall(h, "alice", dev.DeviceID)
	m := h.Ntfy.NextPublish(t)
	// Answer after the server's write timeout but within push-timeout.
	time.Sleep(h.Server.Config.WriteTimeout + time.Second)
	if st := approve(t, h, dev.Auth, m.Click); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	if r := wait(t, res); r.Response.Result != "allow" {
		t.Fatalf("auth: %+v", r.Response)
	}
}

func TestPendingLoginBlockedByLaterDisable(t *testing.T) {
	ctx := context.Background()
	t.Run("user disable", func(t *testing.T) {
		h := testutil.NewHarness(t, nil)
		dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
		res := authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		if err := h.Svc.SetUserDisabled(ctx, "alice", true); err != nil {
			t.Fatal(err)
		}
		if r := wait(t, res); r.Response.Result != "deny" {
			t.Fatalf("auth after disable: %+v", r.Response)
		}
		if st := approve(t, h, dev.Auth, m.Click); st != 410 {
			t.Fatalf("approve after disable: %d", st)
		}
	})
	t.Run("kill switch", func(t *testing.T) {
		h := testutil.NewHarness(t, nil)
		dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
		res := authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		h.Reload(t, func(c *config.Config) { c.PushDisabled = true })
		if r := wait(t, res); r.Response.Result != "deny" {
			t.Fatalf("auth after kill switch: %+v", r.Response)
		}
		if st := approve(t, h, dev.Auth, m.Click); st != 410 {
			t.Fatalf("approve after kill switch: %d", st)
		}
	})
	t.Run("disabled by another process", func(t *testing.T) {
		// Disabled by another process straight in the database, so this one denied no pending
		// logins: valid passkey and CLI break-glass approvals are still refused.
		h := testutil.NewHarness(t, func(c *config.Config) { c.PushTimeout = config.Duration(2 * time.Second) })
		dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
		authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		u, _, _ := h.Svc.DevicesOf(ctx, "alice")
		if err := h.Store.SetUserDisabled(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		if st := approve(t, h, dev.Auth, m.Click); st != 403 {
			t.Fatalf("approve for disabled user: %d", st)
		}
		id := strings.TrimPrefix(testutil.LocalPath(t, m.Click), "/challenge/")
		if err := h.Svc.AdminApprove(ctx, id); err == nil {
			t.Fatal("admin approve for disabled user succeeded")
		}
	})
}

func TestSyncedPasskeyLockedOutWhenPolicyTightened(t *testing.T) {
	short := func(c *config.Config) { c.PushTimeout = config.Duration(2 * time.Second) }
	h := testutil.NewHarness(t, func(c *config.Config) { short(c); c.WebAuthnAllowSynced = true })
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	a.Flags |= testutil.FlagBE | testutil.FlagBS
	dev := h.Enroll(t, "alice", a)
	res := authCall(h, "alice", dev.DeviceID)
	m := h.Ntfy.NextPublish(t)
	path := testutil.LocalPath(t, m.Click)
	// Options fetched while synced passkeys were allowed, asserted after they no longer are.
	_, opts := h.Do(t, testutil.Request{Method: "GET", Path: path + "/options"})

	h.Restart(t, func(c *config.Config) { c.WebAuthnAllowSynced = false })
	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: path + "/assert", Body: a.Get(t, opts)})
	if resp.StatusCode != 403 {
		t.Fatalf("synced assertion after policy change: %d", resp.StatusCode)
	}
	if st := approve(t, h, a, m.Click); st != 403 {
		t.Fatalf("synced passkey approved after policy change: %d", st)
	}
	if r := wait(t, res); r.Response.Result != "deny" {
		t.Fatalf("auth %+v", r.Response)
	}
}

func TestRevokeResumesAfterNtfyFailure(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	lost := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	kept := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	res := authCall(h, "alice", lost.DeviceID)
	m := h.Ntfy.NextPublish(t)

	h.Ntfy.FailNext("DELETE", "/v1/users/access", 1)
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, false, false, "test"); err == nil {
		t.Fatal("revoke reported success while ntfy failed")
	}
	// Locally revoked regardless: nothing can approve, preauth no longer lists it.
	if r := wait(t, res); r.Response.Result != "deny" {
		t.Fatalf("pending auth: %+v", r.Response)
	}
	if st := approve(t, h, lost.Auth, m.Click); st != 410 {
		t.Fatalf("approve after failed revoke: %d", st)
	}
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if len(pre.Response.Devices) != 1 || pre.Response.Devices[0].Device != kept.DeviceID {
		t.Fatalf("preauth after failed revoke: %+v", pre.Response)
	}
	if h.Ntfy.Grant("alice", lost.Topic) == "" {
		t.Fatal("fake ntfy did not fail")
	}

	// Re-running finishes the job.
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, false, false, "test"); err != nil {
		t.Fatal(err)
	}
	if h.Ntfy.Grant("alice", lost.Topic) != "" {
		t.Fatal("topic grant left after retry")
	}
	if h.HasDevice(t, "alice", lost.DeviceID) {
		t.Fatal("device row left after retry")
	}

	// A reset that fails is resumable the same way, and the purge job finishes plain revokes.
	again := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Ntfy.FailNext("DELETE", "/v1/users", 1)
	if err := h.Svc.RevokeDevice(ctx, again.DeviceID, true, false, "test"); err == nil {
		t.Fatal("reset reported success while ntfy failed")
	}
	if err := h.Svc.RevokeDevice(ctx, again.DeviceID, true, false, "test"); err != nil {
		t.Fatal(err)
	}
	if h.Ntfy.Grant("alice", kept.Topic) != config.PermReadOnly || h.Ntfy.Grant("alice", again.Topic) != "" {
		t.Fatalf("grants after reset: %+v", h.Ntfy.User("alice").Grants)
	}
	third := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Ntfy.FailNext("DELETE", "/v1/users/access", 1)
	_ = h.Svc.RevokeDevice(ctx, third.DeviceID, false, false, "test")
	h.Svc.Purge(ctx)
	if h.HasDevice(t, "alice", third.DeviceID) || h.Ntfy.Grant("alice", third.Topic) != "" {
		t.Fatal("purge did not finish the revoke")
	}
}

// A reset requested with a revoke must complete, even if the revoke fails early and the purge job
// removes the device row.
func TestPurgeFinishesInterruptedReset(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	kept := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	lost := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	before := h.Ntfy.Password("alice")

	h.Ntfy.FailNext("DELETE", "/v1/users/access", 1)
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, true, false, "test"); err == nil {
		t.Fatal("revoke reported success while ntfy failed")
	}
	if h.Ntfy.Password("alice") != before {
		t.Fatal("fake ntfy did not fail before the reset")
	}
	h.Ntfy.FailNext("POST", "/v1/users", 1)
	h.Svc.Purge(ctx)
	if h.HasDevice(t, "alice", lost.DeviceID) {
		t.Fatal("purge did not finish the revoke")
	}
	h.Svc.Purge(ctx)
	if h.Ntfy.User("alice") == nil || h.Ntfy.Password("alice") == before {
		t.Fatal("purge did not reset the ntfy user")
	}
	if h.Ntfy.Grant("alice", kept.Topic) != config.PermReadOnly || h.Ntfy.Grant("alice", lost.Topic) != "" {
		t.Fatalf("grants after reset: %+v", h.Ntfy.User("alice").Grants)
	}
	if pending, _ := h.Store.PendingNtfyResets(ctx); len(pending) != 0 {
		t.Fatalf("resets still pending: %v", pending)
	}
}

// Disabling a user denies logins, but must not prevent resetting/recreating the ntfy account to
// avoid hanging resets.
func TestResetWhileUserDisabled(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	kept := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	lost := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	if err := h.Svc.SetUserDisabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	wantGrants := func(want map[string]string) {
		t.Helper()
		u := h.Ntfy.User("alice")
		if u == nil {
			t.Fatal("ntfy user not recreated")
		}
		got := map[string]string{}
		for _, g := range u.Grants {
			got[g.Topic] = g.Permission
		}
		if len(got) != len(want) {
			t.Fatalf("grants %v, want %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("grants %v, want %v", got, want)
			}
		}
	}

	before := h.Ntfy.Password("alice")
	if err := h.Svc.RevokeDevice(ctx, lost.DeviceID, true, false, "test"); err != nil {
		t.Fatalf("revoke with reset: %v", err)
	}
	if h.Ntfy.Password("alice") == before {
		t.Fatal("ntfy user not recreated")
	}
	wantGrants(map[string]string{"alice-*": config.PermReadWrite, "alerts": config.PermReadOnly, kept.Topic: config.PermReadOnly})
	if pending, _ := h.Store.PendingNtfyResets(ctx); len(pending) != 0 {
		t.Fatalf("resets still pending: %v", pending)
	}
	if h.HasDevice(t, "alice", lost.DeviceID) {
		t.Fatal("device row kept")
	}

	// Nothing is left for the purge job.
	after := h.Ntfy.Password("alice")
	if err := h.Svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if h.Ntfy.Password("alice") != after {
		t.Fatal("reconcile reset the ntfy user again")
	}

	// user reset-ntfy works on a disabled user too; the user stays disabled.
	if err := h.Svc.ResetNtfyUser(ctx, "alice", false); err != nil {
		t.Fatalf("reset-ntfy: %v", err)
	}
	if h.Ntfy.Password("alice") == after {
		t.Fatal("ntfy user not recreated")
	}
	wantGrants(map[string]string{"alice-*": config.PermReadWrite, "alerts": config.PermReadOnly, kept.Topic: config.PermReadOnly})
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "deny" {
		t.Fatalf("preauth after reset of a disabled user: %+v", pre.Response)
	}
	// Onboarding still refuses a disabled user.
	if _, err := h.Svc.Provision(ctx, "alice"); !errors.Is(err, core.ErrUserDisabled) {
		t.Fatalf("provision of a disabled user: %v", err)
	}
}

func TestResetRefusesForeignGrantUnderPushPrefix(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Ntfy.AddForeignGrant("alice", "push-ops", config.PermReadOnly)
	if err := h.Svc.RevokeDevice(context.Background(), dev.DeviceID, true, false, "test"); err == nil {
		t.Fatal("reset removed a grant the shim did not make")
	}
	if err := h.Svc.ResetNtfyUser(context.Background(), "alice", false); err == nil {
		t.Fatal("user reset-ntfy removed a grant the shim did not make")
	}
}

func TestFailedEnrollmentKeepsCodeUsable(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	_, link, _, err := h.Svc.CreateEnrollCode(ctx, "erin", core.EnrollCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	h.Ntfy.FailNext("POST", "/", 1) // the setup push
	failed, status, _ := h.FinishEnroll(t, "", link, testutil.NewAuthenticator(t, testutil.PublicURL))
	if status == 200 {
		t.Fatal("enrollment succeeded while ntfy failed")
	}
	if _, devs, err := h.Svc.DevicesOf(ctx, "erin"); err != nil || len(devs) != 0 {
		t.Fatalf("half-built device left: %+v %v", devs, err)
	}
	for _, g := range h.Ntfy.User("erin").Grants {
		if strings.HasPrefix(g.Topic, "push-") {
			t.Fatalf("topic grant left: %+v (failed device %q)", g, failed.DeviceID)
		}
	}
	e, status, b := h.FinishEnroll(t, "", link, testutil.NewAuthenticator(t, testutil.PublicURL))
	if status != 200 {
		t.Fatalf("retry with the same code: %d %s", status, b)
	}
	h.VerifyFromPush(t, h.Ntfy.NextPublish(t))
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("erin"))
	if pre.Response.Result != "auth" || pre.Response.Devices[0].Device != e.DeviceID {
		t.Fatalf("preauth after retry: %+v", pre.Response)
	}
}

func TestEnrollmentResultResend(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	e, status, b := h.FinishEnroll(t, "alice", "", testutil.NewAuthenticator(t, testutil.PublicURL))
	if status != 200 || e.ResultToken == "" {
		t.Fatalf("finish: %d %s", status, b)
	}
	first := h.Ntfy.NextPublish(t)
	// The result page keeps working across a server restart.
	h.Restart(t, func(*config.Config) {})

	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: "/token/resend", Body: []byte(`{"token":"forged"}`)})
	if resp.StatusCode != 410 {
		t.Fatalf("forged result token: %d", resp.StatusCode)
	}

	// Resending replaces the setup link: the new one activates, the old one no longer does.
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: "/token/resend", Body: []byte(`{"token":"` + e.ResultToken + `"}`)})
	if resp.StatusCode != 200 {
		t.Fatalf("resend: %d", resp.StatusCode)
	}
	second := h.Ntfy.NextPublish(t)
	if resp, _ := h.SubmitVerify(t, first); resp.StatusCode != 410 {
		t.Fatalf("superseded setup link: %d", resp.StatusCode)
	}
	h.VerifyFromPush(t, second)
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: "/token/resend", Body: []byte(`{"token":"` + e.ResultToken + `"}`)})
	if resp.StatusCode != 410 {
		t.Fatalf("resend after setup: %d", resp.StatusCode)
	}
}

// Enrollment is a core ceremony: the web adapter only carries the handle and attestation.
func TestEnrollmentThroughCore(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	a := testutil.NewAuthenticator(t, testutil.PublicURL)

	handle, _, err := h.Svc.BeginEnrollment(ctx, core.EnrollRequest{Username: "alice", DeviceName: "  Pixel 9 "})
	if err != nil {
		t.Fatal(err)
	}
	// Without a code, the identity finishing the ceremony must be the user who began it.
	if _, err := h.Svc.FinishEnrollment(ctx, handle, "mallory", strings.NewReader("")); !errors.Is(err, core.ErrIdentityChanged) {
		t.Fatalf("finish as another user: %v", err)
	}
	// A handle is single-use: the refused attempt consumed it.
	if _, err := h.Svc.FinishEnrollment(ctx, handle, "alice", strings.NewReader("")); !errors.Is(err, core.ErrEnrollmentExpired) {
		t.Fatalf("reused handle: %v", err)
	}

	handle, opts, err := h.Svc.BeginEnrollment(ctx, core.EnrollRequest{Username: "alice", DeviceName: "  Pixel 9 "})
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.Svc.FinishEnrollment(ctx, handle, "alice", strings.NewReader(string(a.Create(t, opts))))
	if err != nil {
		t.Fatal(err)
	}
	if res.Device.Name != "Pixel 9" || res.ResultToken == "" || h.Ntfy.Grant("alice", res.Device.NtfyTopic) != config.PermReadOnly {
		t.Fatalf("enrollment %+v", res)
	}
	h.VerifyFromPush(t, h.Ntfy.NextPublish(t))
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "auth" || pre.Response.Devices[0].Device != res.Device.ID {
		t.Fatalf("preauth: %+v", pre.Response)
	}

	// An unnamed device gets a default name.
	handle, opts, err = h.Svc.BeginEnrollment(ctx, core.EnrollRequest{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	res, err = h.Svc.FinishEnrollment(ctx, handle, "alice", strings.NewReader(string(testutil.NewAuthenticator(t, testutil.PublicURL).Create(t, opts))))
	if err != nil || res.Device.Name != "Phone" {
		t.Fatalf("default name: %+v %v", res, err)
	}
}
