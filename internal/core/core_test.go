package core_test

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duosecurity/duo_api_golang/authapi"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

var callSeq atomic.Int32

// authCall runs an Authelia-shaped auth request in the background. Each call differs (by
// hostname) so back-to-back calls are not identical signed requests, which the replay guard refuses.
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
	if !strings.HasPrefix(dev.NtfyLink, "ntfy://") || !strings.Contains(dev.NtfyLink, "/"+dev.Topic+"?") ||
		!strings.Contains(dev.NtfyLink, "user=alice") || !strings.Contains(dev.NtfyLink, "code=") {
		t.Fatalf("ntfy link %q", dev.NtfyLink)
	}
	link, _ := url.Parse(dev.NtfyLink)
	if tok, err := h.Svc.Ntfy.RedeemEnrollCode(context.Background(), link.Query().Get("code"), "Pixel"); err != nil || tok.Username != "alice" {
		t.Fatalf("enrollment link code: %+v %v", tok, err)
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

func TestAuthRefusals(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	alice := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	h.Enroll(t, "bob", testutil.NewAuthenticator(t, testutil.PublicURL))
	duo := h.Duo(testutil.IKey, testutil.SKey)

	for _, c := range []struct {
		name   string
		factor string
		opts   []func(*url.Values)
	}{
		{"another user's device", "push", []func(*url.Values){authapi.AuthUsername("bob"), authapi.AuthDevice(alice.DeviceID)}},
		{"unknown user", "push", []func(*url.Values){authapi.AuthUsername("mallory"), authapi.AuthDevice("auto")}},
		{"sms factor", "sms", []func(*url.Values){authapi.AuthUsername("alice"), authapi.AuthDevice(alice.DeviceID)}},
		{"passcode factor", "passcode", []func(*url.Values){authapi.AuthUsername("alice"), authapi.AuthPasscode("123456")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, err := duo.Auth(c.factor, c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if r.Stat != "OK" || r.Response.Result != "deny" {
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

	next := *h.Cfg
	next.PushDisabled = true
	h.Svc.Reload(&next)
	pre, _ = duo.Preauth(authapi.PreauthUsername("alice"))
	if pre.Response.Result != "deny" {
		t.Fatalf("preauth with push disabled: %+v", pre.Response)
	}
	if r, _ := duo.Auth("push", authapi.AuthUsername("alice"), authapi.AuthDevice(dev.DeviceID), authapi.AuthIpAddr("198.51.100.1")); r.Response.Result != "deny" {
		t.Fatalf("auth with push disabled: %+v", r.Response)
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
	if _, err := h.Svc.Store.Device(context.Background(), dev.DeviceID); err == nil {
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
	if _, err := h.Svc.Store.Device(ctx, lost.DeviceID); err != nil {
		t.Fatalf("device removed despite refusal: %v", err)
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
	if resp.StatusCode != 400 || !strings.Contains(string(b), "synced") {
		t.Fatalf("synced passkey: %d %s", resp.StatusCode, b)
	}

	h = testutil.NewHarness(t, func(c *config.Config) { c.WebAuthnAllowSynced = true })
	h.Enroll(t, "alice", a)
}

func TestRequireAttestationRefusesNone(t *testing.T) {
	h := testutil.NewHarness(t, func(c *config.Config) { c.WebAuthnRequireAttestation = true })
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	token, opts, _ := h.BeginEnroll(t, "alice", "", "Phone")
	resp, _ := h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts), User: "alice"})
	if resp.StatusCode != 400 {
		t.Fatalf("attestation none accepted: %d", resp.StatusCode)
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
	u, _ := url.Parse(m.Click)
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: u.Path + "?t=wrong"})
	if resp.StatusCode != 410 {
		t.Fatalf("wrong verify token: %d", resp.StatusCode)
	}
	h.VerifyFromPush(t, m)
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: u.Path + "?" + u.RawQuery})
	if resp.StatusCode != 410 {
		t.Fatalf("verify reuse: %d", resp.StatusCode)
	}
}

func TestForwardAuthOnlyFromTrustedProxies(t *testing.T) {
	h := testutil.NewHarness(t, func(c *config.Config) { c.TrustedProxies = []string{"10.9.9.9"} })
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: "/devices", User: "alice"})
	if resp.StatusCode != 403 {
		t.Fatalf("untrusted Remote-User: %d", resp.StatusCode)
	}
	h = testutil.NewHarness(t, nil)
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/devices"})
	if resp.StatusCode != 403 {
		t.Fatalf("missing Remote-User: %d", resp.StatusCode)
	}
}

func TestProvision(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	resp, page := h.Do(t, testutil.Request{Method: "GET", Path: "/provision", User: "dana",
		Header: map[string]string{"User-Agent": "Mozilla/5.0 (Linux; Android 15)"}})
	if resp.StatusCode != 200 {
		t.Fatalf("provision: %d", resp.StatusCode)
	}
	for _, want := range []string{"ntfy://", "/alerts?", "/dana-inbox?", "user=dana", "play.google.com"} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("android page lacks %q", want)
		}
	}
	androidCode := linkParam(t, string(page), "ntfy://", "code")

	resp, page = h.Do(t, testutil.Request{Method: "GET", Path: "/provision", User: "dana",
		Header: map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}})
	if resp.StatusCode != 200 || !strings.Contains(string(page), "data:image/png;base64,") {
		t.Fatalf("desktop page: %d", resp.StatusCode)
	}
	// The web app link carries code, user and topics in the fragment, per ntfy's /account/token/redeem.
	frag, err := url.ParseQuery(linkParam(t, string(page), h.Ntfy.URL+"/account/token/redeem#", ""))
	if err != nil {
		t.Fatal(err)
	}
	if frag.Get("user") != "dana" || frag.Get("subscribe") != "alerts,dana-inbox" || frag.Get("code") == "" {
		t.Fatalf("redeem fragment %v", frag)
	}
	// Reloading superseded the first page's code; the new one redeems once, as dana.
	ctx := context.Background()
	if _, err := h.Svc.Ntfy.RedeemEnrollCode(ctx, androidCode, "Pixel"); err == nil {
		t.Fatal("superseded code still redeemable")
	}
	tok, err := h.Svc.Ntfy.RedeemEnrollCode(ctx, frag.Get("code"), "Laptop")
	if err != nil || tok.Username != "dana" {
		t.Fatalf("redeem: %+v %v", tok, err)
	}
	if _, err := h.Svc.Ntfy.RedeemEnrollCode(ctx, frag.Get("code"), "Laptop"); err == nil {
		t.Fatal("code redeemed twice")
	}
	// Provisioning creates no push device.
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("dana"))
	if pre.Response.Result != "enroll" {
		t.Fatalf("preauth after provision: %+v", pre.Response)
	}
	if h.Ntfy.Grant("dana", "dana-*") != config.PermReadWrite {
		t.Fatal("enroll-access not applied")
	}
}

// linkParam finds the first link starting with prefix in an HTML page and returns query param
// key, or with key "" the rest of the link after prefix.
func linkParam(t *testing.T, page, prefix, key string) string {
	t.Helper()
	i := strings.Index(page, prefix)
	if i < 0 {
		t.Fatalf("no link starting with %q", prefix)
	}
	link := html.UnescapeString(page[i : i+strings.IndexByte(page[i:], '"')])
	if key == "" {
		return strings.TrimPrefix(link, prefix)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
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

func TestEnrollmentWithoutNtfyEnrollEndpoint(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	h.Ntfy.EnrollSupported = false
	dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
	if dev.HasCode || strings.Contains(dev.NtfyLink, "code=") || !strings.Contains(dev.NtfyLink, "user=alice") {
		t.Fatalf("link without enroll support: %q", dev.NtfyLink)
	}
}

func TestEnrollLinkSingleUse(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	code, link, err := h.Svc.CreateEnrollCode(context.Background(), "erin", core.EnrollCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := h.Do(t, testutil.Request{Method: "GET", Path: testutil.LocalPath(t, link)})
	if resp.StatusCode != 200 {
		t.Fatalf("enroll page: %d", resp.StatusCode)
	}
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	token, opts, _ := h.BeginEnroll(t, "", code, "Phone")
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts)})
	if resp.StatusCode != 200 {
		t.Fatalf("finish: %d", resp.StatusCode)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: testutil.LocalPath(t, link)})
	if resp.StatusCode != 410 {
		t.Fatalf("used link: %d", resp.StatusCode)
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
	entries, _ := h.Svc.Store.AuditLog(ctx, "alice", 100)
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
	h2 := testutil.NewHarness(t, func(c *config.Config) { c.NtfyAdminToken = "tk_wrong" })
	if err := h2.Svc.StartupChecks(context.Background()); err == nil {
		t.Fatal("wrong admin token passed startup checks")
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
		next := *h.Cfg
		next.PushDisabled = true
		h.Svc.Reload(&next)
		if r := wait(t, res); r.Response.Result != "deny" {
			t.Fatalf("auth after kill switch: %+v", r.Response)
		}
		if st := approve(t, h, dev.Auth, m.Click); st != 410 {
			t.Fatalf("approve after kill switch: %d", st)
		}
	})
	t.Run("disabled by another process", func(t *testing.T) {
		// A disable that did not deny the pending login (e.g. a direct database change) still
		// keeps a valid passkey from approving it, and the CLI break-glass too.
		h := testutil.NewHarness(t, func(c *config.Config) { c.PushTimeout = config.Duration(2 * time.Second) })
		dev := h.Enroll(t, "alice", testutil.NewAuthenticator(t, testutil.PublicURL))
		authCall(h, "alice", dev.DeviceID)
		m := h.Ntfy.NextPublish(t)
		u, _ := h.Svc.Store.UserByName(ctx, "alice")
		if err := h.Svc.Store.SetUserDisabled(ctx, u.ID, true); err != nil {
			t.Fatal(err)
		}
		if st := approve(t, h, dev.Auth, m.Click); st != 403 {
			t.Fatalf("approve for disabled user: %d", st)
		}
		id := strings.TrimPrefix(testutil.LocalPath(t, m.Click), "/c/")
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
	if _, err := h.Svc.Store.Device(ctx, lost.DeviceID); err == nil {
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
	if _, err := h.Svc.Store.Device(ctx, third.DeviceID); err == nil || h.Ntfy.Grant("alice", third.Topic) != "" {
		t.Fatal("purge did not finish the revoke")
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
	code, _, err := h.Svc.CreateEnrollCode(ctx, "erin", core.EnrollCodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	h.Ntfy.FailNext("POST", "/", 1) // the setup push
	failed, status, _ := h.FinishEnroll(t, "", code, testutil.NewAuthenticator(t, testutil.PublicURL))
	if status == 200 {
		t.Fatal("enrollment succeeded while ntfy failed")
	}
	u, err := h.Svc.Store.UserByName(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	if devs, _ := h.Svc.Store.Devices(ctx, u.ID, false); len(devs) != 0 {
		t.Fatalf("half-built device left: %+v", devs)
	}
	for _, g := range h.Ntfy.User("erin").Grants {
		if strings.HasPrefix(g.Topic, "push-") {
			t.Fatalf("topic grant left: %+v (failed device %q)", g, failed.DeviceID)
		}
	}
	e, status, b := h.FinishEnroll(t, "", code, testutil.NewAuthenticator(t, testutil.PublicURL))
	if status != 200 {
		t.Fatalf("retry with the same code: %d %s", status, b)
	}
	h.VerifyFromPush(t, h.Ntfy.NextPublish(t))
	pre, _ := h.Duo(testutil.IKey, testutil.SKey).Preauth(authapi.PreauthUsername("erin"))
	if pre.Response.Result != "auth" || pre.Response.Devices[0].Device != e.DeviceID {
		t.Fatalf("preauth after retry: %+v", pre.Response)
	}
}

func TestEnrollmentResultResendAndManualSignIn(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	e, status, b := h.FinishEnroll(t, "alice", "", testutil.NewAuthenticator(t, testutil.PublicURL))
	if status != 200 || e.ResultToken == "" {
		t.Fatalf("finish: %d %s", status, b)
	}
	first := h.Ntfy.NextPublish(t)
	// The result page keeps working across a server restart.
	h.Restart(t, func(*config.Config) {})

	// Manual sign-in for apps that ignore the code: a fresh ntfy password, shown once.
	before := h.Ntfy.Password("alice")
	resp, b := h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/password", Body: []byte(`{"token":"` + e.ResultToken + `"}`)})
	var pw struct{ Username, Password string }
	_ = json.Unmarshal(b, &pw)
	if resp.StatusCode != 200 || pw.Username != "alice" || pw.Password == "" || pw.Password == before || h.Ntfy.Password("alice") != pw.Password {
		t.Fatalf("manual password: %d %s", resp.StatusCode, b)
	}
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/password", Body: []byte(`{"token":"forged"}`)})
	if resp.StatusCode != 410 {
		t.Fatalf("forged result token: %d", resp.StatusCode)
	}

	// Resending replaces the setup link: the new one activates, the old one no longer does.
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/resend", Body: []byte(`{"token":"` + e.ResultToken + `"}`)})
	if resp.StatusCode != 200 {
		t.Fatalf("resend: %d", resp.StatusCode)
	}
	second := h.Ntfy.NextPublish(t)
	if resp, _ := h.SubmitForm(t, testutil.LocalPath(t, first.Click), "", "/enroll/verify/", nil); resp.StatusCode != 410 {
		t.Fatalf("superseded setup link: %d", resp.StatusCode)
	}
	h.VerifyFromPush(t, second)
	resp, _ = h.Do(t, testutil.Request{Method: "POST", Path: "/enroll/resend", Body: []byte(`{"token":"` + e.ResultToken + `"}`)})
	if resp.StatusCode != 410 {
		t.Fatalf("resend after setup: %d", resp.StatusCode)
	}

	// The same manual path from /provision, a plain HTML form.
	resp, b = h.SubmitForm(t, "/provision", "alice", "/provision/password", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), h.Ntfy.Password("alice")) {
		t.Fatalf("provision password: %d", resp.StatusCode)
	}
}
