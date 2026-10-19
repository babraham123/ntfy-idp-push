package duoapi_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	duoapigo "github.com/duosecurity/duo_api_golang"
	"github.com/skip2/go-qrcode"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/duoapi"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

type fail struct {
	Stat    string `json:"stat"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// signedPOST builds a form-encoded v2 request by hand, so tests can tamper with any part of it.
type signedPOST struct {
	host, path, date string
	signed, sent     url.Values
	ikey, skey       string
}

func (h signedPOST) send(t *testing.T, hs *testutil.Harness) (int, fail) {
	t.Helper()
	if h.ikey == "" {
		h.ikey, h.skey = testutil.IKey, testutil.SKey
	}
	if h.host == "" {
		h.host = hs.Host
	}
	if h.date == "" {
		h.date = time.Now().UTC().Format(time.RFC1123Z)
	}
	if h.sent == nil {
		h.sent = h.signed
	}
	req, _ := http.NewRequest("POST", hs.Server.URL+h.path, strings.NewReader(h.sent.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Date", h.date)
	req.Header.Set("Authorization", duoapi.SignatureHeader(h.ikey, h.skey, duoapi.CanonV2(h.date, "POST", h.host, h.path, h.signed)))
	resp, err := hs.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var f fail
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &f)
	return resp.StatusCode, f
}

func TestCanonicalizationParityWithDuoClient(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	// Spaces, reserved characters, repeated keys and unicode exercise every canonicalization rule.
	res, err := h.Duo(testutil.IKey, testutil.SKey).Preauth(
		func(v *url.Values) {
			v.Set("username", "alice")
			v.Set("ipaddr", "10.0.0.1")
			v.Set("hostname", "laptop name+with/odd~chars é")
			v.Add("zz", "b")
			v.Add("zz", "a")
		})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stat != "OK" {
		t.Fatalf("stat %s: %v", res.Stat, *res.Message)
	}
}

func TestPingAndCheck(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	duo := h.Duo(testutil.IKey, testutil.SKey)
	if r, err := duo.Ping(); err != nil || r.Stat != "OK" || r.Response.Time == 0 {
		t.Fatalf("ping: %+v %v", r, err)
	}
	if r, err := duo.Check(); err != nil || r.Stat != "OK" {
		t.Fatalf("check: %+v %v", r, err)
	}
	if r, err := h.Duo(testutil.IKey, strings.Repeat("x", 40)).Check(); err != nil || r.Stat != "FAIL" {
		t.Fatalf("check with wrong key must fail: %+v %v", r, err)
	}
}

func TestPreauthUnenrolled(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	r, err := h.Duo(testutil.IKey, testutil.SKey).Preauth(func(v *url.Values) { v.Set("username", "nobody") })
	if err != nil {
		t.Fatal(err)
	}
	if r.Response.Result != "enroll" || r.Response.Enroll_Portal_Url != testutil.PublicURL+"/enroll" {
		t.Fatalf("got %+v", r.Response)
	}

	h = testutil.NewHarness(t, func(c *config.Config) { c.EnrollPortalURL = "" })
	r, err = h.Duo(testutil.IKey, testutil.SKey).Preauth(func(v *url.Values) { v.Set("username", "nobody") })
	if err != nil {
		t.Fatal(err)
	}
	if r.Response.Result != "deny" {
		t.Fatalf("without enroll-portal-url unenrolled users must be denied, got %+v", r.Response)
	}
}

func TestSignatureRejections(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	params := url.Values{"username": {"alice"}}
	cases := []struct {
		name string
		req  signedPOST
		code int
	}{
		{"wrong ikey", signedPOST{ikey: "DIBBBBBBBBBBBBBBBBBB", skey: testutil.SKey}, 40102},
		{"wrong skey", signedPOST{ikey: testutil.IKey, skey: strings.Repeat("k", 40)}, 40103},
		{"tampered params", signedPOST{sent: url.Values{"username": {"mallory"}}}, 40103},
		{"other host signed", signedPOST{host: "api-12345.duosecurity.com"}, 40103},
		{"stale date", signedPOST{date: time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC1123Z)}, 40105},
		{"future date", signedPOST{date: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC1123Z)}, 40105},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.req.path, c.req.signed = "/auth/v2/preauth", params
			status, f := c.req.send(t, h)
			if status != 401 || f.Stat != "FAIL" || f.Code != c.code {
				t.Fatalf("got %d %+v, want 401 code %d", status, f, c.code)
			}
		})
	}
}

func TestHostHeaderMustMatch(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	date := time.Now().UTC().Format(time.RFC1123Z)
	params := url.Values{"username": {"alice"}}
	req, _ := http.NewRequest("POST", h.Server.URL+"/auth/v2/preauth", strings.NewReader(params.Encode()))
	req.Host = "proxy.internal"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Date", date)
	// Signed for the rewritten host, as a client configured with it would.
	req.Header.Set("Authorization", duoapi.SignatureHeader(testutil.IKey, testutil.SKey, duoapi.CanonV2(date, "POST", "proxy.internal", "/auth/v2/preauth", params)))
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
}

func TestReplay(t *testing.T) {
	h := testutil.NewHarness(t, nil)
	date := time.Now().UTC().Format(time.RFC1123Z)
	// enroll has side effects: a replayed request is refused.
	req := signedPOST{path: "/auth/v2/enroll", signed: url.Values{"username": {"alice"}}, date: date}
	if status, f := req.send(t, h); status != 200 {
		t.Fatalf("first: %d %+v", status, f)
	}
	if status, f := req.send(t, h); status != 401 || f.Code != 40101 {
		t.Fatalf("replay: got %d %+v, want 401", status, f)
	}
	// preauth is idempotent; identical calls within the same second are legitimate.
	req = signedPOST{path: "/auth/v2/preauth", signed: url.Values{"username": {"alice"}}, date: date}
	for i := 0; i < 2; i++ {
		if status, f := req.send(t, h); status != 200 {
			t.Fatalf("preauth %d: %d %+v", i, status, f)
		}
	}
}

func TestSHA1SignatureAccepted(t *testing.T) {
	// duo_client_python with sig_version=2 and an HMAC-SHA1 digestmod.
	h := testutil.NewHarness(t, nil)
	date := time.Now().UTC().Format(time.RFC1123Z)
	params := url.Values{"username": {"alice"}}
	canon := duoapi.CanonV2(date, "POST", h.Host, "/auth/v2/preauth", params)
	m := hmac.New(sha1.New, []byte(testutil.SKey))
	m.Write([]byte(canon))
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(testutil.IKey+":"+hex.EncodeToString(m.Sum(nil))))
	req, _ := http.NewRequest("POST", h.Server.URL+"/auth/v2/preauth", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Date", date)
	req.Header.Set("Authorization", auth)
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestVerifyBodyKind(t *testing.T) {
	// JSON bodies are v5 only, form bodies v2 only, bodyless requests try both. SHA-1 is v2
	// only.
	const host, path, skey = "api-test.example", "/auth/v2/preauth", "verify-body-kind-secret-key-0123456789ab"
	date := time.Now().UTC().Format(time.RFC1123Z)
	alice := url.Values{"username": {"alice"}}
	type kind struct {
		method, contentType, body string
		query, signed             url.Values
	}
	kinds := map[string]kind{
		"json":     {method: "POST", contentType: "application/json", body: `{"username":"alice"}`},
		"form":     {method: "POST", contentType: "application/x-www-form-urlencoded", body: alice.Encode(), signed: alice},
		"bodyless": {method: "GET", query: alice, signed: alice},
	}
	hashes := map[string]func() hash.Hash{"sha512": sha512.New, "sha1": sha1.New}
	cases := []struct {
		kind, canon, hash string
		ok                bool
	}{
		{"json", "v5", "sha512", true},
		{"json", "v2", "sha512", false},
		{"json", "v5", "sha1", false},
		{"json", "v2", "sha1", false},
		{"form", "v2", "sha512", true},
		{"form", "v5", "sha512", false},
		{"form", "v2", "sha1", true},
		{"form", "v5", "sha1", false},
		{"bodyless", "v2", "sha512", true},
		{"bodyless", "v5", "sha512", true},
		{"bodyless", "v2", "sha1", true},
		{"bodyless", "v5", "sha1", false},
	}
	for _, c := range cases {
		k := kinds[c.kind]
		t.Run(c.kind+"/"+c.canon+"/"+c.hash, func(t *testing.T) {
			header := http.Header{}
			if k.contentType != "" {
				header.Set("Content-Type", k.contentType)
			}
			canon := duoapi.CanonV2(date, k.method, host, path, k.signed)
			if c.canon == "v5" {
				canon = duoapi.CanonV5(date, k.method, host, path, k.signed, []byte(k.body), header)
			}
			m := hmac.New(hashes[c.hash], []byte(skey))
			m.Write([]byte(canon))
			got, err := duoapi.Verify(duoapi.SignedRequest{
				Method: k.method, Host: host, Path: path, Query: k.query, Header: header,
				Body: []byte(k.body), Date: date, Sig: hex.EncodeToString(m.Sum(nil)),
			}, []string{skey})
			if (err == nil) != c.ok {
				t.Fatalf("err %v, want accepted=%v", err, c.ok)
			}
			if c.ok && got.Get("username") != "alice" {
				t.Fatalf("params %v, want username=alice", got)
			}
		})
	}
}

func TestKeyRotationGrace(t *testing.T) {
	newKey := strings.Repeat("n", 40)
	for _, c := range []struct {
		name      string
		rotatedAt time.Time
		oldOK     bool
	}{
		{"inside grace", time.Now().Add(-10 * time.Minute), true},
		{"after grace", time.Now().Add(-2 * time.Hour), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testutil.NewHarness(t, func(cfg *config.Config) {
				cfg.DuoSecretKey = newKey
				cfg.DuoSecretKeyPrevious = testutil.SKey
				cfg.DuoSecretKeyRotatedAt = c.rotatedAt.UTC().Format(time.RFC3339)
			})
			if r, err := h.Duo(testutil.IKey, newKey).Check(); err != nil || r.Stat != "OK" {
				t.Fatalf("new key: %+v %v", r, err)
			}
			r, err := h.Duo(testutil.IKey, testutil.SKey).Check()
			if err != nil {
				t.Fatal(err)
			}
			if (r.Stat == "OK") != c.oldOK {
				t.Fatalf("old key stat %s, want accepted=%v", r.Stat, c.oldOK)
			}
		})
	}
}

func TestV5SignedGET(t *testing.T) {
	// JSONSignedCall and duo_client_python v5 send GET query params without body/Content-Type
	// but sign v5.
	h := testutil.NewHarness(t, nil)
	resp, body, err := h.DuoClient().JSONSignedCall("GET", "/auth/v2/check", duoapigo.JSONParams{}, duoapigo.UseTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"stat":"OK"`) {
		t.Fatalf("v5 GET check: %d %s", resp.StatusCode, body)
	}
	bad := duoapigo.NewDuoApi(testutil.IKey, "wrongwrongwrongwrongwrongwrongwrongwrong", h.Host, "test", duoapigo.SetInsecure())
	resp, _, err = bad.JSONSignedCall("GET", "/auth/v2/check", duoapigo.JSONParams{}, duoapigo.UseTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("v5 GET with wrong key: %d", resp.StatusCode)
	}
}

func TestV5JSONEnrollAndStatus(t *testing.T) {
	// authentik's duo_client signs JSON bodies with v5; duo_api_golang's JSONSignedCall does the same.
	h := testutil.NewHarness(t, nil)
	duo := h.DuoClient()
	_, body, err := duo.JSONSignedCall("POST", "/auth/v2/enroll", duoapigo.JSONParams{"username": "carol"}, duoapigo.UseTimeout)
	if err != nil {
		t.Fatal(err)
	}
	var enroll struct {
		Stat     string
		Response struct {
			ActivationBarcode string `json:"activation_barcode"`
			ActivationCode    string `json:"activation_code"`
			ActivationURL     string `json:"activation_url"`
			Expiration        int64  `json:"expiration"`
			UserID            string `json:"user_id"`
			Username          string `json:"username"`
		}
	}
	if err := json.Unmarshal(body, &enroll); err != nil || enroll.Stat != "OK" {
		t.Fatalf("enroll: %s %v", body, err)
	}
	r := enroll.Response
	if r.Username != "carol" || r.UserID == "" || r.ActivationCode == "" || r.Expiration <= time.Now().Unix() {
		t.Fatalf("enroll response: %+v", r)
	}
	// The phone's link carries the code in its fragment, and the barcode is a QR of that link.
	if r.ActivationURL != testutil.PublicURL+"/token/#"+r.ActivationCode ||
		r.ActivationBarcode != testutil.PublicURL+"/token/qr?value="+url.QueryEscape(r.ActivationURL) {
		t.Fatalf("activation links: %+v", r)
	}
	// The ntfy account exists (provisioned) but nothing push-related yet.
	if h.Ntfy.User("carol") == nil {
		t.Fatal("ntfy user not provisioned")
	}

	status := func() string {
		_, body, err := duo.JSONSignedCall("POST", "/auth/v2/enroll_status",
			duoapigo.JSONParams{"user_id": r.UserID, "activation_code": r.ActivationCode}, duoapigo.UseTimeout)
		if err != nil {
			t.Fatal(err)
		}
		var s struct{ Stat, Response string }
		if err := json.Unmarshal(body, &s); err != nil || s.Stat != "OK" {
			t.Fatalf("enroll_status: %s %v", body, err)
		}
		return s.Response
	}
	if s := status(); s != "waiting" {
		t.Fatalf("before enrollment: %s", s)
	}

	// The barcode renders only for the issued URL.
	resp, png := h.Do(t, testutil.Request{Method: "GET", Path: testutil.LocalPath(t, r.ActivationBarcode)})
	want, err := qrcode.Encode(r.ActivationURL, qrcode.Medium, 320)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" || !bytes.Equal(png, want) {
		t.Fatalf("barcode: %d %s, QR of the activation URL: %v", resp.StatusCode, resp.Header.Get("Content-Type"), bytes.Equal(png, want))
	}
	resp, _ = h.Do(t, testutil.Request{Method: "GET", Path: "/token/qr?value=" + url.QueryEscape("https://evil.example/")})
	if resp.StatusCode != 404 {
		t.Fatalf("arbitrary QR value: %d", resp.StatusCode)
	}

	// The phone scans the code and enrolls on the token routes, without any IdP session.
	a := testutil.NewAuthenticator(t, testutil.PublicURL)
	token, opts, st := h.BeginEnroll(t, "", r.ActivationURL, "Phone")
	if st != 200 {
		t.Fatalf("begin: %d", st)
	}
	resp, b := h.Do(t, testutil.Request{Method: "POST", Path: "/token/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts)})
	if resp.StatusCode != 200 {
		t.Fatalf("finish: %d %s", resp.StatusCode, b)
	}
	if s := status(); s != "waiting" {
		t.Fatalf("enrolled but unverified: %s", s)
	}
	h.VerifyFromPush(t, h.Ntfy.NextPublish(t))
	if s := status(); s != "success" {
		t.Fatalf("after verification: %s", s)
	}

	// The code is single-use.
	if _, _, st := h.BeginEnroll(t, "", r.ActivationURL, "Again"); st == 200 {
		t.Fatal("enrollment code reused")
	}

	// authentik then authenticates with factor=auto, device=auto by user_id.
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		_, body, err := duo.JSONSignedCall("POST", "/auth/v2/auth",
			duoapigo.JSONParams{"user_id": r.UserID, "factor": "auto", "device": "auto"})
		done <- result{body, err}
	}()
	if st := h.Approve(t, a, h.Ntfy.NextPublish(t).Click); st != 200 {
		t.Fatalf("approve: %d", st)
	}
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	var auth struct {
		Stat     string
		Response struct{ Result, Status string }
	}
	if err := json.Unmarshal(res.body, &auth); err != nil || auth.Response.Result != "allow" {
		t.Fatalf("auth: %s %v", res.body, err)
	}

	// The IdP may keep polling after the phone is removed; it must not keep reporting success.
	var finished struct{ Device string }
	if err := json.Unmarshal(b, &finished); err != nil {
		t.Fatal(err)
	}
	if err := h.Svc.RevokeDevice(context.Background(), finished.Device, core.Revocation{Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	if s := status(); s != "invalid" {
		t.Fatalf("after revocation: %s", s)
	}
}
