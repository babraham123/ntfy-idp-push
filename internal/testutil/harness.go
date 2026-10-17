package testutil

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	duoapigo "github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/duoapi"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/web"
)

const (
	IKey      = "DIAAAAAAAAAAAAAAAAAA"
	SKey      = "secretsecretsecretsecretsecretsecretsecr"
	PublicURL = "https://push.test"
)

// Harness is the whole shim on an httptest TLS server with a fake ntfy behind it. The test client
// connects from loopback, which the config lists as the trusted proxy, so Request.User plays the
// proxy's forward-auth step.
type Harness struct {
	Cfg    *config.Config
	Svc    *core.Service
	Ntfy   *FakeNtfy
	Server *httptest.Server
	// Host is what Duo clients put in the Host header and sign (duo-hostname).
	Host   string
	Client *http.Client
	Store  *store.Store
	log    *slog.Logger
}

// NewHarness starts the shim. mutate may adjust the config before validation.
func NewHarness(t *testing.T, mutate func(*config.Config)) *Harness {
	t.Helper()
	fn := NewFakeNtfy(t)
	srv := httptest.NewUnstartedServer(nil)
	host := srv.Listener.Addr().String()
	cfg := &config.Config{
		ListenHTTP:        "unused",
		PublicURL:         PublicURL,
		DuoHostname:       host,
		DuoIntegrationKey: IKey,
		DuoSecretKey:      SKey,
		DuoMaxSkew:        config.Duration(300 * time.Second),
		DuoKeyGrace:       config.Duration(time.Hour),
		PushTimeout:       config.Duration(10 * time.Second),
		TrustedProxies:    []string{"127.0.0.1/32", "::1/128"},
		IdentityHeader:    "Remote-User",
		EnrollPortalURL:   PublicURL + "/enroll",
		NtfyBaseURL:       fn.URL,
		NtfyAdminToken:    AdminToken,
		NtfyTopicPrefix:   "push-",
		DefaultTopics:     []string{"alerts", "${user}-inbox"},
		EnrollRole:        "user",
		EnrollAccess:      []string{"${user}-*:rw", "alerts:ro"},
		Database:          ":memory:",
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(&testWriter{t}, nil))
	}
	h := &Harness{Cfg: cfg, Ntfy: fn, Server: srv, Host: host, Store: st, log: log}
	h.serve(t)
	// Shorter than push-timeout (like serve's write timeout), forcing blocking auth to extend
	// its own deadline.
	srv.Config.WriteTimeout = 3 * time.Second
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
	h.Client = client
	return h
}

// serve builds the service from h.Cfg on h.Store and routes the server to it.
func (h *Harness) serve(t *testing.T) {
	t.Helper()
	svc, err := core.New(h.Cfg, h.Store, h.log)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	duoapi.New(svc, h.log).Register(mux)
	web.New(svc, h.log).Register(mux)
	h.Server.Config.Handler = web.SecurityHeaders(mux)
	h.Svc = svc
}

// Restart rebuilds the service on the same database with a changed config, as a restart would.
func (h *Harness) Restart(t *testing.T, mutate func(*config.Config)) {
	t.Helper()
	next := *h.Cfg
	mutate(&next)
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Cfg = &next
	h.serve(t)
}

type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// Duo returns a real duo_api_golang client, as Authelia uses, pointed at the harness.
func (h *Harness) Duo(ikey, skey string) *authapi.AuthApi {
	return authapi.NewAuthApi(*duoapigo.NewDuoApi(ikey, skey, h.Host, "test", duoapigo.SetInsecure()))
}

// DuoClient returns the raw client, for JSONSignedCall.
func (h *Harness) DuoClient() *duoapigo.DuoApi {
	return duoapigo.NewDuoApi(IKey, SKey, h.Host, "test", duoapigo.SetInsecure())
}

type Request struct {
	Method, Path string
	Body         []byte
	Header       map[string]string
	// User, when set, is signed in: the request carries the identity header the proxy adds after
	// its forward-auth step.
	User string
}

// Do sends a browser-style request: Origin is the public origin unless overridden.
func (h *Harness) Do(t *testing.T, r Request) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(r.Method, h.Server.URL+r.Path, bytes.NewReader(r.Body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", PublicURL)
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.User != "" {
		req.Header.Set(h.Cfg.IdentityHeader, r.User)
	}
	for k, v := range r.Header {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// LocalPath turns an absolute public URL into a path on the harness.
func LocalPath(t *testing.T, u string) string {
	t.Helper()
	if !strings.HasPrefix(u, PublicURL) {
		t.Fatalf("%q is not under %s", u, PublicURL)
	}
	return strings.TrimPrefix(u, PublicURL)
}

type Enrolled struct {
	DeviceID, Topic, NtfyLink string
	HasCode                   bool
	// ResultToken authorizes the enrollment result page's resend and manual sign-in actions.
	ResultToken string
	Auth        *Authenticator
}

// enrollBase picks the route family: /token with an enrollment code, /enroll with the proxy's
// identity.
func enrollBase(code string) string {
	if code != "" {
		return "/token"
	}
	return "/enroll"
}

// BeginEnroll runs /enroll/begin or /token/begin and returns the registration token and creation
// options.
func (h *Harness) BeginEnroll(t *testing.T, user, code, name string) (string, json.RawMessage, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name, "code": code})
	req := Request{Method: "POST", Path: enrollBase(code) + "/begin", Body: body}
	if code == "" {
		req.User = user
	}
	resp, b := h.Do(t, req)
	var out struct {
		Token   string          `json:"token"`
		Options json.RawMessage `json:"options"`
	}
	_ = json.Unmarshal(b, &out)
	return out.Token, out.Options, resp.StatusCode
}

// FinishEnroll simulates web enrollment passkey steps and returns the outcome, skipping device
// verification.
func (h *Harness) FinishEnroll(t *testing.T, user, code string, a *Authenticator) (Enrolled, int, []byte) {
	t.Helper()
	token, opts, status := h.BeginEnroll(t, user, code, "Pixel")
	if status != 200 {
		t.Fatalf("enroll begin: %d", status)
	}
	req := Request{Method: "POST", Path: enrollBase(code) + "/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts)}
	if code == "" {
		req.User = user
	}
	resp, b := h.Do(t, req)
	var out struct {
		Device      string `json:"device"`
		Topic       string `json:"topic"`
		NtfyLink    string `json:"ntfy_link"`
		HasCode     bool   `json:"has_code"`
		ResultToken string `json:"result_token"`
	}
	_ = json.Unmarshal(b, &out)
	return Enrolled{DeviceID: out.Device, Topic: out.Topic, NtfyLink: out.NtfyLink, HasCode: out.HasCode,
		ResultToken: out.ResultToken, Auth: a}, resp.StatusCode, b
}

// Enroll enrolls and verifies a phone for user through the web flow with a passkey from a.
func (h *Harness) Enroll(t *testing.T, user string, a *Authenticator) Enrolled {
	t.Helper()
	e, status, b := h.FinishEnroll(t, user, "", a)
	if status != 200 {
		t.Fatalf("enroll finish: %d %s", status, b)
	}
	h.VerifyFromPush(t, h.Ntfy.NextPublish(t))
	return e
}

// VerifyFromPush simulates a user tapping the setup push and clicking Activate.
func (h *Harness) VerifyFromPush(t *testing.T, m ntfy.Message) {
	t.Helper()
	if m.Title != "Finish setup" {
		t.Fatalf("expected the setup push, got %q", m.Title)
	}
	resp, b := h.SubmitForm(t, LocalPath(t, m.Click), "", "/token/verify/", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("verify: %d %s", resp.StatusCode, b)
	}
}

var (
	formRe     = regexp.MustCompile(`(?s)<form method="post" action="([^"]+)"[^>]*>(.*?)</form>`)
	hiddenRe   = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
	referrerRe = regexp.MustCompile(`<meta name="referrer" content="([^"]+)">`)
)

// SubmitForm simulates browser form submission, including hidden inputs, extra data, and Fetch
// standard Origin headers.
func (h *Harness) SubmitForm(t *testing.T, page, user, match string, extra url.Values) (*http.Response, []byte) {
	t.Helper()
	resp, body := h.Do(t, Request{Method: "GET", Path: page, User: user})
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", page, resp.StatusCode)
	}
	policy := resp.Header.Get("Referrer-Policy")
	if m := referrerRe.FindSubmatch(body); m != nil {
		policy = string(m[1])
	}
	origin := PublicURL
	if policy == "no-referrer" {
		origin = "null"
	}
	for _, f := range formRe.FindAllSubmatch(body, -1) {
		action := html.UnescapeString(string(f[1]))
		if !strings.Contains(action, match) {
			continue
		}
		form := url.Values{}
		for _, in := range hiddenRe.FindAllSubmatch(f[2], -1) {
			form.Set(html.UnescapeString(string(in[1])), html.UnescapeString(string(in[2])))
		}
		for k, v := range extra {
			form[k] = v
		}
		return h.Do(t, Request{Method: "POST", Path: action, Body: []byte(form.Encode()), User: user,
			Header: map[string]string{"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}})
	}
	t.Fatalf("no form posting to %q on %s", match, page)
	return nil, nil
}
