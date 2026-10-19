package testutil

import (
	"bytes"
	"context"
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

	"github.com/babraham123/ntfy-idp-push/internal/app"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

const (
	IKey      = "DIAAAAAAAAAAAAAAAAAA"
	SKey      = "secretsecretsecretsecretsecretsecretsecr"
	PublicURL = "https://push.test"
)

// Harness is the whole shim, assembled as serve assembles it, on an httptest TLS server with a
// fake ntfy behind it. The test client connects from loopback, which the config lists as the
// trusted proxy, so Request.User plays the proxy's forward-auth step.
type Harness struct {
	Cfg  *config.Config
	Svc  *core.Service
	Ntfy *FakeNtfy
	// Dir is the user directory the sync reads, wired in unless the config sets no directory-type;
	// Mail records the emails the shim sends.
	Dir    *FakeDirectory
	Mail   *FakeMail
	Server *httptest.Server
	// Host is what Duo clients put in the Host header and sign (duo-hostname).
	Host   string
	Client *http.Client
	// Store is the database other processes (the CLI, an earlier server) share with this one;
	// tests use it to leave the state such a process would, never to read what core can tell them.
	Store *store.Store
	log   *slog.Logger
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
		// Tests run Sync themselves; the interval only has to be valid. The source is Dir, unless
		// NoDirectory clears the type.
		DirectoryType:         "ldap",
		DirectorySyncInterval: config.Duration(time.Hour),
		SMTPHost:              "smtp.test",
		SMTPPort:              587,
		MailFrom:              "push@push.test",
		// The software authenticator attests "none"; the opt-in default has its own config test.
		WebAuthnRequireAttestation: false,
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
	h := &Harness{Cfg: cfg, Ntfy: fn, Dir: &FakeDirectory{}, Mail: NewFakeMail(), Server: srv, Host: host, Store: st, log: log}
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

// serve builds the shim from h.Cfg on h.Store and routes the server to it.
func (h *Harness) serve(t *testing.T) {
	t.Helper()
	a, err := app.Build(h.Cfg, h.Store, h.log, h.Source(), h.Mail)
	if err != nil {
		t.Fatal(err)
	}
	h.Server.Config.Handler = a.Handler
	h.Svc = a.Svc
}

// NoDirectory is a NewHarness mutate that runs the shim with no directory.
func NoDirectory(c *config.Config) { c.DirectoryType = "" }

// Source is the directory the shim is built with: Dir, or nil when the config sets no
// directory-type.
func (h *Harness) Source() directory.Source {
	if h.Cfg.DirectoryType == "" {
		return nil
	}
	return h.Dir
}

// Reload applies a changed config as SIGHUP would.
func (h *Harness) Reload(t *testing.T, mutate func(*config.Config)) {
	t.Helper()
	next := *h.Cfg
	mutate(&next)
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := h.Svc.Reload(&next); err != nil {
		t.Fatal(err)
	}
	h.Cfg = &next
}

// HasDevice reports whether user still has a device row for id, in any state.
func (h *Harness) HasDevice(t *testing.T, user, id string) bool {
	t.Helper()
	_, devs, err := h.Svc.DevicesOf(context.Background(), user)
	if err != nil {
		return false
	}
	for _, d := range devs {
		if d.ID == id {
			return true
		}
	}
	return false
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
	// Ctx, when set, is the request's context. Cancelling it hangs up, as a browser closing the tab
	// would; Do then returns a nil response instead of failing the test.
	Ctx context.Context
}

// Do sends a browser-style request: Origin is the public origin unless overridden.
func (h *Harness) Do(t *testing.T, r Request) (*http.Response, []byte) {
	t.Helper()
	ctx := r.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, h.Server.URL+r.Path, bytes.NewReader(r.Body))
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
	if err != nil && ctx.Err() != nil {
		return nil, nil
	}
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
	// Server is the ntfy server URL the result page shows for subscribing by hand.
	Server string
	// ResultToken authorizes the enrollment result page's resend action.
	ResultToken string
	Auth        *Authenticator
}

// Fragment splits an issued link as a browser does: the local path it requests, and the raw
// fragment (location.hash without "#") it keeps to itself for the page's script.
func Fragment(t *testing.T, link string) (path, fragment string) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	path = LocalPath(t, link)
	path, _, _ = strings.Cut(path, "#")
	return path, u.EscapedFragment()
}

// enrollBase picks the route family: /token for an issued enrollment link, whose code it reads
// from the fragment as app.js does, or /enroll with the proxy's identity when link is "".
func enrollBase(t *testing.T, link string) (base, code string) {
	t.Helper()
	if link == "" {
		return "/enroll", ""
	}
	path, frag := Fragment(t, link)
	if path != "/token/" {
		t.Fatalf("enrollment link %q does not open /token/", link)
	}
	code, err := url.PathUnescape(frag)
	if err != nil {
		t.Fatal(err)
	}
	return "/token", code
}

// BeginEnroll runs /enroll/begin, or /token/begin with the code of the enrollment link, and returns
// the registration token and creation options.
func (h *Harness) BeginEnroll(t *testing.T, user, link, name string) (string, json.RawMessage, int) {
	t.Helper()
	base, code := enrollBase(t, link)
	body, _ := json.Marshal(map[string]string{"name": name, "code": code})
	req := Request{Method: "POST", Path: base + "/begin", Body: body}
	if link == "" {
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
func (h *Harness) FinishEnroll(t *testing.T, user, link string, a *Authenticator) (Enrolled, int, []byte) {
	t.Helper()
	token, opts, status := h.BeginEnroll(t, user, link, "Pixel")
	if status != 200 {
		t.Fatalf("enroll begin: %d", status)
	}
	base, _ := enrollBase(t, link)
	req := Request{Method: "POST", Path: base + "/finish?token=" + url.QueryEscape(token), Body: a.Create(t, opts)}
	if link == "" {
		req.User = user
	}
	resp, b := h.Do(t, req)
	var out struct {
		Device      string `json:"device"`
		Topic       string `json:"topic"`
		NtfyLink    string `json:"ntfy_link"`
		Server      string `json:"server"`
		ResultToken string `json:"result_token"`
	}
	_ = json.Unmarshal(b, &out)
	return Enrolled{DeviceID: out.Device, Topic: out.Topic, NtfyLink: out.NtfyLink, Server: out.Server,
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
	resp, b := h.SubmitVerify(t, m)
	if resp.StatusCode != 200 {
		t.Fatalf("verify: %d %s", resp.StatusCode, b)
	}
}

// SubmitVerify opens the setup push's link and clicks Activate, with the token app.js copies from
// the fragment into the form.
func (h *Harness) SubmitVerify(t *testing.T, m ntfy.Message) (*http.Response, []byte) {
	t.Helper()
	if m.Title != ntfy.SetupTitle {
		t.Fatalf("expected the setup push, got %q", m.Title)
	}
	path, frag := Fragment(t, m.Click)
	q, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatal(err)
	}
	return h.SubmitForm(t, path, "", "/token/verify/", url.Values{"t": {q.Get("t")}})
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
