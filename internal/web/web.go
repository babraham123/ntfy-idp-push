// Package web serves the enrollment, approval, provisioning and device pages.
package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/time/rate"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/routes"
)

//go:embed templates/*.html static/*
var assets embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"join": strings.Join,
}).ParseFS(assets, "templates/*.html"))

const maxBody = 64 << 10

// Server serves two kinds of routes. Identity routes (/enroll, /provision, /devices) know the user
// only from the identity header a trusted proxy sets after its forward-auth step. Token routes
// (/token/*, /challenge/*) never read it: an enrollment code, result token, verify token, deny token
// or passkey is their whole credential, so the proxy can let them through unauthenticated.
type Server struct {
	svc *core.Service
	log *slog.Logger

	mu       sync.Mutex
	limiters map[string]*limiterEntry
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

func New(svc *core.Service, log *slog.Logger) *Server {
	return &Server{svc: svc, log: log, limiters: map[string]*limiterEntry{}}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.Handle("GET "+routes.Static, http.FileServerFS(assets))
	mux.HandleFunc("GET "+routes.Health, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	enroll, tok, ch := routes.Enroll, routes.Token, routes.Challenge
	mux.Handle("GET "+enroll, s.limit(s.enrollPage))
	mux.Handle("POST "+enroll+"/begin", s.limit(s.sameOrigin(s.enrollBegin)))
	mux.Handle("POST "+enroll+"/finish", s.limit(s.sameOrigin(s.enrollFinish)))

	mux.Handle("GET "+tok+"/{code}", s.limit(s.tokenPage))
	mux.Handle("POST "+tok+"/begin", s.limit(s.sameOrigin(s.tokenBegin)))
	mux.Handle("POST "+tok+"/finish", s.limit(s.sameOrigin(s.tokenFinish)))
	mux.Handle("GET "+tok+"/verify/{device}", s.limit(s.verifyPage))
	mux.Handle("POST "+tok+"/verify/{device}", s.limit(s.sameOrigin(s.verifyDevice)))
	mux.Handle("POST "+tok+"/resend", s.limit(s.sameOrigin(s.enrollResend)))
	mux.Handle("POST "+tok+"/password", s.limit(s.sameOrigin(s.enrollPassword)))
	mux.HandleFunc("GET "+tok+"/qr", s.enrollQR)

	mux.Handle("GET "+ch+"/{id}", s.limit(s.approvePage))
	mux.Handle("GET "+ch+"/{id}/options", s.limit(s.assertionOptions))
	mux.Handle("POST "+ch+"/{id}/assert", s.limit(s.sameOrigin(s.assert)))
	// Called by the ntfy app's http action, which sends no Origin; the deny token authorizes it.
	mux.Handle("POST "+ch+"/{id}/deny", s.limit(s.deny))
	mux.Handle("POST "+ch+"/{id}/fraud", s.limit(s.sameOrigin(s.fraud)))

	mux.HandleFunc("GET "+routes.Provision, s.provisionPage)
	mux.Handle("POST "+routes.Provision+"/password", s.sameOrigin(s.provisionPassword))
	mux.HandleFunc("GET "+routes.Devices, s.devicesPage)
	mux.Handle("POST "+routes.Devices+"/{id}/revoke", s.sameOrigin(s.revoke))
}

// SecurityHeaders sets the headers every response carries, Duo API and static files included.
// HSTS is sent on plain HTTP too: browsers ignore it there, and behind a TLS proxy it reaches them
// over HTTPS. It leaves out includeSubDomains, as the shim does not own the rest of the domain.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// ---- responses

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("render", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Pages carry ntfy sign-in codes and passwords, and per-user content.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
	// Not no-referrer: with it, browsers send "Origin: null" on form posts and sameOrigin refuses them.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) message(w http.ResponseWriter, status int, title, text string) {
	s.render(w, status, "message.html", map[string]string{"Title": title, "Text": text})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// status maps a core failure kind to the HTTP status every handler answers with.
func status(k core.Kind) int {
	switch k {
	case core.Refused:
		return http.StatusForbidden
	case core.Gone:
		return http.StatusGone
	case core.NotFound:
		return http.StatusNotFound
	case core.Invalid:
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// failure is what the client learns about err: core's own reason for a classified failure, and
// nothing but the status for an internal one, which is logged instead.
func (s *Server) failure(err error, what string) (int, string) {
	k := core.KindOf(err)
	if k == core.Internal {
		s.log.Error(what, "err", err)
		return http.StatusInternalServerError, "internal error"
	}
	return status(k), err.Error()
}

// jsonFail answers a fetch() call with err.
func (s *Server) jsonFail(w http.ResponseWriter, err error, what string) {
	st, msg := s.failure(err, what)
	writeJSON(w, st, map[string]string{"error": msg})
}

// pageFail answers a page request with err.
func (s *Server) pageFail(w http.ResponseWriter, err error, what string) {
	st, msg := s.failure(err, what)
	title := "Error"
	switch status := st; status {
	case http.StatusGone:
		title = "Link expired"
	case http.StatusForbidden:
		title = "Not allowed"
	case http.StatusNotFound:
		title = "Not found"
	case http.StatusBadRequest:
		title = "Bad request"
	}
	s.message(w, st, title, strings.ToUpper(msg[:1])+msg[1:]+".")
}

// readJSON decodes a fetch() body into v, answering 400 itself when it cannot.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return false
	}
	return true
}

// ---- request identity

// sameOrigin refuses cross-site state changes from browsers.
func (s *Server) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != s.svc.Config().PublicOrigin {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// signedIn returns the user named by the identity header when a trusted proxy sent it, or "" and
// false after answering 401. The proxy's forward-auth step signs users in before requests reach
// the shim, so a request without identity means the proxy is misconfigured, not that the browser
// should be sent anywhere.
func (s *Server) signedIn(w http.ResponseWriter, r *http.Request) (string, bool) {
	cfg := s.svc.Config()
	if trusted(cfg.TrustedNets, remoteIP(r)) {
		if u := strings.TrimSpace(r.Header.Get(cfg.IdentityHeader)); u != "" {
			return u, true
		}
	}
	http.Error(w, "sign in required: no "+cfg.IdentityHeader+" from a trusted proxy", http.StatusUnauthorized)
	return "", false
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func trusted(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP is the peer address, or X-Forwarded-For's last hop when the peer is a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	ip := remoteIP(r)
	if trusted(s.svc.Config().TrustedNets, ip) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if p := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); p != nil {
				return p.String()
			}
		}
	}
	return ip.String()
}

// limit allows a burst of 20 requests and 1/s sustained per client IP on unauthenticated pages.
func (s *Server) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		now := time.Now()
		s.mu.Lock()
		e := s.limiters[ip]
		if e == nil {
			e = &limiterEntry{l: rate.NewLimiter(1, 20)}
			s.limiters[ip] = e
		}
		e.seen = now
		if len(s.limiters) > 10000 {
			for k, v := range s.limiters {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(s.limiters, k)
				}
			}
		}
		ok := e.l.AllowN(now, 1)
		s.mu.Unlock()
		if !ok {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func qrDataURL(content string) (template.URL, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)), nil
}

// ---- enrollment

// enrollPage is the identity route: the proxy signed the user in.
func (s *Server) enrollPage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "enroll.html", map[string]string{"User": user, "Base": routes.Enroll})
}

// tokenPage is the token route: a shim-issued enrollment code is the whole credential.
func (s *Server) tokenPage(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	user, err := s.svc.ResolveEnrollCode(r.Context(), code)
	if err != nil {
		s.pageFail(w, err, "enroll: code")
		return
	}
	s.render(w, http.StatusOK, "enroll.html", map[string]string{"User": user, "Code": code, "Base": routes.Token})
}

func (s *Server) enrollBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	var in struct{ Name string }
	if !readJSON(w, r, &in) {
		return
	}
	s.beginEnrollment(w, r, core.EnrollRequest{Username: user, DeviceName: in.Name})
}

func (s *Server) tokenBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Code string }
	if !readJSON(w, r, &in) {
		return
	}
	if in.Code == "" {
		s.jsonFail(w, core.ErrInvalidCode, "")
		return
	}
	s.beginEnrollment(w, r, core.EnrollRequest{Code: in.Code, DeviceName: in.Name})
}

func (s *Server) beginEnrollment(w http.ResponseWriter, r *http.Request, req core.EnrollRequest) {
	handle, opts, err := s.svc.BeginEnrollment(r.Context(), req)
	if err != nil {
		s.jsonFail(w, err, "enroll: begin")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": handle, "options": opts})
}

func (s *Server) enrollFinish(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	s.finishEnrollment(w, r, user)
}

func (s *Server) tokenFinish(w http.ResponseWriter, r *http.Request) {
	s.finishEnrollment(w, r, "")
}

// finishEnrollment completes a ceremony begun on the same kind of route: core refuses one begun
// with identity when none is presented now.
func (s *Server) finishEnrollment(w http.ResponseWriter, r *http.Request, signedIn string) {
	handle := r.URL.Query().Get("token")
	res, err := s.svc.FinishEnrollment(r.Context(), handle, signedIn, io.LimitReader(r.Body, maxBody))
	if err != nil {
		s.log.Warn("enroll: finish", "err", err)
		s.jsonFail(w, err, "enroll: finish")
		return
	}
	link := res.Handoff.Links[0].URL
	qr, err := qrDataURL(link)
	if err != nil {
		s.jsonFail(w, err, "enroll: qr")
		return
	}
	var codeExpires int64
	if res.Handoff.HasCode() {
		codeExpires = res.Handoff.CodeExpires.Unix()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device":       res.Device.ID,
		"topic":        res.Device.NtfyTopic,
		"username":     res.Device.Username,
		"ntfy_link":    link,
		"has_code":     res.Handoff.HasCode(),
		"code_expires": codeExpires,
		"qr":           qr,
		"result_token": res.ResultToken,
	})
}

// enrolledFrom resolves the result token posted by the enrollment result page to the device's
// ID and owner.
func (s *Server) enrolledFrom(w http.ResponseWriter, r *http.Request) (deviceID, username string, ok bool) {
	var in struct{ Token string }
	if !readJSON(w, r, &in) {
		return "", "", false
	}
	d, err := s.svc.EnrolledDevice(r.Context(), in.Token)
	if err != nil {
		s.jsonFail(w, err, "enroll: result token")
		return "", "", false
	}
	return d.ID, d.Username, true
}

func (s *Server) enrollResend(w http.ResponseWriter, r *http.Request) {
	id, user, ok := s.enrolledFrom(w, r)
	if !ok {
		return
	}
	if err := s.svc.ResendSetupPush(r.Context(), id, user); err != nil {
		s.jsonFail(w, err, "enroll: resend")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "sent"})
}

func (s *Server) enrollPassword(w http.ResponseWriter, r *http.Request) {
	_, user, ok := s.enrolledFrom(w, r)
	if !ok {
		return
	}
	password, err := s.svc.SetNtfyPassword(r.Context(), user)
	if err != nil {
		s.jsonFail(w, err, "enroll: ntfy password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": user, "password": password})
}

func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request) {
	// A GET only renders a form: link previews and prefetchers must not verify the device.
	s.render(w, http.StatusOK, "verify.html", map[string]string{"Device": r.PathValue("device"), "Token": r.URL.Query().Get("t")})
}

func (s *Server) verifyDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.VerifyDevice(r.Context(), r.PathValue("device"), r.FormValue("t")); err != nil {
		s.pageFail(w, err, "enroll: verify")
		return
	}
	s.message(w, http.StatusOK, "Phone ready", "This phone will now receive sign-in requests. You can close this page.")
}

// ---- approval

func (s *Server) approvePage(w http.ResponseWriter, r *http.Request) {
	c, err := s.svc.PendingChallenge(r.Context(), r.PathValue("id"))
	if err != nil {
		s.pageFail(w, err, "approve: page")
		return
	}
	s.render(w, http.StatusOK, "approve.html", map[string]any{
		"ID": c.ID, "Summary": core.Describe(c), "User": c.DisplayUsername, "IP": c.IPAddr, "Target": c.TargetURL,
		"Expires": c.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) assertionOptions(w http.ResponseWriter, r *http.Request) {
	opts, err := s.svc.AssertionOptions(r.Context(), r.PathValue("id"))
	if err != nil {
		s.jsonFail(w, err, "approve: options")
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) assert(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Approve(r.Context(), r.PathValue("id"), io.LimitReader(r.Body, maxBody)); err != nil {
		s.log.Warn("approve", "challenge", r.PathValue("id"), "err", err)
		s.jsonFail(w, err, "approve")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "allow"})
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	denyToken, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err := s.svc.Deny(r.Context(), r.PathValue("id"), strings.TrimSpace(string(denyToken))); err != nil {
		st, msg := s.failure(err, "deny")
		http.Error(w, msg, st)
		return
	}
	io.WriteString(w, "denied\n")
}

// fraud lets push holders report it. This endpoint can only deny logins, never approve them.
func (s *Server) fraud(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.ReportFraud(r.Context(), r.PathValue("id"), s.clientIP(r)); err != nil {
		s.jsonFail(w, err, "fraud")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "fraud"})
}

// ---- QR for IdP-driven enrollment

// enrollQR renders QR codes only for shim-issued enrollment codes (preventing general-purpose QR
// abuse).
func (s *Server) enrollQR(w http.ResponseWriter, r *http.Request) {
	code := routes.EnrollCode(s.svc.Config().PublicURL, r.URL.Query().Get("value"))
	if code == "" {
		http.NotFound(w, r)
		return
	}
	if _, err := s.svc.ResolveEnrollCode(r.Context(), code); err != nil {
		st, msg := s.failure(err, "enroll: qr")
		http.Error(w, msg, st)
		return
	}
	png, err := qrcode.Encode(s.svc.EnrollURL(code), qrcode.Medium, 320)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}
