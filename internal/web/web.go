// Package web serves the enrollment, approval, provisioning and device pages.
package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/time/rate"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/store"
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
	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	mux.Handle("GET /enroll", s.limit(s.enrollPage))
	mux.Handle("POST /enroll/begin", s.limit(s.sameOrigin(s.enrollBegin)))
	mux.Handle("POST /enroll/finish", s.limit(s.sameOrigin(s.enrollFinish)))

	mux.Handle("GET /token/{code}", s.limit(s.tokenPage))
	mux.Handle("POST /token/begin", s.limit(s.sameOrigin(s.tokenBegin)))
	mux.Handle("POST /token/finish", s.limit(s.sameOrigin(s.tokenFinish)))
	mux.Handle("GET /token/verify/{device}", s.limit(s.verifyPage))
	mux.Handle("POST /token/verify/{device}", s.limit(s.sameOrigin(s.verifyDevice)))
	mux.Handle("POST /token/resend", s.limit(s.sameOrigin(s.enrollResend)))
	mux.Handle("POST /token/password", s.limit(s.sameOrigin(s.enrollPassword)))
	mux.HandleFunc("GET /token/qr", s.enrollQR)

	mux.Handle("GET /challenge/{id}", s.limit(s.approvePage))
	mux.Handle("GET /challenge/{id}/options", s.limit(s.assertionOptions))
	mux.Handle("POST /challenge/{id}/assert", s.limit(s.sameOrigin(s.assert)))
	// Called by the ntfy app's http action, which sends no Origin; the deny token authorizes it.
	mux.Handle("POST /challenge/{id}/deny", s.limit(s.deny))
	mux.Handle("POST /challenge/{id}/fraud", s.limit(s.sameOrigin(s.fraud)))

	mux.HandleFunc("GET /provision", s.provisionPage)
	mux.Handle("POST /provision/password", s.sameOrigin(s.provisionPassword))
	mux.HandleFunc("GET /devices", s.devicesPage)
	mux.Handle("POST /devices/{id}/revoke", s.sameOrigin(s.revoke))
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

// ---- helpers

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

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

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

// enrollPage is the identity route: the proxy signed the user in. Links from before the route
// split carried the code as ?code=; they are forwarded to /token/{code} for one release.
func (s *Server) enrollPage(w http.ResponseWriter, r *http.Request) {
	if code := r.URL.Query().Get("code"); code != "" {
		http.Redirect(w, r, "/token/"+url.PathEscape(code), http.StatusFound)
		return
	}
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "enroll.html", map[string]string{"User": user, "Base": "/enroll"})
}

// tokenPage is the token route: a shim-issued enrollment code is the whole credential.
func (s *Server) tokenPage(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	user, err := s.svc.ResolveEnrollCode(r.Context(), code)
	if err != nil {
		s.message(w, http.StatusGone, "Link expired", "This enrollment link is invalid or has expired. Ask for a new one.")
		return
	}
	s.render(w, http.StatusOK, "enroll.html", map[string]string{"User": user, "Code": code, "Base": "/token"})
}

func (s *Server) enrollBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	var in struct{ Name string }
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	s.beginEnrollment(w, r, core.EnrollRequest{Username: user, DeviceName: in.Name})
}

func (s *Server) tokenBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Code string }
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	if in.Code == "" {
		s.codeExpired(w)
		return
	}
	s.beginEnrollment(w, r, core.EnrollRequest{Code: in.Code, DeviceName: in.Name})
}

func (s *Server) codeExpired(w http.ResponseWriter) {
	jsonError(w, http.StatusGone, "This enrollment link is invalid or has expired. Ask for a new one.")
}

func (s *Server) beginEnrollment(w http.ResponseWriter, r *http.Request, req core.EnrollRequest) {
	handle, opts, err := s.svc.BeginEnrollment(r.Context(), req)
	if errors.Is(err, core.ErrInvalidCode) {
		s.codeExpired(w)
		return
	} else if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
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
	switch {
	case errors.Is(err, core.ErrIdentityChanged):
		jsonError(w, http.StatusForbidden, err.Error())
		return
	case err != nil:
		s.log.Warn("enroll", "err", err)
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	var codeExpires int64
	if res.Code != nil {
		codeExpires = res.Code.Expires
	}
	qr, err := qrDataURL(res.NtfyLink)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device":       res.Device.ID,
		"topic":        res.Device.NtfyTopic,
		"username":     res.Device.Username,
		"ntfy_link":    res.NtfyLink,
		"has_code":     res.Code != nil,
		"code_expires": codeExpires,
		"qr":           qr,
		"result_token": res.ResultToken,
	})
}

// enrolledFrom resolves the result token posted by the enrollment result page.
func (s *Server) enrolledFrom(w http.ResponseWriter, r *http.Request) (*store.Device, bool) {
	var in struct{ Token string }
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return nil, false
	}
	d, err := s.svc.EnrolledDevice(r.Context(), in.Token)
	if errors.Is(err, core.ErrInvalidCode) {
		jsonError(w, http.StatusGone, "this page has expired; enroll again")
		return nil, false
	} else if err != nil {
		s.log.Error("enroll: result token", "err", err)
		jsonError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return d, true
}

func (s *Server) enrollResend(w http.ResponseWriter, r *http.Request) {
	d, ok := s.enrolledFrom(w, r)
	if !ok {
		return
	}
	if err := s.svc.ResendSetupPush(r.Context(), d.ID, d.Username); errors.Is(err, core.ErrInvalidCode) {
		jsonError(w, http.StatusGone, "this phone is already set up or was removed")
		return
	} else if err != nil {
		s.log.Error("enroll: resend", "device", d.ID, "err", err)
		jsonError(w, http.StatusBadGateway, "could not send the setup notification")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "sent"})
}

func (s *Server) enrollPassword(w http.ResponseWriter, r *http.Request) {
	d, ok := s.enrolledFrom(w, r)
	if !ok {
		return
	}
	password, err := s.svc.SetNtfyPassword(r.Context(), d.Username)
	if err != nil {
		s.log.Error("enroll: ntfy password", "user", d.Username, "err", err)
		jsonError(w, http.StatusBadGateway, "could not set an ntfy password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": d.Username, "password": password})
}

func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request) {
	// A GET only renders a form: link previews and prefetchers must not verify the device.
	s.render(w, http.StatusOK, "verify.html", map[string]string{"Device": r.PathValue("device"), "Token": r.URL.Query().Get("t")})
}

func (s *Server) verifyDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.VerifyDevice(r.Context(), r.PathValue("device"), r.FormValue("t")); err != nil {
		s.message(w, http.StatusGone, "Link expired", "This setup link was already used or is invalid.")
		return
	}
	s.message(w, http.StatusOK, "Phone ready", "This phone will now receive sign-in requests. You can close this page.")
}

// ---- approval

func (s *Server) approvePage(w http.ResponseWriter, r *http.Request) {
	c, err := s.svc.PendingChallenge(r.Context(), r.PathValue("id"))
	if errors.Is(err, core.ErrGone) {
		s.message(w, http.StatusGone, "Request closed", "This sign-in request was already answered or has expired.")
		return
	} else if err != nil {
		s.message(w, http.StatusInternalServerError, "Error", "Something went wrong.")
		return
	}
	s.render(w, http.StatusOK, "approve.html", map[string]any{
		"ID": c.ID, "Summary": core.Describe(c), "User": c.DisplayUsername, "IP": c.IPAddr, "Target": c.TargetURL,
		"Expires": c.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) assertionOptions(w http.ResponseWriter, r *http.Request) {
	opts, err := s.svc.AssertionOptions(r.Context(), r.PathValue("id"))
	if errors.Is(err, core.ErrGone) {
		jsonError(w, http.StatusGone, err.Error())
		return
	} else if errors.Is(err, core.ErrPasskeyPolicy) {
		jsonError(w, http.StatusForbidden, err.Error())
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) assert(w http.ResponseWriter, r *http.Request) {
	err := s.svc.Approve(r.Context(), r.PathValue("id"), io.LimitReader(r.Body, maxBody))
	switch {
	case errors.Is(err, core.ErrGone):
		jsonError(w, http.StatusGone, err.Error())
	case errors.Is(err, core.ErrUserDisabled), errors.Is(err, core.ErrPushDisabled), errors.Is(err, core.ErrDeviceRevoked),
		errors.Is(err, core.ErrPasskeyPolicy):
		s.log.Warn("approve", "challenge", r.PathValue("id"), "err", err)
		jsonError(w, http.StatusForbidden, err.Error())
	case err != nil:
		s.log.Warn("approve", "challenge", r.PathValue("id"), "err", err)
		jsonError(w, http.StatusForbidden, "passkey verification failed")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"result": "allow"})
	}
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	denyToken, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	err := s.svc.Deny(r.Context(), r.PathValue("id"), strings.TrimSpace(string(denyToken)))
	switch {
	case errors.Is(err, core.ErrGone):
		http.Error(w, "gone", http.StatusGone)
	case errors.Is(err, core.ErrBadToken):
		http.Error(w, "forbidden", http.StatusForbidden)
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		io.WriteString(w, "denied\n")
	}
}

// fraud lets push holders report it. This endpoint can only deny logins, never approve them.
func (s *Server) fraud(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.ReportFraud(r.Context(), r.PathValue("id"), s.clientIP(r)); err != nil {
		jsonError(w, http.StatusGone, "request already closed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "fraud"})
}

// ---- QR for IdP-driven enrollment

// enrollQR renders QR codes only for shim-issued enrollment codes (preventing general-purpose QR
// abuse).
func (s *Server) enrollQR(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	prefix := s.svc.Config().PublicURL + "/token/"
	code := ""
	if strings.HasPrefix(value, prefix) {
		code, _ = url.PathUnescape(value[len(prefix):])
	}
	if code == "" || strings.Contains(code, "/") {
		http.NotFound(w, r)
		return
	}
	if _, err := s.svc.ResolveEnrollCode(r.Context(), code); err != nil {
		http.NotFound(w, r)
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
