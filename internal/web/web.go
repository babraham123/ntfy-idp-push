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
	"strings"
	"sync"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/skip2/go-qrcode"
	"golang.org/x/time/rate"

	"github.com/babraham123/ntfy-idp-push/internal/challenge"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/webauthn"
)

//go:embed templates/*.html static/*
var assets embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"join": strings.Join,
}).ParseFS(assets, "templates/*.html"))

const maxBody = 64 << 10

type Server struct {
	svc      *core.Service
	identity Identity
	log      *slog.Logger

	mu       sync.Mutex
	regs     map[string]*registration
	limiters map[string]*limiterEntry
}

// registration is a passkey ceremony in progress between /enroll/begin and /enroll/finish.
type registration struct {
	username, name, code string
	session              gowebauthn.SessionData
	expires              time.Time
}

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

func New(svc *core.Service, identity Identity, log *slog.Logger) *Server {
	return &Server{svc: svc, identity: identity, log: log, regs: map[string]*registration{}, limiters: map[string]*limiterEntry{}}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	mux.Handle("GET /enroll", s.limit(s.enrollPage))
	mux.Handle("POST /enroll/begin", s.limit(s.sameOrigin(s.enrollBegin)))
	mux.Handle("POST /enroll/finish", s.limit(s.sameOrigin(s.enrollFinish)))
	mux.Handle("GET /enroll/verify/{device}", s.limit(s.verifyPage))
	mux.Handle("POST /enroll/verify/{device}", s.limit(s.sameOrigin(s.verifyDevice)))
	mux.Handle("POST /enroll/resend", s.limit(s.sameOrigin(s.enrollResend)))
	mux.Handle("POST /enroll/password", s.limit(s.sameOrigin(s.enrollPassword)))
	mux.HandleFunc("GET /enroll/qr", s.enrollQR)

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

// ---- helpers

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("render", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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

// enrollUser resolves the enrolling user from an enrollment code or from the identity provider.
func (s *Server) enrollUser(w http.ResponseWriter, r *http.Request, code string) (string, bool) {
	if code != "" {
		ec, err := s.svc.ResolveEnrollCode(r.Context(), code)
		if err != nil {
			s.message(w, http.StatusGone, "Link expired", "This enrollment link is invalid or has expired. Ask for a new one.")
			return "", false
		}
		return ec.Username, true
	}
	return s.identity.User(w, r)
}

func (s *Server) enrollPage(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	user, ok := s.enrollUser(w, r, code)
	if !ok {
		return
	}
	s.render(w, http.StatusOK, "enroll.html", map[string]string{"User": user, "Code": code})
}

func (s *Server) enrollBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Code string }
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	user, ok := s.enrollUser(w, r, in.Code)
	if !ok {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) > 64 {
		in.Name = in.Name[:64]
	}
	opts, session, err := s.svc.BeginEnrollment(r.Context(), user, in.Name)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	token := challenge.RandomToken(24)
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.regs {
		if now.After(v.expires) {
			delete(s.regs, k)
		}
	}
	s.regs[token] = &registration{username: user, name: in.Name, code: in.Code, session: *session, expires: now.Add(5 * time.Minute)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "options": opts})
}

func (s *Server) enrollFinish(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	s.mu.Lock()
	reg := s.regs[token]
	delete(s.regs, token)
	s.mu.Unlock()
	if reg == nil || time.Now().After(reg.expires) {
		jsonError(w, http.StatusBadRequest, "registration expired; start again")
		return
	}
	// Without a code the identity must still be the one that began the ceremony.
	if reg.code == "" {
		user, ok := s.identity.User(w, r)
		if !ok {
			return
		}
		if user != reg.username {
			jsonError(w, http.StatusForbidden, "identity changed during enrollment")
			return
		}
	}
	res, err := s.svc.CompleteEnrollment(r.Context(), reg.username, reg.name, reg.session, io.LimitReader(r.Body, maxBody), reg.code)
	if err != nil {
		s.log.Warn("enroll", "user", reg.username, "err", err)
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
		"username":     reg.username,
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
	if errors.Is(err, challenge.ErrGone) {
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
	if errors.Is(err, challenge.ErrGone) {
		jsonError(w, http.StatusGone, err.Error())
		return
	} else if errors.Is(err, webauthn.ErrNoUsableCredential) {
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
	case errors.Is(err, challenge.ErrGone):
		jsonError(w, http.StatusGone, err.Error())
	case errors.Is(err, core.ErrUserDisabled), errors.Is(err, core.ErrPushDisabled), errors.Is(err, core.ErrDeviceRevoked),
		errors.Is(err, webauthn.ErrSynced), errors.Is(err, webauthn.ErrNoUsableCredential):
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
	token, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
	err := s.svc.Challenges.Deny(r.Context(), r.PathValue("id"), strings.TrimSpace(string(token)))
	switch {
	case errors.Is(err, challenge.ErrGone):
		http.Error(w, "gone", http.StatusGone)
	case errors.Is(err, challenge.ErrBadToken):
		http.Error(w, "forbidden", http.StatusForbidden)
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		io.WriteString(w, "denied\n")
	}
}

// fraud lets whoever holds the push report it. Anyone able to reach this can only deny a login,
// never approve one.
func (s *Server) fraud(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := s.svc.PendingChallenge(r.Context(), id)
	if err == nil {
		err = s.svc.Challenges.Decide(r.Context(), id, store.StateFraud)
	}
	if err != nil {
		jsonError(w, http.StatusGone, "request already closed")
		return
	}
	s.svc.Store.Audit(r.Context(), c.Username, "fraud_reported", map[string]any{"challenge": id, "ip": s.clientIP(r)})
	writeJSON(w, http.StatusOK, map[string]string{"result": "fraud"})
}

// ---- QR for IdP-driven enrollment

// enrollQR renders the enrollment URL only for codes the shim issued, so it cannot be used as a
// general-purpose QR generator.
func (s *Server) enrollQR(w http.ResponseWriter, r *http.Request) {
	value := r.URL.Query().Get("value")
	prefix := s.svc.Config().PublicURL + "/enroll?code="
	code := ""
	if strings.HasPrefix(value, prefix) {
		code = value[len(prefix):]
	}
	if code == "" {
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
