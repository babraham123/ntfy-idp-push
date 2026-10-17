// Package duoapi serves the subset of the Duo Auth API v2 that IdPs call: ping, check, preauth,
// auth, enroll and enroll_status.
package duoapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/routes"
)

const maxBody = 64 << 10

type Handler struct {
	svc       *core.Service
	log       *slog.Logger
	replay    *replayCache
	rejectLog *rate.Limiter
	now       func() time.Time
}

func New(svc *core.Service, log *slog.Logger) *Handler {
	return &Handler{svc: svc, log: log, replay: newReplayCache(), rejectLog: rate.NewLimiter(1, 20), now: time.Now}
}

// Register mounts the Duo API routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/v2/ping", h.ping)
	// Signatures have 1s resolution. Identical idempotent calls legitimately repeat signatures;
	// side-effecting calls refuse replays.
	mux.Handle("GET /auth/v2/check", h.signed(h.check, false))
	mux.Handle("POST /auth/v2/preauth", h.signed(h.preauth, false))
	mux.Handle("POST /auth/v2/auth", h.signed(h.auth, true))
	mux.Handle("POST /auth/v2/enroll", h.signed(h.enroll, true))
	mux.Handle("POST /auth/v2/enroll_status", h.signed(h.enrollStatus, false))
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
		writeFail(w, http.StatusNotFound, 40401, "Resource not found", "")
	})
}

type params url.Values

func (p params) get(k string) string { return url.Values(p).Get(k) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOK(w http.ResponseWriter, resp any) {
	writeJSON(w, http.StatusOK, map[string]any{"stat": "OK", "response": resp})
}

func writeFail(w http.ResponseWriter, status, code int, msg, detail string) {
	body := map[string]any{"stat": "FAIL", "code": code, "message": msg}
	if detail != "" {
		body["message_detail"] = detail
	}
	writeJSON(w, status, body)
}

func (h *Handler) signed(next func(http.ResponseWriter, *http.Request, params), noReplay bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := h.authenticate(r, noReplay)
		if err != nil {
			// Sampled: this route is reachable unauthenticated, and a flood of rejections must not
			// become a flood of log lines. The reason stays here; the client gets only the code.
			if h.rejectLog.Allow() {
				h.log.Warn("duo api: rejected", "path", r.URL.Path, "remote", r.RemoteAddr, "err", err)
			}
			code := 40101
			switch {
			case errors.Is(err, errBadIKey):
				code = 40102
			case errors.Is(err, errBadSignature):
				code = 40103
			case errors.Is(err, errSkew):
				code = 40105
			}
			writeFail(w, http.StatusUnauthorized, code, "Invalid request credentials", "")
			return
		}
		next(w, r, p)
	})
}

// authenticate checks Host, date skew, integration key, signature and (if noReplay) replay, in
// that order.
func (h *Handler) authenticate(r *http.Request, noReplay bool) (params, error) {
	cfg := h.svc.Config()
	// The client signs its configured hostname; a rewritten Host would also break the signature.
	if strings.ToLower(r.Host) != cfg.DuoHostname {
		return nil, fmt.Errorf("%w: host %q", errBadSignature, r.Host)
	}
	date := r.Header.Get("Date")
	if d := r.Header.Get("X-Duo-Date"); d != "" {
		date = d
	}
	t, err := parseDate(date)
	if err != nil {
		return nil, err
	}
	now := h.now()
	if skew := now.Sub(t); skew > cfg.DuoMaxSkew.D() || -skew > cfg.DuoMaxSkew.D() {
		return nil, fmt.Errorf("%w: %s", errSkew, now.Sub(t).Round(time.Second))
	}
	ikey, sig, err := parseAuthorization(r)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(ikey), []byte(cfg.DuoIntegrationKey)) != 1 {
		return nil, errBadIKey
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return nil, err
	}
	values, err := Verify(SignedRequest{
		Method: r.Method, Host: cfg.DuoHostname, Path: r.URL.Path, Query: r.URL.Query(),
		Header: r.Header, Body: body, Date: date, Sig: sig,
	}, cfg.SecretKeys(now))
	if err != nil {
		return nil, err
	}
	if noReplay {
		if err := h.replay.check(date, sig, now, cfg.DuoMaxSkew.D()); err != nil {
			return nil, err
		}
	}
	return params(values), nil
}

func (h *Handler) ping(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"time": h.now().Unix()})
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request, _ params) {
	writeOK(w, map[string]any{"time": h.now().Unix()})
}

// deny is the Duo response for a login that was refused before or instead of a push, worded for
// the IdP's login screen from the core failure behind it.
func deny(err error) map[string]any {
	msg := "Login request denied."
	switch {
	case errors.Is(err, core.ErrPushDisabled):
		msg = "Push authentication is disabled"
	case errors.Is(err, core.ErrUserDisabled):
		msg = "user disabled"
	case errors.Is(err, core.ErrUnknownUser):
		msg = "Unknown user"
	case errors.Is(err, core.ErrUnknownDevice), errors.Is(err, core.ErrNotOwner):
		msg = "Unknown device"
	case errors.Is(err, core.ErrEnrollmentRequired):
		msg = "Enrollment required"
	case errors.Is(err, core.ErrTooManyPushes):
		msg = "Too many sign-in requests"
	}
	return map[string]any{"result": "deny", "status": "deny", "status_msg": msg}
}

// statusMsg is the Duo wording of a classified core failure in a FAIL response.
func statusMsg(err error) string {
	if errors.Is(err, core.ErrUserDisabled) {
		return "user disabled"
	}
	return err.Error()
}

func userRef(p params) core.UserRef {
	return core.UserRef{ID: p.get("user_id"), Username: p.get("username")}
}

type device struct {
	Device       string   `json:"device"`
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	DisplayName  string   `json:"display_name"`
	Number       string   `json:"number"`
	Capabilities []string `json:"capabilities"`
}

func (h *Handler) preauth(w http.ResponseWriter, r *http.Request, p params) {
	if p.get("username") == "" && p.get("user_id") == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "username")
		return
	}
	res, err := h.svc.Preauth(r.Context(), userRef(p))
	if err != nil {
		h.internal(w, err)
		return
	}
	switch {
	case res.Deny != nil:
		writeOK(w, deny(res.Deny))
	case res.EnrollURL != "":
		writeOK(w, map[string]any{"result": "enroll", "status_msg": "Enroll an authentication device to proceed",
			"enroll_portal_url": res.EnrollURL})
	default:
		out := make([]device, 0, len(res.Devices))
		for _, d := range res.Devices {
			out = append(out, device{Device: d.ID, Type: "phone", Name: d.Name, DisplayName: d.Name, Capabilities: []string{"push"}})
		}
		writeOK(w, map[string]any{"result": "auth", "status_msg": "Account is active", "devices": out})
	}
}

func (h *Handler) auth(w http.ResponseWriter, r *http.Request, p params) {
	if p.get("username") == "" && p.get("user_id") == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "username")
		return
	}
	if f := p.get("factor"); f != "push" && f != "auto" {
		writeOK(w, map[string]any{"result": "deny", "status": "deny", "status_msg": "Only push is supported"})
		return
	}
	// The response blocks until push is answered. The deadline is set here to pick up a
	// reloaded push-timeout.
	timeout := h.svc.Config().PushTimeout.D()
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout + 30*time.Second)); err != nil {
		h.internal(w, err)
		return
	}
	ref := userRef(p)
	// Duo's device=auto is core's default: the most recently used device.
	device := p.get("device")
	if device == "auto" {
		device = ""
	}
	state, err := h.svc.Authenticate(r.Context(), core.AuthRequest{
		User: ref, Device: device, IPAddr: p.get("ipaddr"), TargetURL: pushInfo(p.get("pushinfo"), "target url"),
		DisplayUsername: p.get("display_username"), Timeout: timeout,
	})
	if err != nil && core.KindOf(err) == core.Internal {
		h.internal(w, err)
		return
	}
	if err != nil {
		h.log.Info("duo api: auth not approved", "user", ref, "state", state, "err", err)
	}
	switch state {
	case model.StateAllow:
		writeOK(w, map[string]any{"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."})
	case model.StateFraud:
		writeOK(w, map[string]any{"result": "deny", "status": "fraud", "status_msg": "Login request reported as fraudulent."})
	case model.StateTimeout:
		writeOK(w, map[string]any{"result": "deny", "status": "timeout", "status_msg": "Login timed out."})
	default:
		writeOK(w, deny(err))
	}
}

// pushInfo reads key from Duo's url-encoded pushinfo parameter.
func pushInfo(raw, key string) string {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	return v.Get(key)
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request, p params) {
	ctx := r.Context()
	username := p.get("username")
	if username == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "username")
		return
	}
	e, err := h.svc.StartIdPEnrollment(ctx, username)
	switch {
	case errors.Is(err, core.ErrInvalidName):
		writeFail(w, http.StatusBadRequest, 40002, "Invalid request parameters", "username")
		return
	case err != nil && core.KindOf(err) != core.Internal:
		writeFail(w, http.StatusBadRequest, 40002, "Invalid request parameters", statusMsg(err))
		return
	case err != nil:
		h.internal(w, err)
		return
	}
	writeOK(w, map[string]any{
		"activation_barcode": routes.QRURL(h.svc.Config().PublicURL, e.Link),
		"activation_code":    e.Code,
		"activation_url":     e.Link,
		"expiration":         e.ExpiresAt.Unix(),
		"user_id":            e.UserID,
		"username":           e.Username,
	})
}

func (h *Handler) enrollStatus(w http.ResponseWriter, r *http.Request, p params) {
	if p.get("user_id") == "" || p.get("activation_code") == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "user_id, activation_code")
		return
	}
	writeOK(w, enrollStatus[h.svc.EnrollmentState(r.Context(), p.get("user_id"), p.get("activation_code"))])
}

// enrollStatus is Duo's wording of each enrollment state.
var enrollStatus = map[core.EnrollmentState]string{
	core.EnrollmentWaiting: "waiting",
	core.EnrollmentDone:    "success",
	core.EnrollmentInvalid: "invalid",
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("duo api", "err", err)
	writeFail(w, http.StatusInternalServerError, 50000, "Internal server error", "")
}
