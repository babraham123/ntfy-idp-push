// Package duoapi serves the subset of the Duo Auth API v2 that IdPs call: ping, check, preauth,
// auth, enroll and enroll_status.
package duoapi

import (
	"context"
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

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

const maxBody = 64 << 10

type Handler struct {
	svc    *core.Service
	log    *slog.Logger
	replay *replayCache
	now    func() time.Time
}

func New(svc *core.Service, log *slog.Logger) *Handler {
	return &Handler{svc: svc, log: log, replay: newReplayCache(), now: time.Now}
}

// Register mounts the Duo API routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/v2/ping", h.ping)
	// Signatures have one-second date resolution, so identical idempotent calls (an IdP polling
	// enroll_status) legitimately repeat a signature; only calls with side effects refuse replays.
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
			h.log.Warn("duo api: rejected", "path", r.URL.Path, "remote", r.RemoteAddr, "err", err)
			code := 40101
			switch {
			case errors.Is(err, errBadIKey):
				code = 40102
			case errors.Is(err, errBadSignature):
				code = 40103
			case errors.Is(err, errSkew):
				code = 40105
			}
			writeFail(w, http.StatusUnauthorized, code, "Invalid request credentials", err.Error())
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

func deny(msg string) map[string]any {
	return map[string]any{"result": "deny", "status": "deny", "status_msg": msg}
}

// lookupUser resolves username or user_id; a nil user with nil error means unknown.
func (h *Handler) lookupUser(ctx context.Context, p params) (*store.User, error) {
	var u *store.User
	var err error
	if id := p.get("user_id"); id != "" {
		u, err = h.svc.Store.UserByID(ctx, id)
	} else {
		u, err = h.svc.Store.UserByName(ctx, p.get("username"))
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return u, err
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
	ctx := r.Context()
	cfg := h.svc.Config()
	if p.get("username") == "" && p.get("user_id") == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "username")
		return
	}
	if cfg.PushDisabled {
		writeOK(w, deny("Push authentication is disabled"))
		return
	}
	u, err := h.lookupUser(ctx, p)
	if err != nil {
		h.internal(w, err)
		return
	}
	var devs []store.Device
	if u != nil {
		if u.DisabledAt != nil {
			writeOK(w, deny("user disabled"))
			return
		}
		if devs, err = h.svc.Store.Devices(ctx, u.ID, true); err != nil {
			h.internal(w, err)
			return
		}
	}
	if len(devs) == 0 {
		if cfg.EnrollPortalURL == "" {
			writeOK(w, deny("Enrollment required"))
			return
		}
		writeOK(w, map[string]any{"result": "enroll", "status_msg": "Enroll an authentication device to proceed",
			"enroll_portal_url": cfg.EnrollPortalURL})
		return
	}
	out := make([]device, 0, len(devs))
	for _, d := range devs {
		out = append(out, device{Device: d.ID, Type: "phone", Name: d.Name, DisplayName: d.Name, Capabilities: []string{"push"}})
	}
	writeOK(w, map[string]any{"result": "auth", "status_msg": "Account is active", "devices": out})
}

func (h *Handler) auth(w http.ResponseWriter, r *http.Request, p params) {
	ctx := r.Context()
	if p.get("username") == "" && p.get("user_id") == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "username")
		return
	}
	if f := p.get("factor"); f != "push" && f != "auto" {
		writeOK(w, deny("Only push is supported"))
		return
	}
	u, err := h.lookupUser(ctx, p)
	if err != nil {
		h.internal(w, err)
		return
	}
	if u == nil {
		writeOK(w, deny("Unknown user"))
		return
	}
	dev, err := h.pickDevice(ctx, u, p.get("device"))
	if err != nil {
		h.internal(w, err)
		return
	}
	if dev == nil {
		writeOK(w, deny("Unknown device"))
		return
	}
	// The response blocks until the push is answered, so it must outlast push-timeout. The deadline
	// is set here rather than on the server so a reloaded push-timeout takes effect.
	timeout := h.svc.Config().PushTimeout.D()
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout + 30*time.Second)); err != nil {
		h.internal(w, err)
		return
	}
	state, err := h.svc.Authenticate(ctx, core.AuthRequest{
		User: u, Device: dev, IPAddr: p.get("ipaddr"), TargetURL: pushInfo(p.get("pushinfo"), "target url"),
		DisplayUsername: p.get("display_username"), Timeout: timeout,
	})
	if err != nil {
		h.log.Info("duo api: auth not approved", "user", u.Username, "state", state, "err", err)
	}
	switch state {
	case store.StateAllow:
		writeOK(w, map[string]any{"result": "allow", "status": "allow", "status_msg": "Success. Logging you in..."})
	case store.StateFraud:
		writeOK(w, map[string]any{"result": "deny", "status": "fraud", "status_msg": "Login request reported as fraudulent."})
	case store.StateTimeout:
		writeOK(w, map[string]any{"result": "deny", "status": "timeout", "status_msg": "Login timed out."})
	default:
		msg := "Login request denied."
		if errors.Is(err, core.ErrUserDisabled) {
			msg = "user disabled"
		}
		writeOK(w, deny(msg))
	}
}

// pickDevice resolves the device param; "auto" (or empty) means the most recently used device.
// A device that is not the user's verified device resolves to nil.
func (h *Handler) pickDevice(ctx context.Context, u *store.User, id string) (*store.Device, error) {
	devs, err := h.svc.Store.Devices(ctx, u.ID, true)
	if err != nil {
		return nil, err
	}
	if id == "" || id == "auto" {
		if len(devs) == 0 {
			return nil, nil
		}
		return &devs[0], nil
	}
	for i := range devs {
		if devs[i].ID == id {
			return &devs[i], nil
		}
	}
	return nil, nil
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
	if err := core.ValidUsername(username); err != nil {
		writeFail(w, http.StatusBadRequest, 40002, "Invalid request parameters", "username")
		return
	}
	u, err := h.svc.Provision(ctx, username)
	if errors.Is(err, core.ErrUserDisabled) {
		writeFail(w, http.StatusBadRequest, 40002, "Invalid request parameters", "user disabled")
		return
	} else if err != nil {
		h.internal(w, err)
		return
	}
	ttl := core.EnrollCodeTTL
	code, link, err := h.svc.CreateEnrollCode(ctx, username, ttl)
	if err != nil {
		h.internal(w, err)
		return
	}
	writeOK(w, map[string]any{
		"activation_barcode": h.svc.Config().PublicURL + "/enroll/qr?value=" + url.QueryEscape(link),
		"activation_code":    code,
		"activation_url":     link,
		"expiration":         h.now().Add(ttl).Unix(),
		"user_id":            u.ID,
		"username":           u.Username,
	})
}

func (h *Handler) enrollStatus(w http.ResponseWriter, r *http.Request, p params) {
	if p.get("user_id") == "" || p.get("activation_code") == "" {
		writeFail(w, http.StatusBadRequest, 40001, "Missing required request parameters", "user_id, activation_code")
		return
	}
	writeOK(w, h.svc.EnrollStatus(r.Context(), p.get("user_id"), p.get("activation_code")))
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("duo api", "err", err)
	writeFail(w, http.StatusInternalServerError, 50000, "Internal server error", "")
}
