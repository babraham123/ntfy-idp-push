package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
)

type topicLink struct {
	Topic string
	Link  template.URL
}

// provisionPage creates the ntfy account and hands out one-tap sign-in/subscribe links.
func (s *Server) provisionPage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.identity.User(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := s.svc.Provision(ctx, user); err != nil {
		s.log.Warn("provision", "user", user, "err", err)
		s.message(w, http.StatusBadRequest, "Cannot set up ntfy", err.Error())
		return
	}
	ec, err := s.svc.MintNtfyCode(ctx, user)
	if err != nil {
		s.log.Error("provision: enroll code", "user", user, "err", err)
		s.message(w, http.StatusBadGateway, "Cannot set up ntfy", "The ntfy server did not issue a sign-in code.")
		return
	}
	code := ""
	if ec != nil {
		code = ec.Code
	}
	cfg := s.svc.Config()
	var topics []string
	var links []topicLink
	for _, t := range cfg.DefaultTopics {
		t = config.Expand(t, user)
		topics = append(topics, t)
		links = append(links, topicLink{Topic: t, Link: template.URL(s.svc.NtfyLink(t, user, code))})
	}
	data := map[string]any{
		"User":    user,
		"HasCode": ec != nil,
		"Links":   links,
		"WebApp":  cfg.NtfyBaseURL,
	}
	if ec != nil {
		data["CodeMinutes"] = int(time.Until(ec.ExpiresAt()).Round(time.Minute).Minutes())
	}
	ua := r.UserAgent()
	switch {
	case strings.Contains(ua, "Android"):
		data["Platform"] = "android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		data["Platform"] = "ios"
	default:
		data["Platform"] = "desktop"
		if len(links) > 0 {
			if qr, err := qrDataURL(string(links[0].Link)); err == nil {
				data["QR"] = qr
			}
		}
		if code != "" {
			// The fragment keeps the code out of ntfy server logs. user= prevents the
			// web app from mixing accounts.
			frag := url.Values{"code": {code}, "user": {user}, "subscribe": {strings.Join(topics, ",")}}
			data["Redeem"] = template.URL(cfg.NtfyBaseURL + "/account/token/redeem#" + frag.Encode())
		}
	}
	s.render(w, http.StatusOK, "provision.html", data)
}

// provisionPassword is the manual sign-in path for ntfy apps that cannot redeem sign-in codes.
func (s *Server) provisionPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.identity.User(w, r)
	if !ok {
		return
	}
	password, err := s.svc.SetNtfyPassword(r.Context(), user)
	if err != nil {
		s.log.Error("provision: ntfy password", "user", user, "err", err)
		s.message(w, http.StatusBadGateway, "Cannot set up ntfy", "The ntfy server did not accept a new password.")
		return
	}
	s.render(w, http.StatusOK, "password.html", map[string]string{"User": user, "Password": password, "Server": s.svc.Config().NtfyBaseURL})
}

func (s *Server) devicesPage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.identity.User(w, r)
	if !ok {
		return
	}
	data := map[string]any{"User": user}
	u, devs, err := s.svc.DevicesOf(r.Context(), user)
	switch {
	case errors.Is(err, core.ErrUnknownUser):
	case err != nil:
		s.log.Error("devices", "user", user, "err", err)
		s.message(w, http.StatusInternalServerError, "Error", "Could not load devices.")
		return
	default:
		data["Devices"] = devs
		data["Disabled"] = u.DisabledAt != nil
	}
	s.render(w, http.StatusOK, "devices.html", data)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	user, ok := s.identity.User(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	err := s.svc.RevokeOwned(r.Context(), user, id, r.FormValue("reset_ntfy") == "1")
	switch {
	case errors.Is(err, core.ErrUnknownDevice):
		s.message(w, http.StatusNotFound, "Not found", "No such device.")
		return
	case errors.Is(err, core.ErrForeignGrants):
		s.message(w, http.StatusConflict, "Ask an administrator",
			"Your ntfy account has permissions this service did not set up, so it cannot sign out your ntfy apps for you. The phone was not revoked.")
		return
	case err != nil:
		s.log.Error("revoke", "device", id, "err", err)
		s.message(w, http.StatusInternalServerError, "Error", "The phone can no longer approve sign-ins, but cleaning up its ntfy access failed. Try again.")
		return
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}
