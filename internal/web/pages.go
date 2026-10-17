package web

import (
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/routes"
)

type topicLink struct {
	Topic string
	Link  template.URL
}

// provisionPage creates the ntfy account and hands out one-tap sign-in/subscribe links.
func (s *Server) provisionPage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if _, err := s.svc.Provision(ctx, user); err != nil {
		s.pageFail(w, err, "provision")
		return
	}
	h, err := s.svc.DefaultHandoff(ctx, user)
	if err != nil {
		s.pageFail(w, err, "provision: handoff")
		return
	}
	var links []topicLink
	for _, l := range h.Links {
		links = append(links, topicLink{Topic: l.Topic, Link: template.URL(l.URL)})
	}
	data := map[string]any{
		"User":    user,
		"HasCode": h.HasCode(),
		"Links":   links,
		"WebApp":  s.svc.Config().NtfyBaseURL,
	}
	if h.HasCode() {
		data["CodeMinutes"] = int(time.Until(h.CodeExpires).Round(time.Minute).Minutes())
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
		if h.RedeemURL != "" {
			data["Redeem"] = template.URL(h.RedeemURL)
		}
	}
	s.render(w, http.StatusOK, "provision.html", data)
}

// provisionPassword is the manual sign-in path for ntfy apps that cannot redeem sign-in codes.
func (s *Server) provisionPassword(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	password, err := s.svc.SetNtfyPassword(r.Context(), user)
	if err != nil {
		s.pageFail(w, err, "provision: ntfy password")
		return
	}
	s.render(w, http.StatusOK, "password.html", map[string]string{"User": user, "Password": password, "Server": s.svc.Config().NtfyBaseURL})
}

func (s *Server) devicesPage(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	data := map[string]any{"User": user}
	u, devs, err := s.svc.DevicesOf(r.Context(), user)
	switch {
	case errors.Is(err, core.ErrUnknownUser):
		// Nothing enrolled yet: the page still offers to.
	case err != nil:
		s.pageFail(w, err, "devices")
		return
	default:
		data["Devices"] = devs
		data["Disabled"] = !u.Enabled()
	}
	s.render(w, http.StatusOK, "devices.html", data)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	user, ok := s.signedIn(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	err := s.svc.RevokeOwned(r.Context(), user, id, r.FormValue("reset_ntfy") == "1")
	switch {
	case errors.Is(err, core.ErrForeignGrants):
		s.message(w, http.StatusConflict, "Ask an administrator",
			"Your ntfy account has permissions this service did not set up, so it cannot sign out your ntfy apps for you. The phone was not revoked.")
		return
	case err != nil && core.KindOf(err) == core.Internal:
		s.log.Error("revoke", "device", id, "err", err)
		s.message(w, http.StatusInternalServerError, "Error", "The phone can no longer approve sign-ins, but cleaning up its ntfy access failed. Try again.")
		return
	case err != nil:
		s.pageFail(w, err, "revoke")
		return
	}
	http.Redirect(w, r, routes.Devices, http.StatusSeeOther)
}
