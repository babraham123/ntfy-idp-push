package web

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/routes"
)

// platform picks the ntfy app instructions a page shows: the Android app subscribes from an
// ntfy:// link, the iOS app does not open them and subscribes by hand, and a desktop browser is
// not the phone, so it shows a QR code for Android and the manual steps for iOS.
func platform(r *http.Request) string {
	ua := r.UserAgent()
	switch {
	case strings.Contains(ua, "Android"):
		return "android"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		return "ios"
	}
	return "desktop"
}

// subscribeData fills the ntfy-subscribe template. The enrollment page sets only Platform and its
// script fills in the rest.
type subscribeData struct {
	Platform, Topic, Server string
	// Intent is core's intent:// link for the Android button; html/template would otherwise
	// replace the non-web scheme.
	Intent, QR template.URL
}

// subscribePage is where the welcome email's topic links lead, as mail clients drop ntfy:// links.
// It is public: the phone opening it is not signed in to the proxy, and it serves only the user's
// default topics, which name nothing secret.
func (s *Server) subscribePage(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	l, err := s.svc.DefaultTopicLink(user, r.PathValue("topic"))
	if err != nil {
		s.pageFail(w, err, "subscribe")
		return
	}
	sub := subscribeData{Platform: platform(r), Topic: l.Topic, Server: s.svc.Config().NtfyBaseURL, Intent: template.URL(l.Intent)}
	if sub.Platform == "desktop" {
		if sub.QR, err = qrDataURL(l.URL); err != nil {
			s.pageFail(w, err, "subscribe: qr")
			return
		}
	}
	s.render(w, http.StatusOK, "subscribe.html", map[string]any{"User": user, "Subscribe": sub})
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
	if err == nil {
		http.Redirect(w, r, routes.Devices, http.StatusSeeOther)
		return
	}
	if m, ok := revokeMessages[core.ReasonOf(err)]; ok {
		if m.status == http.StatusInternalServerError {
			s.log.Error("revoke", "device", id, "err", err)
		}
		s.message(w, m.status, m.title, m.text)
		return
	}
	s.pageFail(w, err, "revoke")
}

// revokeMessages is what the devices page says for the revoke failures that core's reason does
// not explain to a user by itself, by reason; "" is an internal failure, which has already
// revoked the phone locally.
var revokeMessages = map[core.Reason]struct {
	status      int
	title, text string
}{
	core.ErrForeignGrants.Reason: {http.StatusConflict, "Ask an administrator",
		"Your ntfy account has permissions this service did not set up, so it cannot sign out your ntfy apps for you. The phone was not revoked."},
	"": {http.StatusInternalServerError, "Error",
		"The phone can no longer approve sign-ins, but cleaning up its ntfy access failed. Try again."},
}
