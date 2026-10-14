package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/babraham123/ntfy-idp-push/internal/oidc"
)

// Identity resolves who is using the self-service pages.
type Identity interface {
	// User returns the username, or "" and false after writing a response (redirect or refusal).
	User(w http.ResponseWriter, r *http.Request) (string, bool)
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

// ForwardAuth trusts Remote-User set by an Authelia forward-auth proxy, from trusted-proxies only.
type ForwardAuth struct {
	Trusted func() []*net.IPNet
}

func (f ForwardAuth) User(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !trusted(f.Trusted(), remoteIP(r)) {
		http.Error(w, "forbidden: request did not come through the authenticating proxy", http.StatusForbidden)
		return "", false
	}
	u := strings.TrimSpace(r.Header.Get("Remote-User"))
	if u == "" {
		http.Error(w, "forbidden: proxy sent no Remote-User", http.StatusForbidden)
		return "", false
	}
	return u, true
}

type OIDCAuth struct{ *oidc.Auth }

func (o OIDCAuth) User(w http.ResponseWriter, r *http.Request) (string, bool) {
	if u := o.Auth.User(r); u != "" {
		return u, true
	}
	if r.Method != http.MethodGet {
		http.Error(w, "sign in required", http.StatusUnauthorized)
		return "", false
	}
	http.Redirect(w, r, oidc.LoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	return "", false
}
