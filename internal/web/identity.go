package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/oidc"
)

// Identity resolves who is using the self-service pages.
type Identity interface {
	// User returns the username, or "" and false after writing a response (redirect or refusal).
	User(w http.ResponseWriter, r *http.Request) (string, bool)
}

// NewIdentity signs users in through the IdP's OIDC provider and registers the login and callback
// routes on mux.
func NewIdentity(ctx context.Context, svc *core.Service, mux *http.ServeMux) (Identity, error) {
	cfg := svc.Config()
	a, err := oidc.New(ctx, cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret, cfg.PublicURL, svc.Store)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	mux.HandleFunc("GET "+oidc.LoginPath, a.Login)
	mux.HandleFunc("GET "+oidc.CallbackPath, a.Callback)
	return OIDCAuth{Auth: a}, nil
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
