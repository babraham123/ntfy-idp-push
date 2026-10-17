// Package oidc handles Web UI logins via OIDC auth code flow with PKCE, mapping preferred_username
// to Username.
package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

const (
	flowCookie    = "nip_oidc"
	sessionCookie = "nip_session"
	sessionTTL    = 12 * time.Hour
	CallbackPath  = "/oidc/callback"
	LoginPath     = "/oidc/login"
)

type Auth struct {
	oauth    oauth2.Config
	verifier *gooidc.IDTokenVerifier
	store    *store.Store
	secure   bool
}

func New(ctx context.Context, issuer, clientID, clientSecret, publicURL string, st *store.Store) (*Auth, error) {
	p, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &Auth{
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  publicURL + CallbackPath,
			Scopes:       []string{gooidc.ScopeOpenID, "profile"},
		},
		verifier: p.Verifier(&gooidc.Config{ClientID: clientID}),
		store:    st,
		secure:   strings.HasPrefix(publicURL, "https://"),
	}, nil
}

func (a *Auth) cookie(name, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode}
}

// User returns the signed-in username, or "" when there is no valid session.
func (a *Auth) User(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	u, err := a.store.SessionUser(r.Context(), c.Value, time.Now())
	if err != nil {
		return ""
	}
	return u
}

// LocalPath returns next if on-origin, else /devices. Protects against browser normalization tricks
// (e.g., /\evil.example).
func LocalPath(next string) string {
	const fallback = "/devices"
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, "\\") ||
		strings.IndexFunc(next, unicode.IsControl) >= 0 {
		return fallback
	}
	if u, err := url.Parse(next); err != nil || u.Scheme != "" || u.Host != "" {
		return fallback
	}
	return next
}

// Login redirects to the provider, then back to next.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	next := LocalPath(r.URL.Query().Get("next"))
	state, verifier := token.Random(16), oauth2.GenerateVerifier()
	val := state + "." + verifier + "." + base64.RawURLEncoding.EncodeToString([]byte(next))
	http.SetCookie(w, a.cookie(flowCookie, val, 10*time.Minute))
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	next, err := a.callback(w, r)
	if err != nil {
		http.Error(w, "sign-in failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) (string, error) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return "", errors.New("missing flow cookie")
	}
	http.SetCookie(w, a.cookie(flowCookie, "", -time.Second))
	parts := strings.SplitN(c.Value, ".", 3)
	if len(parts) != 3 || r.URL.Query().Get("state") != parts[0] {
		return "", errors.New("state mismatch")
	}
	next, _ := base64.RawURLEncoding.DecodeString(parts[2])
	tok, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(parts[1]))
	if err != nil {
		return "", err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", errors.New("no id_token")
	}
	idt, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		return "", err
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&claims); err != nil || claims.PreferredUsername == "" {
		return "", errors.New("id_token lacks preferred_username")
	}
	id := token.Random(32)
	if err := a.store.CreateSession(r.Context(), id, claims.PreferredUsername, time.Now().Add(sessionTTL)); err != nil {
		return "", err
	}
	http.SetCookie(w, a.cookie(sessionCookie, id, sessionTTL))
	return LocalPath(string(next)), nil
}
