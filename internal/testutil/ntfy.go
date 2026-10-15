// Package testutil provides a fake ntfy server, a virtual WebAuthn authenticator, and a harness
// that wires the shim together for integration tests.
package testutil

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
)

const AdminToken = "tk_admin"

// FakeNtfy implements the slice of ntfy's API the shim uses, with auth-default-access: deny-all.
// Error statuses and codes follow ntfy v2.30 (server/server_admin.go).
type FakeNtfy struct {
	*httptest.Server
	// EnrollSupported toggles the ntfy#597 POST /v1/users/token/enroll endpoint.
	EnrollSupported bool
	// AdminRole is the role GET /v1/account reports for the admin token.
	AdminRole string
	// AnonymousRead simulates a server that lets anyone poll any topic.
	AnonymousRead bool

	mu        sync.Mutex
	failures  map[string]int // "METHOD /path" -> calls left to fail with 500
	passwords map[string]string
	users     map[string]*ntfy.User
	codes     map[string]string // pending enrollment code -> username; one per user, as in ntfy
	published []ntfy.Message
	deleted   []string // "topic/sequence_id"
	pubCh     chan ntfy.Message
}

func NewFakeNtfy(t *testing.T) *FakeNtfy {
	f := &FakeNtfy{
		EnrollSupported: true,
		AdminRole:       "admin",
		users:           map[string]*ntfy.User{"idp-push": {Username: "idp-push", Role: "admin"}},
		pubCh:           make(chan ntfy.Message, 100),
		codes:           map[string]string{},
		failures:        map[string]int{},
		passwords:       map[string]string{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *FakeNtfy) serve(w http.ResponseWriter, r *http.Request) {
	admin := r.Header.Get("Authorization") == "Bearer "+AdminToken
	var body map[string]string
	if r.Body != nil && r.Header.Get("Content-Type") == "application/json" && r.URL.Path != "/" {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if key := r.Method + " " + r.URL.Path; f.failures[key] > 0 {
		f.failures[key]--
		http.Error(w, `{"code":50001}`, http.StatusInternalServerError)
		return
	}
	switch {
	case r.URL.Path == "/v1/account/token/redeem" && r.Method == http.MethodPost:
		user, ok := f.codes[body["code"]]
		if !ok {
			http.Error(w, `{"code":40060}`, http.StatusBadRequest)
			return
		}
		delete(f.codes, body["code"])
		json.NewEncoder(w).Encode(ntfy.Token{Token: "tk_" + user, Label: body["label"], Username: user})
	case strings.HasSuffix(r.URL.Path, "/json") && r.Method == http.MethodGet:
		if !admin && !f.AnonymousRead {
			http.Error(w, `{"code":40301}`, http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	case !admin:
		http.Error(w, `{"code":40101}`, http.StatusUnauthorized)
	case r.URL.Path == "/v1/account" && r.Method == http.MethodGet:
		json.NewEncoder(w).Encode(ntfy.Account{Username: "idp-push", Role: f.AdminRole})
	case r.URL.Path == "/v1/users" && r.Method == http.MethodGet:
		out := []ntfy.User{}
		for _, u := range f.users {
			out = append(out, *u)
		}
		json.NewEncoder(w).Encode(out)
	case r.URL.Path == "/v1/users" && r.Method == http.MethodPost:
		if f.users[body["username"]] != nil {
			http.Error(w, `{"code":40901}`, http.StatusConflict)
			return
		}
		if body["password"] == "" {
			http.Error(w, `{"code":40001}`, http.StatusBadRequest)
			return
		}
		f.users[body["username"]] = &ntfy.User{Username: body["username"], Role: "user"}
		f.passwords[body["username"]] = body["password"]
		w.Write([]byte(`{"success":true}`))
	case r.URL.Path == "/v1/users" && r.Method == http.MethodPut:
		// An upsert: ntfy creates a missing user.
		if f.users[body["username"]] == nil {
			f.users[body["username"]] = &ntfy.User{Username: body["username"], Role: "user"}
		}
		f.passwords[body["username"]] = body["password"]
		w.Write([]byte(`{"success":true}`))
	case r.URL.Path == "/v1/users" && r.Method == http.MethodDelete:
		if f.users[body["username"]] == nil {
			http.Error(w, `{"code":40031}`, http.StatusBadRequest)
			return
		}
		delete(f.users, body["username"])
		f.dropCodes(body["username"])
		w.Write([]byte(`{"success":true}`))
	case r.URL.Path == "/v1/users/access" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		u := f.users[body["username"]]
		if u == nil {
			http.Error(w, `{"code":40031}`, http.StatusBadRequest)
			return
		}
		u.Grants = setGrant(u.Grants, ntfy.Grant{Topic: body["topic"], Permission: body["permission"]})
		w.Write([]byte(`{"success":true}`))
	case r.URL.Path == "/v1/users/access" && r.Method == http.MethodDelete:
		u := f.users[body["username"]]
		if u == nil {
			// ntfy passes user.ErrUserNotFound through unwrapped, which it reports as a generic 500.
			http.Error(w, `{"code":50001}`, http.StatusInternalServerError)
			return
		}
		u.Grants = setGrant(u.Grants, ntfy.Grant{Topic: body["topic"]})
		w.Write([]byte(`{"success":true}`))
	case r.URL.Path == "/v1/users/token/enroll" && r.Method == http.MethodPost:
		if !f.EnrollSupported {
			http.NotFound(w, r)
			return
		}
		u := f.users[body["username"]]
		if u == nil {
			http.Error(w, `{"code":40035}`, http.StatusBadRequest)
			return
		} else if u.Role != "user" {
			http.Error(w, `{"code":40101}`, http.StatusUnauthorized)
			return
		}
		f.dropCodes(u.Username)
		code := rand.Text()
		f.codes[code] = u.Username
		json.NewEncoder(w).Encode(ntfy.EnrollCode{Code: code, Expires: time.Now().Add(10 * time.Minute).Unix()})
	case r.URL.Path == "/" && r.Method == http.MethodPost:
		var m ntfy.Message
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.published = append(f.published, m)
		select {
		case f.pubCh <- m:
		default:
		}
		w.Write([]byte(`{"id":"x"}`))
	case r.Method == http.MethodDelete && strings.Count(r.URL.Path, "/") == 2:
		f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/"))
		w.Write([]byte(`{"id":"x"}`))
	default:
		http.NotFound(w, r)
	}
}

// dropCodes removes a user's pending code: issuing a new one or deleting the user supersedes it.
func (f *FakeNtfy) dropCodes(user string) {
	for c, u := range f.codes {
		if u == user {
			delete(f.codes, c)
		}
	}
}

// setGrant replaces the grant for g.Topic; an empty permission removes it.
func setGrant(gs []ntfy.Grant, g ntfy.Grant) []ntfy.Grant {
	out := gs[:0:0]
	for _, x := range gs {
		if x.Topic != g.Topic {
			out = append(out, x)
		}
	}
	if g.Permission != "" {
		out = append(out, g)
	}
	return out
}

// User returns a copy of the ntfy user, or nil.
func (f *FakeNtfy) User(name string) *ntfy.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u := f.users[name]; u != nil {
		c := *u
		c.Grants = append([]ntfy.Grant(nil), u.Grants...)
		return &c
	}
	return nil
}

// AddForeignGrant simulates a grant an admin made outside the shim.
func (f *FakeNtfy) AddForeignGrant(user, topic, perm string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[user].Grants = append(f.users[user].Grants, ntfy.Grant{Topic: topic, Permission: perm})
}

// Grant returns the permission user has on exactly topic, or "".
func (f *FakeNtfy) Grant(user, topic string) string {
	if u := f.User(user); u != nil {
		for _, g := range u.Grants {
			if g.Topic == topic {
				return g.Permission
			}
		}
	}
	return ""
}

// NextPublish waits for the next published message.
func (f *FakeNtfy) NextPublish(t *testing.T) ntfy.Message {
	t.Helper()
	select {
	case m := <-f.pubCh:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message published")
		return ntfy.Message{}
	}
}

// FailNext makes the next n calls of method on path answer 500, like an ntfy outage.
func (f *FakeNtfy) FailNext(method, path string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[method+" "+path] = n
}

// Password returns the user's current password.
func (f *FakeNtfy) Password(user string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passwords[user]
}

func (f *FakeNtfy) Deleted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

// DeleteUser removes the ntfy user directly, as an admin acting outside the shim would.
func (f *FakeNtfy) DeleteUser(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, name)
	f.dropCodes(name)
}
