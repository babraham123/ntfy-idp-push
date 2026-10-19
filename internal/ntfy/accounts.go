package ntfy

import (
	"context"
	"fmt"
	"sync"

	"github.com/babraham123/ntfy-idp-push/internal/token"
)

// Accounts is ntfy's user list, fetched once on first use and kept current by the adds and deletes
// made through it. ntfy has no single-user lookup, so a sync round that touches many accounts
// shares one Accounts and lists ntfy once; a single operation makes its own. It never outlives the
// operation that made it: ntfy is the truth, and another process may change it at any time.
type Accounts struct {
	c      *Client
	mu     sync.Mutex
	byName map[string]*User
}

// Accounts starts an empty view of the server's users; the first lookup fills it.
func (c *Client) Accounts() *Accounts { return &Accounts{c: c} }

// load fills the view if it is empty. It is called with mu held.
func (a *Accounts) load(ctx context.Context) error {
	if a.byName != nil {
		return nil
	}
	us, err := a.c.Users(ctx)
	if err != nil {
		return err
	}
	a.byName = make(map[string]*User, len(us))
	for i := range us {
		a.byName[us[i].Username] = &us[i]
	}
	return nil
}

// Get returns username's account, or nil when there is none.
func (a *Accounts) Get(ctx context.Context, username string) (*User, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(ctx); err != nil {
		return nil, err
	}
	return a.byName[username], nil
}

// Ensure creates username's account if there is none. The new account gets a password nobody knows;
// the shim hands the user one later by replacing it. An account that is an admin is refused: the
// shim must never grant, reset or delete an administrator.
func (a *Accounts) Ensure(ctx context.Context, username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.load(ctx); err != nil {
		return err
	}
	if u := a.byName[username]; u != nil {
		if u.Role == "admin" {
			return fmt.Errorf("ntfy user %q is an admin; refusing to manage it", username)
		}
		return nil
	}
	if err := a.c.AddUser(ctx, username, token.Random(32)); err != nil {
		return err
	}
	a.byName[username] = &User{Username: username, Role: "user"}
	return nil
}

// Delete removes username's account; a missing one counts as deleted.
func (a *Accounts) Delete(ctx context.Context, username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.c.DeleteUser(ctx, username); err != nil {
		return err
	}
	if a.byName != nil {
		delete(a.byName, username)
	}
	return nil
}
