package core

// The directory controls who has an ntfy account. Sync converges the store and ntfy on the directory
// every round. Welcome emails the user their credentials. The ntfy password exists only in the email,
// so every path that invalidates the password (a new account, a reset) marks a welcome as owed
// before it changes anything, and ends in Welcome. The next sync round sends any welcome still owed.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/mail"
	"github.com/babraham123/ntfy-idp-push/internal/model"
)

// SyncCounts is what one sync round changed.
type SyncCounts struct {
	Created, Welcomed, Deleted, Updated int
}

// Sync runs one directory sync round. A directory that fails or lists nobody skips the round and
// changes nothing, since deletes cannot be undone and a broken directory would delete everyone.
// The round first reconciles accounts: it creates listed people, records profiles, and deletes
// users the directory no longer lists or marks disabled. Only then does it send owed welcomes, so
// a slow or failing mail server never holds up a deletion. A failure for one user does not stop
// the round; every failure is logged, and they are returned together.
func (s *Service) Sync(ctx context.Context) error {
	people, err := s.dir.List(ctx)
	if err != nil {
		s.Log.Warn("directory sync skipped", "err", err)
		s.store.Audit(ctx, "", "sync_skipped", map[string]any{"error": err.Error()})
		return err
	}
	users, err := s.store.Users(ctx)
	if err != nil {
		return err
	}
	ctx = s.withNtfyUsers(ctx)
	known := make(map[string]*model.User, len(users))
	for i := range users {
		known[users[i].Username] = &users[i]
	}
	listed := make(map[string]bool, len(people))
	now := time.Now()
	var n SyncCounts
	var errs []error
	fail := func(username string, err error) {
		s.Log.Warn("directory sync", "user", username, "err", err)
		errs = append(errs, fmt.Errorf("sync %q: %w", username, err))
	}

	for _, p := range people {
		// A disabled person is treated as absent: never created, and deleted if known.
		if p.Disabled {
			continue
		}
		listed[p.Username] = true
		u := known[p.Username]
		if u == nil {
			u, err := s.adopt(ctx, p, now)
			if u != nil {
				n.Created++
			}
			if err != nil {
				fail(p.Username, err)
			}
			continue
		}
		changed := u.Email != p.Email || u.DisplayName != p.DisplayName
		if err := s.recordProfile(ctx, u, p, now); err != nil {
			fail(p.Username, err)
			continue
		}
		if changed {
			n.Updated++
		}
	}

	for _, u := range users {
		if listed[u.Username] {
			continue
		}
		if err := s.DeleteUser(ctx, u.Username, false); err != nil {
			fail(u.Username, err)
			continue
		}
		n.Deleted++
	}

	// Re-read so the users just created and the addresses just recorded are included.
	if users, err = s.store.Users(ctx); err != nil {
		errs = append(errs, err)
		users = nil
	}
	for _, u := range users {
		if u.WelcomedAt != nil || u.Email == "" || !u.Enabled() {
			continue
		}
		sent, err := s.welcome(ctx, u.Username, true)
		if err != nil {
			fail(u.Username, err)
			continue
		}
		if sent {
			n.Welcomed++
		}
	}

	s.store.Audit(ctx, "", "sync", map[string]any{
		"created": n.Created, "welcomed": n.Welcomed, "deleted": n.Deleted, "updated": n.Updated,
		"failed": len(errs),
	})
	return errors.Join(errs...)
}

// ProvisionFromDirectory provisions a user the directory lists, records their directory profile,
// and sends the welcome they are owed. A name absent from the directory or marked disabled
// is refused.
func (s *Service) ProvisionFromDirectory(ctx context.Context, username string) (*model.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	people, err := s.dir.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		if p.Username != username {
			continue
		}
		if p.Disabled {
			return nil, ErrUserDisabled
		}
		u, err := s.adopt(ctx, p, time.Now())
		if err != nil {
			return u, err
		}
		_, err = s.welcome(ctx, username, true)
		return u, err
	}
	return nil, ErrNotInDirectory
}

// adopt provisions p's account and records p's profile. A user is returned once provisioning
// succeeded, even if recording the profile failed.
func (s *Service) adopt(ctx context.Context, p directory.Person, now time.Time) (*model.User, error) {
	u, err := s.Provision(ctx, p.Username)
	if err != nil {
		return nil, err
	}
	return u, s.recordProfile(ctx, u, p, now)
}

func (s *Service) recordProfile(ctx context.Context, u *model.User, p directory.Person, now time.Time) error {
	if err := s.store.SetUserProfile(ctx, u.ID, p.Email, p.DisplayName, now); err != nil {
		return err
	}
	u.Email, u.DisplayName, u.SyncedAt = p.Email, p.DisplayName, &now
	return nil
}

// Welcome gives the user a new random ntfy password and emails it with the server URL, app links,
// and a subscribe link per default topic. Older passwords fail. A welcome that does not complete
// stays owed, so the next sync round retries it.
func (s *Service) Welcome(ctx context.Context, username string) error {
	_, err := s.welcome(ctx, username, false)
	return err
}

// welcome sends the welcome, or with owedOnly, sends it only if one is still owed. It reports
// whether an email was sent.
//
// The owed marker is written before the password changes, and the success stamp only after the
// email is accepted, so a crash or a failure anywhere in between leaves the welcome owed. The
// bookkeeping ignores ctx's cancellation: a client that hangs up mid-send must not leave a
// password nobody received and no welcome owed. Welcomes for one user run one at a time, so the
// last email sent always carries the password ntfy holds.
func (s *Service) welcome(ctx context.Context, username string, owedOnly bool) (bool, error) {
	unlock := s.welcoming.lock(username)
	defer unlock()
	// Read under the lock: an overlapping welcome may have just sent one.
	u, err := s.user(ctx, username)
	if err != nil {
		return false, err
	}
	if owedOnly && u.WelcomedAt != nil {
		return false, nil
	}
	book := context.WithoutCancel(ctx)
	if err := s.store.SetUserWelcomed(book, u.ID, nil); err != nil {
		return false, err
	}
	if err := s.sendWelcome(ctx, u); err != nil {
		s.store.Audit(book, username, "welcome_failed", map[string]any{"error": err.Error()})
		return false, err
	}
	now := time.Now()
	if err := s.store.SetUserWelcomed(book, u.ID, &now); err != nil {
		return false, err
	}
	s.store.Audit(book, username, "welcome_sent", map[string]any{"email": u.Email})
	return true, nil
}

func (s *Service) sendWelcome(ctx context.Context, u *model.User) error {
	if u.Email == "" {
		return ErrNoEmail
	}
	if !u.Enabled() {
		return ErrUserDisabled
	}
	password, err := s.SetNtfyPassword(ctx, u.Username)
	if err != nil {
		return err
	}
	h := s.DefaultHandoff(u.Username)
	w := mail.Welcome{Username: u.Username, DisplayName: u.DisplayName, Password: password, ServerURL: h.Server}
	for _, l := range h.Links {
		w.Topics = append(w.Topics, mail.TopicLink{Topic: l.Topic, URL: l.URL})
	}
	msg, err := mail.RenderWelcome(w)
	if err != nil {
		return err
	}
	msg.To = u.Email
	if err := s.mail.Send(ctx, msg); err != nil {
		return fmt.Errorf("send welcome email: %w", err)
	}
	return nil
}

// keyedMutex is a mutex per key. A key's entry lives only while someone holds or waits for it.
// The zero value is ready to use.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	sync.Mutex
	refs int
}

// lock locks key and returns its unlock.
func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l := k.locks[key]
	if l == nil {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()
	l.Lock()
	return func() {
		l.Unlock()
		k.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
