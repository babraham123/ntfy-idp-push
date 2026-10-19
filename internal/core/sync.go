package core

// The directory controls who has an ntfy account. Sync converges the store and ntfy on the directory
// every round. Welcome emails the user their credentials. The ntfy password exists only in the email,
// so every path that invalidates the password (a new account, a reset) ends in Welcome.
// The next sync round retries failed welcomes.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/mail"
	"github.com/babraham123/ntfy-idp-push/internal/model"
)

// SyncCounts is what one sync round changed.
type SyncCounts struct {
	Created, Welcomed, Disabled, Enabled, Updated int
}

// Sync runs one directory sync round. A directory that fails or lists nobody skips the round and
// changes nothing, since disabling everyone on a broken directory locks everyone out. Users
// are never deleted: users absent from the directory or marked disabled are disabled. They are
// enabled once listed and not disabled, unless an admin disabled them. A failure for one user
// does not stop the round; every failure is logged, and they are returned together.
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
		listed[p.Username] = true
		u := known[p.Username]
		if u == nil {
			if p.Disabled {
				continue
			}
			created, welcomed, err := s.adopt(ctx, p, now)
			if created != nil {
				n.Created++
			}
			if welcomed {
				n.Welcomed++
			}
			if err != nil {
				fail(p.Username, err)
			}
			continue
		}
		if u.Email != p.Email || u.DisplayName != p.DisplayName {
			n.Updated++
		}
		if err := s.recordProfile(ctx, u, p, now); err != nil {
			fail(p.Username, err)
			continue
		}
		switch {
		case p.Disabled && u.Enabled():
			if err := s.setDisabled(ctx, u, true, true); err != nil {
				fail(p.Username, err)
				continue
			}
			n.Disabled++
		case !p.Disabled && !u.Enabled() && u.DisabledBySync:
			if err := s.setDisabled(ctx, u, false, true); err != nil {
				fail(p.Username, err)
				continue
			}
			u.DisabledAt = nil
			n.Enabled++
		}
		if u.Enabled() && u.WelcomedAt == nil && u.Email != "" {
			if err := s.Welcome(ctx, u.Username); err != nil {
				fail(p.Username, err)
				continue
			}
			n.Welcomed++
		}
	}

	for i := range users {
		u := &users[i]
		if listed[u.Username] || !u.Enabled() {
			continue
		}
		if err := s.setDisabled(ctx, u, true, true); err != nil {
			fail(u.Username, err)
			continue
		}
		n.Disabled++
	}

	s.store.Audit(ctx, "", "sync", map[string]any{
		"created": n.Created, "welcomed": n.Welcomed, "disabled": n.Disabled, "enabled": n.Enabled,
		"updated": n.Updated, "failed": len(errs),
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
		u, _, err := s.adopt(ctx, p, time.Now())
		return u, err
	}
	return nil, ErrNotInDirectory
}

// adopt provisions p's account, records p's profile and, unless the user was welcomed before,
// sends the welcome. A user is returned once provisioning succeeded, even if the welcome failed.
func (s *Service) adopt(ctx context.Context, p directory.Person, now time.Time) (*model.User, bool, error) {
	u, err := s.Provision(ctx, p.Username)
	if err != nil {
		return nil, false, err
	}
	if err := s.recordProfile(ctx, u, p, now); err != nil {
		return u, false, err
	}
	if u.WelcomedAt != nil {
		return u, false, nil
	}
	if p.Email == "" {
		return u, false, ErrNoEmail
	}
	if err := s.Welcome(ctx, u.Username); err != nil {
		return u, false, err
	}
	return u, true, nil
}

func (s *Service) recordProfile(ctx context.Context, u *model.User, p directory.Person, now time.Time) error {
	if err := s.store.SetUserProfile(ctx, u.ID, p.Email, p.DisplayName, now); err != nil {
		return err
	}
	u.Email, u.DisplayName, u.SyncedAt = p.Email, p.DisplayName, &now
	return nil
}

// Welcome gives the user a new random ntfy password and emails it with the server URL, app links,
// and a subscribe link per default topic. Older passwords fail. Any failure after the
// user is found is audited and marks the welcome as owed, so the next sync round retries it.
func (s *Service) Welcome(ctx context.Context, username string) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	if err := s.welcome(ctx, u); err != nil {
		s.store.Audit(ctx, username, "welcome_failed", map[string]any{"error": err.Error()})
		if err := s.store.SetUserWelcomed(ctx, u.ID, nil); err != nil {
			s.Log.Error("welcome: mark as owed", "user", username, "err", err)
		}
		return err
	}
	now := time.Now()
	if err := s.store.SetUserWelcomed(ctx, u.ID, &now); err != nil {
		return err
	}
	s.store.Audit(ctx, username, "welcome_sent", map[string]any{"email": u.Email})
	return nil
}

func (s *Service) welcome(ctx context.Context, u *model.User) error {
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
