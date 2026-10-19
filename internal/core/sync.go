package core

// The directory, when one is configured, controls who has an ntfy account. Sync converges the store
// and ntfy on the directory every round. Without one, ProvisionManual creates accounts. Either way a
// new account ends in the welcome (see credentials.go), and a round sends any welcome still owed.

import (
	"context"
	"errors"
	"fmt"
	netmail "net/mail"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
)

// SyncCounts is what one sync round changed.
type SyncCounts struct {
	Created, Welcomed, Deleted, Updated int
}

// Sync runs one directory sync round and reports what it changed; without a directory it refuses
// with ErrNoDirectory and changes nothing. A directory that fails skips the round and changes nothing, since deletes
// cannot be undone and a broken directory would delete everyone.
// The round first reconciles accounts: it creates listed people, records profiles, and deletes
// the users it manages that the directory no longer lists. Only then does it send owed welcomes, so
// a slow or failing mail server never holds up a deletion. A failure for one user does not stop
// the round; every failure is logged, and they are returned together.
func (s *Service) Sync(ctx context.Context) (SyncCounts, error) {
	var n SyncCounts
	if s.dir == nil {
		return n, ErrNoDirectory
	}
	people, err := s.dir.List(ctx)
	if err != nil {
		s.Log.Warn("directory sync skipped", "err", err)
		s.store.Audit(ctx, "", "sync_skipped", map[string]any{"error": err.Error()})
		return n, err
	}
	users, err := s.store.Users(ctx)
	if err != nil {
		return n, err
	}
	// One view of ntfy's users for the whole round.
	acc := s.ntfy().Accounts()
	known := make(map[string]*model.User, len(users))
	for i := range users {
		known[users[i].Username] = &users[i]
	}
	listed := make(map[string]bool, len(people))
	now := time.Now()
	var errs []error
	fail := func(username string, err error) {
		s.Log.Warn("directory sync", "user", username, "err", err)
		errs = append(errs, fmt.Errorf("sync %q: %w", username, err))
	}

	for _, p := range people {
		listed[p.Username] = true
		u := known[p.Username]
		if u == nil {
			u, err := s.adopt(ctx, acc, p, &now)
			if u != nil {
				n.Created++
			}
			if err != nil {
				fail(p.Username, err)
			}
			continue
		}
		changed := u.Email != p.Email || u.DisplayName != p.DisplayName
		if err := s.recordProfile(ctx, u, p, &now); err != nil {
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
		// The directory removes only users it manages: those a round has listed (SyncedAt set).
		// Someone provisioned by hand or through an enrollment link and never listed is the
		// admin's, so an empty or partial listing leaves them alone.
		if u.SyncedAt == nil {
			continue
		}
		if err := s.deleteUser(ctx, acc, u.Username, false); err != nil {
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
		sent, err := s.welcome(ctx, acc, u.Username, true)
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
	return n, errors.Join(errs...)
}

// ProvisionFromDirectory provisions a user the directory lists, records their directory profile,
// and sends the welcome they are owed. A name absent from the directory is refused, and so is
// every name when no directory is configured.
func (s *Service) ProvisionFromDirectory(ctx context.Context, username string) (*model.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	if s.dir == nil {
		return nil, ErrNoDirectory
	}
	people, err := s.dir.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		if p.Username == username {
			now := time.Now()
			return s.provisionAndWelcome(ctx, s.ntfy().Accounts(), p, &now)
		}
	}
	return nil, ErrNotInDirectory
}

// ProvisionManual provisions a user when no directory is configured, records email as their
// address, and sends the welcome they are owed. Running it again re-sends nothing; a different
// email replaces the recorded one without a new welcome (Welcome resends). The account is not
// marked as listed, so a directory configured later never deletes it. With a directory
// configured it is refused: the directory decides each user's email.
func (s *Service) ProvisionManual(ctx context.Context, username, email string) (*model.User, error) {
	if err := ValidUsername(username); err != nil {
		return nil, err
	}
	if s.dir != nil {
		return nil, ErrDirectoryConfigured
	}
	if a, err := netmail.ParseAddress(email); err != nil || a.Address != email {
		return nil, fmt.Errorf("%w: %q", ErrInvalidEmail, email)
	}
	return s.provisionAndWelcome(ctx, s.ntfy().Accounts(), directory.Person{Username: username, Email: email}, nil)
}

// provisionAndWelcome adopts p and sends the welcome if one is owed. A user is returned once
// provisioning succeeded, even if the rest failed.
func (s *Service) provisionAndWelcome(ctx context.Context, acc *ntfy.Accounts, p directory.Person, syncedAt *time.Time) (*model.User, error) {
	u, err := s.adopt(ctx, acc, p, syncedAt)
	if err != nil {
		return u, err
	}
	_, err = s.welcome(ctx, acc, p.Username, true)
	return u, err
}

// adopt provisions p's account and records p's profile, with syncedAt as recordProfile takes it.
// A user is returned once provisioning succeeded, even if recording the profile failed.
func (s *Service) adopt(ctx context.Context, acc *ntfy.Accounts, p directory.Person, syncedAt *time.Time) (*model.User, error) {
	u, err := s.provision(ctx, acc, p.Username)
	if err != nil {
		return nil, err
	}
	return u, s.recordProfile(ctx, u, p, syncedAt)
}

// recordProfile stores p's email and display name on u. syncedAt is when a directory round listed
// p, which makes the account one the directory manages; nil leaves that as it was.
func (s *Service) recordProfile(ctx context.Context, u *model.User, p directory.Person, syncedAt *time.Time) error {
	if err := s.store.SetUserProfile(ctx, u.ID, p.Email, p.DisplayName, syncedAt); err != nil {
		return err
	}
	u.Email, u.DisplayName = p.Email, p.DisplayName
	if syncedAt != nil {
		u.SyncedAt = syncedAt
	}
	return nil
}
