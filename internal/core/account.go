package core

// The shim wants each user's ntfy account to hold exactly the enroll-access grants expanded for
// the user plus read-only access to the push topic of every device that is not revoked. Every
// ntfy user and ACL call the shim makes goes through this file, so that rule is written once:
// Provision applies the enroll-access half, enrollment adds a device's grant, revocation removes
// it, and a reset recreates the account and converges it from scratch.

import (
	"context"
	"fmt"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

// enrollGrants is enroll-access expanded for username.
func (s *Service) enrollGrants(username string) ([]config.Grant, error) {
	cfg := s.Config()
	return config.ExpandAccess(cfg.Access, cfg.NtfyTopicPrefix, username)
}

// deviceGrants is the read-only grant each unrevoked device of a user should hold.
func deviceGrants(devs []store.Device) []config.Grant {
	var out []config.Grant
	for _, d := range devs {
		if d.RevokedAt == nil {
			out = append(out, config.Grant{Topic: d.NtfyTopic, Permission: config.PermReadOnly})
		}
	}
	return out
}

// applyNtfyAccount ensures the ntfy user exists with grants, ignoring user policy to allow
// restoring disabled accounts.
func (s *Service) applyNtfyAccount(ctx context.Context, u *store.User, grants []config.Grant) error {
	if err := s.ensureNtfyUser(ctx, u.Username); err != nil {
		return err
	}
	for _, g := range grants {
		if err := s.ntfy.AllowAccess(ctx, u.Username, g.Topic, g.Permission); err != nil {
			return err
		}
	}
	recorded := grants
	if !s.Config().EnrollAccessReconcile {
		// Keep remembering grants dropped from config so a later reconcile or reset can see them.
		recorded = mergeGrants(grants, u.Grants)
	} else {
		for _, old := range u.Grants {
			if !hasTopic(grants, old.Topic) {
				if err := s.ntfy.ResetAccess(ctx, u.Username, old.Topic); err != nil {
					return err
				}
			}
		}
	}
	if err := s.Store.SetUserGrants(ctx, u.ID, recorded); err != nil {
		return err
	}
	u.Grants = recorded
	return nil
}

// convergeNtfyAccount brings u's ntfy account to the intended state, recreating it first when
// recreate is set so that every token it had stops working. It returns how many device grants it
// made. The enroll-access expansion runs before anything is touched, so a refused name leaves ntfy
// as it was.
func (s *Service) convergeNtfyAccount(ctx context.Context, u *store.User, recreate bool) (int, error) {
	grants, err := s.enrollGrants(u.Username)
	if err != nil {
		return 0, err
	}
	devs, err := s.Store.Devices(ctx, u.ID)
	if err != nil {
		return 0, err
	}
	if recreate {
		if err := s.ntfy.DeleteUser(ctx, u.Username); err != nil {
			return 0, err
		}
	}
	if err := s.applyNtfyAccount(ctx, u, grants); err != nil {
		return 0, err
	}
	dg := deviceGrants(devs)
	for _, g := range dg {
		if err := s.ntfy.AllowAccess(ctx, u.Username, g.Topic, g.Permission); err != nil {
			return 0, err
		}
	}
	return len(dg), nil
}

// grantDevice gives the device's owner read-only access to its push topic.
func (s *Service) grantDevice(ctx context.Context, d *store.Device) error {
	return s.ntfy.AllowAccess(ctx, d.Username, d.NtfyTopic, config.PermReadOnly)
}

// revokeDeviceGrant removes the device's topic grant. A missing ntfy user or grant counts as
// removed.
func (s *Service) revokeDeviceGrant(ctx context.Context, d *store.Device) error {
	return s.ntfy.ResetAccess(ctx, d.Username, d.NtfyTopic)
}

func (s *Service) deleteNtfyAccount(ctx context.Context, username string) error {
	return s.ntfy.DeleteUser(ctx, username)
}

// checkForeignGrants refuses to reset an account that holds grants the shim did not make, since
// a reset would silently drop them.
func (s *Service) checkForeignGrants(ctx context.Context, u *store.User) error {
	known, err := s.knownTopics(ctx, u)
	if err != nil {
		return err
	}
	nu, err := s.ntfy.User(ctx, u.Username)
	if err != nil || nu == nil {
		return err
	}
	for _, g := range nu.Grants {
		if !known[g.Topic] {
			return fmt.Errorf("%w (%s:%s)", ErrForeignGrants, g.Topic, g.Permission)
		}
	}
	return nil
}

// knownTopics is every topic the shim may have granted u: the recorded enroll-access grants and
// the push topic of every device, revoked ones included, since a revoked device's grant may still
// be awaiting cleanup.
func (s *Service) knownTopics(ctx context.Context, u *store.User) (map[string]bool, error) {
	known := map[string]bool{}
	for _, g := range u.Grants {
		known[g.Topic] = true
	}
	devs, err := s.Store.Devices(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		known[d.NtfyTopic] = true
	}
	return known, nil
}

func (s *Service) ensureNtfyUser(ctx context.Context, username string) error {
	nu, err := s.ntfy.User(ctx, username)
	if err != nil {
		return err
	}
	if nu != nil {
		if nu.Role == "admin" {
			return fmt.Errorf("ntfy user %q is an admin; refusing to manage it", username)
		}
		return nil
	}
	// Nobody needs the password: the apps sign in with enrollment codes.
	return s.ntfy.AddUser(ctx, username, token.Random(32))
}

func mergeGrants(a, b []config.Grant) []config.Grant {
	out := append([]config.Grant{}, a...)
	for _, g := range b {
		if !hasTopic(out, g.Topic) {
			out = append(out, g)
		}
	}
	return out
}

func hasTopic(gs []config.Grant, topic string) bool {
	for _, g := range gs {
		if g.Topic == topic {
			return true
		}
	}
	return false
}
