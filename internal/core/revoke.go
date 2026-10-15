package core

// Revocation spans the local database and an ntfy server that may be unreachable, so it is a
// state machine persisted in the store and finished by whoever runs next: the same command re-run,
// or Reconcile from the purge job.
//
//	device: active ─revoke─▶ revoked_at set, row kept ─grant removed─▶ row deleted
//	user:   ntfy_reset_pending set ─ntfy user deleted, recreated, re-granted─▶ cleared
//
// A revoked row still present means its remote steps are pending; a set ntfy_reset_pending means
// the reset is. The rules that keep every interruption resumable:
//
//   - Local first: revoked_at, passkey deletion and denying pending logins precede any ntfy call,
//     so a revoked phone approves nothing even while ntfy is down.
//   - A requested reset is recorded before any step that can fail: Reconcile may delete the
//     revoked device row a manual retry would resume from.
//   - The device row is deleted last, so a failed ntfy call leaves something to retry from.
//   - A user or grant already missing in ntfy counts as removed, so every step is safe to repeat
//     and an interrupted reset resumes at recreation.
//   - Recreating the ntfy user ignores disabled_at. Disabling denies logins at preauth and auth;
//     it must not leave a reset stuck between deleting and recreating the account.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

// RevokeDevice cuts a phone off: its topic grant and, with resetNtfyUser, every ntfy token of the
// user. force skips the check that the ntfy user holds only grants the shim made.
func (s *Service) RevokeDevice(ctx context.Context, deviceID string, resetNtfyUser, force bool, actor string) error {
	d, err := s.Store.Device(ctx, deviceID)
	if err != nil {
		return err
	}
	if resetNtfyUser {
		// Before revoking anything, so a refusal leaves the device intact.
		if err := s.requestReset(ctx, d.Username, force); err != nil {
			return err
		}
	}
	if d.RevokedAt == nil {
		if err := s.Store.RevokeDevice(ctx, d.ID, time.Now()); err != nil {
			return err
		}
		s.Store.Audit(ctx, d.Username, "device_revoked", map[string]any{"device": d.ID, "by": actor, "reset_ntfy_user": resetNtfyUser})
	}
	if err := s.denyPending(ctx, store.ChallengeFilter{DeviceID: d.ID}); err != nil {
		return err
	}
	if err := s.Ntfy.ResetAccess(ctx, d.Username, d.NtfyTopic); err != nil {
		return fmt.Errorf("device revoked but its ntfy grant was not removed; re-run to retry: %w", err)
	}
	if resetNtfyUser {
		if err := s.finishReset(ctx, d.Username); err != nil {
			return fmt.Errorf("device revoked but the ntfy user was not reset; re-run to retry: %w", err)
		}
	}
	return s.Store.DeleteDevice(ctx, d.ID)
}

// ResetNtfyUser deletes and recreates the ntfy user, invalidating every token it has. ntfy has no
// admin endpoint to revoke another user's tokens, so this is the only way to cut a lost phone off.
func (s *Service) ResetNtfyUser(ctx context.Context, username string, force bool) error {
	if err := s.requestReset(ctx, username, force); err != nil {
		return err
	}
	return s.finishReset(ctx, username)
}

// requestReset refuses a reset that would drop grants the shim did not make (unless force), then
// records it as pending.
func (s *Service) requestReset(ctx context.Context, username string, force bool) error {
	u, err := s.Store.UserByName(ctx, username)
	if err != nil {
		return err
	}
	if !force {
		if err := s.checkResettable(ctx, u); err != nil {
			return err
		}
	}
	return s.Store.SetNtfyResetPending(ctx, username, true)
}

func (s *Service) checkResettable(ctx context.Context, u *store.User) error {
	known, err := s.knownGrants(ctx, u)
	if err != nil {
		return err
	}
	nu, err := s.Ntfy.User(ctx, u.Username)
	if err != nil || nu == nil {
		return err
	}
	for _, g := range nu.Grants {
		if _, ok := known[g.Topic]; !ok {
			return fmt.Errorf("%w (%s:%s)", ErrForeignGrants, g.Topic, g.Permission)
		}
	}
	return nil
}

func (s *Service) knownGrants(ctx context.Context, u *store.User) (map[string]string, error) {
	known := map[string]string{}
	for _, g := range u.Grants {
		known[g.Topic] = g.Permission
	}
	devs, err := s.Store.Devices(ctx, u.ID, false)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		known[d.NtfyTopic] = config.PermReadOnly
	}
	return known, nil
}

// finishReset carries out a requested reset and clears it.
func (s *Service) finishReset(ctx context.Context, username string) error {
	grants, err := s.enrollGrants(username)
	if err != nil {
		return err
	}
	u, err := s.Store.UserByName(ctx, username)
	if err != nil {
		return err
	}
	if err := s.Ntfy.DeleteUser(ctx, username); err != nil {
		return err
	}
	if err := s.applyNtfyAccount(ctx, u, grants); err != nil {
		return err
	}
	devs, err := s.Store.Devices(ctx, u.ID, false)
	if err != nil {
		return err
	}
	granted := 0
	for _, d := range devs {
		if d.RevokedAt != nil {
			continue
		}
		if err := s.Ntfy.AllowAccess(ctx, username, d.NtfyTopic, config.PermReadOnly); err != nil {
			return err
		}
		granted++
	}
	if err := s.Store.SetNtfyResetPending(ctx, username, false); err != nil {
		return err
	}
	s.Store.Audit(ctx, username, "ntfy_user_reset", map[string]any{"devices": granted})
	return nil
}

func (s *Service) SetUserDisabled(ctx context.Context, username string, disabled bool) error {
	u, err := s.Store.UserByName(ctx, username)
	if err != nil {
		return err
	}
	if err := s.Store.SetUserDisabled(ctx, u.ID, disabled); err != nil {
		return err
	}
	if disabled {
		if err := s.denyPending(ctx, store.ChallengeFilter{Username: username}); err != nil {
			return err
		}
	}
	ev := "user_enabled"
	if disabled {
		ev = "user_disabled"
	}
	s.Store.Audit(ctx, username, ev, nil)
	return nil
}

// DeleteUser revokes every device and removes the user, and the ntfy user unless keepNtfy.
func (s *Service) DeleteUser(ctx context.Context, username string, keepNtfy bool) error {
	u, err := s.Store.UserByName(ctx, username)
	if err != nil {
		return err
	}
	devs, err := s.Store.Devices(ctx, u.ID, false)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if err := s.RevokeDevice(ctx, d.ID, false, false, "user_delete"); err != nil {
			return err
		}
	}
	if !keepNtfy {
		if err := s.Ntfy.DeleteUser(ctx, username); err != nil {
			return err
		}
	}
	if err := s.Store.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	s.Store.Audit(ctx, username, "user_deleted", map[string]any{"keep_ntfy_user": keepNtfy})
	return nil
}

// Reconcile finishes every revocation and ntfy user reset a failed or interrupted call left
// pending. One failure does not stop the others.
func (s *Service) Reconcile(ctx context.Context) error {
	revoked, err := s.Store.RevokedDevices(ctx)
	if err != nil {
		return err
	}
	errs := []error{s.removeDevices(ctx, revoked)}
	resets, err := s.Store.PendingNtfyResets(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, u := range resets {
		// The foreign-grant check passed, or was forced, when the reset was requested.
		if err := s.finishReset(ctx, u); err != nil {
			errs = append(errs, fmt.Errorf("reset ntfy user %q: %w", u, err))
		}
	}
	return errors.Join(errs...)
}

// removeDevices removes each device, continuing past failures, which stay for the next run.
func (s *Service) removeDevices(ctx context.Context, devs []store.Device) error {
	var errs []error
	for _, d := range devs {
		if err := s.removeDevice(ctx, &d); err != nil {
			errs = append(errs, fmt.Errorf("remove device %s: %w", d.ID, err))
			continue
		}
		s.Store.Audit(ctx, d.Username, "device_purged", map[string]any{"device": d.ID, "revoked": d.RevokedAt != nil})
	}
	return errors.Join(errs...)
}

// removeDevice drops the device's topic grant, then its row.
func (s *Service) removeDevice(ctx context.Context, d *store.Device) error {
	if err := s.Ntfy.ResetAccess(ctx, d.Username, d.NtfyTopic); err != nil {
		return err
	}
	return s.Store.DeleteDevice(ctx, d.ID)
}
