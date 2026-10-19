package core

// Revocation is a resumable state machine since ntfy may be unreachable. Local passes (revoked_at,
// passkey deletion, login denials) happen first to block approvals. Resets are recorded before
// failure-prone steps. Device rows are deleted last to allow retrying ntfy calls.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

// Revocation says how a device is revoked: by whom, and whether its owner's ntfy user is reset so
// that every app signed in as the user is cut off too. ForceReset resets even an ntfy user that
// holds grants the shim did not make, which the reset drops.
type Revocation struct {
	Actor         string
	ResetNtfyUser bool
	ForceReset    bool
}

// RevokeDevice cuts off a phone's topic grant, and with r.ResetNtfyUser every token of its owner.
func (s *Service) RevokeDevice(ctx context.Context, deviceID string, r Revocation) error {
	d, err := s.store.Device(ctx, deviceID)
	if err != nil {
		return notFound(err, ErrUnknownDevice)
	}
	return s.revoke(ctx, s.ntfy().Accounts(), d, r)
}

// RevokeOwned is RevokeDevice on behalf of the device's owner, who may not force a reset.
func (s *Service) RevokeOwned(ctx context.Context, username, deviceID string, resetNtfyUser bool) error {
	d, err := s.ownedDevice(ctx, username, deviceID)
	if err != nil {
		return err
	}
	return s.revoke(ctx, s.ntfy().Accounts(), d, Revocation{Actor: username, ResetNtfyUser: resetNtfyUser})
}

// user is the user named username; a missing one is ErrUnknownUser.
func (s *Service) user(ctx context.Context, username string) (*model.User, error) {
	return s.resolveUser(ctx, UserRef{Username: username})
}

func (s *Service) revoke(ctx context.Context, acc *ntfy.Accounts, d *model.Device, r Revocation) error {
	if r.ResetNtfyUser {
		// Before revoking anything, so a refusal leaves the device intact.
		if err := s.requestReset(ctx, acc, d.Username, r.ForceReset); err != nil {
			return err
		}
	}
	if d.RevokedAt == nil {
		if err := s.store.RevokeDevice(ctx, d.ID, time.Now()); err != nil {
			return err
		}
		s.store.Audit(ctx, d.Username, "device_revoked", map[string]any{"device": d.ID, "by": r.Actor, "reset_ntfy_user": r.ResetNtfyUser})
	}
	if err := s.denyPending(ctx, store.ChallengeFilter{DeviceID: d.ID}); err != nil {
		return err
	}
	if err := s.revokeDeviceGrant(ctx, d); err != nil {
		return fmt.Errorf("device revoked but its ntfy grant was not removed; re-run to retry: %w", err)
	}
	if r.ResetNtfyUser {
		if err := s.finishReset(ctx, acc, d.Username); err != nil {
			return fmt.Errorf("device revoked but the ntfy user was not reset; re-run to retry: %w", err)
		}
	}
	return s.store.DeleteDevice(ctx, d.ID)
}

// ResetNtfyUser deletes and recreates the ntfy user to invalidate all its tokens (since ntfy lacks
// targeted token revocation).
func (s *Service) ResetNtfyUser(ctx context.Context, username string, force bool) error {
	acc := s.ntfy().Accounts()
	if err := s.requestReset(ctx, acc, username, force); err != nil {
		return err
	}
	return s.finishReset(ctx, acc, username)
}

// requestReset validates (unless forced) that no foreign grants exist, then records the reset as
// pending.
func (s *Service) requestReset(ctx context.Context, acc *ntfy.Accounts, username string, force bool) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	if !force {
		if err := s.checkForeignGrants(ctx, acc, u); err != nil {
			return err
		}
	}
	return s.store.SetNtfyResetPending(ctx, username, true)
}

// finishReset carries out a requested reset and clears it.
func (s *Service) finishReset(ctx context.Context, acc *ntfy.Accounts, username string) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	granted, err := s.convergeNtfyAccount(ctx, acc, u, true)
	if err != nil {
		return err
	}
	// The recreated account has a password nobody knows. The welcome is owed before the reset is
	// cleared, so a crash between the two leaves one of them pending.
	if err := s.passwordLost(ctx, u); err != nil {
		return err
	}
	if err := s.store.SetNtfyResetPending(ctx, username, false); err != nil {
		return err
	}
	s.store.Audit(ctx, username, "ntfy_user_reset", map[string]any{"devices": granted})
	// The reset is done either way; a failed welcome is audited and the next sync round retries.
	if _, err := s.welcome(ctx, acc, username, false); err != nil {
		s.Log.Warn("welcome after ntfy user reset", "user", username, "err", err)
	}
	return nil
}

// SetUserDisabled is an admin's disable or enable. The directory sync never changes it; it deletes
// the users the directory drops instead.
func (s *Service) SetUserDisabled(ctx context.Context, username string, disabled bool) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	if err := s.store.SetUserDisabled(ctx, u.ID, disabled); err != nil {
		return err
	}
	if disabled {
		if err := s.denyPending(ctx, store.ChallengeFilter{Username: u.Username}); err != nil {
			return err
		}
	}
	ev := "user_enabled"
	if disabled {
		ev = "user_disabled"
	}
	s.store.Audit(ctx, u.Username, ev, nil)
	return nil
}

// DeleteUser revokes every device and removes the user from the shim and from ntfy.
func (s *Service) DeleteUser(ctx context.Context, username string) error {
	return s.deleteUser(ctx, s.ntfy().Accounts(), username, false)
}

// ForgetUser is DeleteUser without touching ntfy: the ntfy user stays, without its device grants.
func (s *Service) ForgetUser(ctx context.Context, username string) error {
	return s.deleteUser(ctx, s.ntfy().Accounts(), username, true)
}

func (s *Service) deleteUser(ctx context.Context, acc *ntfy.Accounts, username string, keepNtfy bool) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	devs, err := s.store.Devices(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if err := s.revoke(ctx, acc, &d, Revocation{Actor: "user_delete"}); err != nil {
			return err
		}
	}
	if !keepNtfy {
		if err := acc.Delete(ctx, username); err != nil {
			return err
		}
	}
	if err := s.store.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	s.store.Audit(ctx, username, "user_deleted", map[string]any{"keep_ntfy_user": keepNtfy})
	return nil
}

// reconcile finishes pending revocations and ntfy user resets independently.
func (s *Service) reconcile(ctx context.Context) error {
	revoked, err := s.store.RevokedDevices(ctx)
	if err != nil {
		return err
	}
	errs := []error{s.removeDevices(ctx, revoked)}
	resets, err := s.store.PendingNtfyResets(ctx)
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	acc := s.ntfy().Accounts()
	for _, u := range resets {
		// The foreign-grant check passed, or was forced, when the reset was requested.
		if err := s.finishReset(ctx, acc, u); err != nil {
			errs = append(errs, fmt.Errorf("reset ntfy user %q: %w", u, err))
		}
	}
	return errors.Join(errs...)
}

// removeDevices removes each device, continuing past failures, which stay for the next run.
func (s *Service) removeDevices(ctx context.Context, devs []model.Device) error {
	var errs []error
	for _, d := range devs {
		if err := s.removeDevice(ctx, &d); err != nil {
			errs = append(errs, fmt.Errorf("remove device %s: %w", d.ID, err))
			continue
		}
		s.store.Audit(ctx, d.Username, "device_purged", map[string]any{"device": d.ID, "revoked": d.RevokedAt != nil})
	}
	return errors.Join(errs...)
}

// removeDevice drops the device's topic grant, then its row.
func (s *Service) removeDevice(ctx context.Context, d *model.Device) error {
	if err := s.revokeDeviceGrant(ctx, d); err != nil {
		return err
	}
	return s.store.DeleteDevice(ctx, d.ID)
}
