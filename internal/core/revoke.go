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
	"github.com/babraham123/ntfy-idp-push/internal/store"
)

// RevokeDevice cuts off a phone's topic grant and (if resetNtfyUser) all user ntfy tokens. force
// skips checking for foreign ntfy grants.
func (s *Service) RevokeDevice(ctx context.Context, deviceID string, resetNtfyUser, force bool, actor string) error {
	d, err := s.store.Device(ctx, deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrUnknownDevice
	} else if err != nil {
		return err
	}
	return s.revoke(ctx, d, resetNtfyUser, force, actor)
}

// RevokeOwned is RevokeDevice on behalf of the device's owner, who may not force a reset.
func (s *Service) RevokeOwned(ctx context.Context, username, deviceID string, resetNtfyUser bool) error {
	d, err := s.ownedDevice(ctx, username, deviceID)
	if err != nil {
		return err
	}
	return s.revoke(ctx, d, resetNtfyUser, false, username)
}

// user is the user named username; a missing one is ErrUnknownUser.
func (s *Service) user(ctx context.Context, username string) (*model.User, error) {
	u, err := s.store.UserByName(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnknownUser
	}
	return u, err
}

func (s *Service) revoke(ctx context.Context, d *model.Device, resetNtfyUser, force bool, actor string) error {
	if resetNtfyUser {
		// Before revoking anything, so a refusal leaves the device intact.
		if err := s.requestReset(ctx, d.Username, force); err != nil {
			return err
		}
	}
	if d.RevokedAt == nil {
		if err := s.store.RevokeDevice(ctx, d.ID, time.Now()); err != nil {
			return err
		}
		s.store.Audit(ctx, d.Username, "device_revoked", map[string]any{"device": d.ID, "by": actor, "reset_ntfy_user": resetNtfyUser})
	}
	if err := s.denyPending(ctx, store.ChallengeFilter{DeviceID: d.ID}); err != nil {
		return err
	}
	if err := s.revokeDeviceGrant(ctx, d); err != nil {
		return fmt.Errorf("device revoked but its ntfy grant was not removed; re-run to retry: %w", err)
	}
	if resetNtfyUser {
		if err := s.finishReset(ctx, d.Username); err != nil {
			return fmt.Errorf("device revoked but the ntfy user was not reset; re-run to retry: %w", err)
		}
	}
	return s.store.DeleteDevice(ctx, d.ID)
}

// ResetNtfyUser deletes and recreates the ntfy user to invalidate all its tokens (since ntfy lacks
// targeted token revocation).
func (s *Service) ResetNtfyUser(ctx context.Context, username string, force bool) error {
	if err := s.requestReset(ctx, username, force); err != nil {
		return err
	}
	return s.finishReset(ctx, username)
}

// requestReset validates (unless forced) that no foreign grants exist, then records the reset as
// pending.
func (s *Service) requestReset(ctx context.Context, username string, force bool) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	if !force {
		if err := s.checkForeignGrants(ctx, u); err != nil {
			return err
		}
	}
	return s.store.SetNtfyResetPending(ctx, username, true)
}

// finishReset carries out a requested reset and clears it.
func (s *Service) finishReset(ctx context.Context, username string) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	granted, err := s.convergeNtfyAccount(ctx, u, true)
	if err != nil {
		return err
	}
	// The recreated account has a password nobody knows, so the user needs new credentials. The
	// welcome is owed before the reset is cleared, so a crash between the two leaves one of them
	// pending.
	if err := s.store.SetUserWelcomed(ctx, u.ID, nil); err != nil {
		return err
	}
	if err := s.store.SetNtfyResetPending(ctx, username, false); err != nil {
		return err
	}
	s.store.Audit(ctx, username, "ntfy_user_reset", map[string]any{"devices": granted})
	// The reset is done either way; a failed welcome is audited and the next sync round retries.
	if err := s.Welcome(ctx, username); err != nil {
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

// DeleteUser revokes every device and removes the user, and the ntfy user unless keepNtfy.
func (s *Service) DeleteUser(ctx context.Context, username string, keepNtfy bool) error {
	u, err := s.user(ctx, username)
	if err != nil {
		return err
	}
	devs, err := s.store.Devices(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if err := s.RevokeDevice(ctx, d.ID, false, false, "user_delete"); err != nil {
			return err
		}
	}
	if !keepNtfy {
		if err := s.deleteNtfyAccount(ctx, username); err != nil {
			return err
		}
	}
	if err := s.store.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	s.store.Audit(ctx, username, "user_deleted", map[string]any{"keep_ntfy_user": keepNtfy})
	return nil
}

// Reconcile finishes pending revocations and ntfy user resets independently.
func (s *Service) Reconcile(ctx context.Context) error {
	revoked, err := s.store.RevokedDevices(ctx)
	if err != nil {
		return err
	}
	errs := []error{s.removeDevices(ctx, revoked)}
	resets, err := s.store.PendingNtfyResets(ctx)
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
