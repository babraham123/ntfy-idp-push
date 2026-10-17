package core

import (
	"context"

	"github.com/babraham123/ntfy-idp-push/internal/model"
)

// UserSummary is a user with the number of its devices that can receive logins.
type UserSummary struct {
	model.User
	ActiveDevices int
}

// Users lists every user, by username.
func (s *Service) Users(ctx context.Context) ([]UserSummary, error) {
	users, err := s.store.Users(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserSummary, 0, len(users))
	for _, u := range users {
		devs, err := s.activeDevices(ctx, &u)
		if err != nil {
			return nil, err
		}
		out = append(out, UserSummary{User: u, ActiveDevices: len(devs)})
	}
	return out, nil
}

// DevicesOf returns the user and all their devices (MRU first); an unknown user is ErrUnknownUser.
func (s *Service) DevicesOf(ctx context.Context, username string) (*model.User, []model.Device, error) {
	u, err := s.resolveUser(ctx, UserRef{Username: username})
	if err != nil {
		return nil, nil, err
	}
	devs, err := s.store.Devices(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}
	return u, devs, nil
}
