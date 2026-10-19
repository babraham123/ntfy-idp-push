package core

// A challenge is a pending login created by Authenticate and decided exactly once. Decisions wake
// local blocked auth calls and clear phone pushes; cross-process decisions are detected via
// polling.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/url"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

// pollInterval bounds how long a decision made by another process (the CLI) takes to be seen.
const pollInterval = time.Second

// createChallenge stores a pending challenge for r on device d and returns it with the plaintext
// deny token.
func (s *Service) createChallenge(ctx context.Context, d *model.Device, r AuthRequest) (*model.Challenge, string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	denyToken := token.Random(32)
	now := time.Now()
	c := &model.Challenge{
		ID:              token.Random(16),
		Username:        d.Username,
		DeviceID:        d.ID,
		Nonce:           nonce,
		IPAddr:          r.IPAddr,
		TargetURL:       r.TargetURL,
		DisplayUsername: r.DisplayUsername,
		State:           model.StatePending,
		DenyTokenHash:   token.Hash(denyToken),
		CreatedAt:       now,
		ExpiresAt:       now.Add(r.Timeout),
	}
	s.waitMu.Lock()
	s.waiters[c.ID] = make(chan struct{})
	s.waitMu.Unlock()
	if err := s.store.CreateChallenge(ctx, c); err != nil {
		s.release(c.ID)
		return nil, "", err
	}
	return c, denyToken, nil
}

// release wakes the auth call waiting on challenge id, if it is in this process.
func (s *Service) release(id string) {
	s.waitMu.Lock()
	if ch, ok := s.waiters[id]; ok {
		close(ch)
		delete(s.waiters, id)
	}
	s.waitMu.Unlock()
}

// decide moves a pending challenge to state, once. An allow is refused with ErrUserDisabled or
// ErrDeviceRevoked when the login is no longer eligible; the store checks that in the deciding
// statement, so a concurrent revoke or disable cannot slip through.
func (s *Service) decide(ctx context.Context, id string, state model.ChallengeState) error {
	ok, refusal, err := s.store.DecideChallenge(ctx, id, state, time.Now())
	switch {
	case err != nil:
		return err
	case refusal == store.UserDisabled:
		return ErrUserDisabled
	case refusal == store.DeviceInactive:
		return ErrDeviceRevoked
	case !ok:
		return ErrGone
	}
	s.decided(ctx, id)
	return nil
}

// decided runs once per challenge after it leaves pending.
func (s *Service) decided(ctx context.Context, id string) {
	s.release(id)
	if c, err := s.store.Challenge(ctx, id); err == nil {
		s.clearPush(c)
	}
}

// clearPush deletes the login push once its challenge is decided, so stale requests vanish.
func (s *Service) clearPush(c *model.Challenge) {
	d, err := s.store.Device(context.Background(), c.DeviceID)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.ntfy().ClearLogin(ctx, d.NtfyTopic, c.ID); err != nil {
		s.Log.Debug("clear push", "challenge", c.ID, "err", err)
	}
}

// wait blocks until the challenge decides, expires, or ctx ends (returning timeout for
// expiry/cancellation).
func (s *Service) wait(ctx context.Context, c *model.Challenge) (model.ChallengeState, error) {
	s.waitMu.Lock()
	ch := s.waiters[c.ID]
	s.waitMu.Unlock()
	if ch == nil {
		ch = make(chan struct{})
	}
	deadline := time.NewTimer(time.Until(c.ExpiresAt))
	defer deadline.Stop()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ch:
		case <-tick.C:
		case <-deadline.C:
		case <-ctx.Done():
		}
		// The request context may be gone; finish the bookkeeping regardless.
		bg := context.WithoutCancel(ctx)
		cur, err := s.store.Challenge(bg, c.ID)
		if err != nil {
			return model.StateDeny, err
		}
		if cur.State != model.StatePending {
			s.release(c.ID)
			return cur.State, nil
		}
		if ctx.Err() != nil || !time.Now().Before(c.ExpiresAt) {
			err := s.decide(bg, c.ID, model.StateTimeout)
			if errors.Is(err, ErrGone) {
				// Lost a race with a concurrent decision; loop to read it.
				continue
			}
			if err != nil {
				return model.StateDeny, err
			}
			return model.StateTimeout, nil
		}
	}
}

// denyPending denies the pending challenges matching f, waking their blocked auth calls.
func (s *Service) denyPending(ctx context.Context, f store.ChallengeFilter) error {
	return s.decidePending(ctx, f, model.StateDeny)
}

func (s *Service) decidePending(ctx context.Context, f store.ChallengeFilter, state model.ChallengeState) error {
	ids, err := s.store.PendingChallengeIDs(ctx, f)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.decide(ctx, id, state); err != nil && !errors.Is(err, ErrGone) {
			return err
		}
	}
	return nil
}

// PendingChallenge returns the challenge if it can still be decided.
func (s *Service) PendingChallenge(ctx context.Context, id string) (*model.Challenge, error) {
	c, err := s.store.Challenge(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrGone
	} else if err != nil {
		return nil, err
	}
	if !c.Decidable(time.Now()) {
		return nil, ErrGone
	}
	return c, nil
}

// Deny denies with the token from the push's Deny action.
func (s *Service) Deny(ctx context.Context, id, denyToken string) error {
	c, err := s.store.Challenge(ctx, id)
	if err != nil {
		return notFound(err, ErrGone)
	}
	if subtle.ConstantTimeCompare(c.DenyTokenHash, token.Hash(denyToken)) != 1 {
		return ErrBadToken
	}
	return s.decide(ctx, id, model.StateDeny)
}

// ReportFraud decides a pending challenge as fraud ("This wasn't me") and audits the reporter's ip.
func (s *Service) ReportFraud(ctx context.Context, id, ip string) error {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return err
	}
	if err := s.decide(ctx, id, model.StateFraud); err != nil {
		return err
	}
	s.store.Audit(ctx, c.Username, "fraud_reported", map[string]any{"challenge": id, "ip": ip})
	return nil
}

// Describe is the human summary shown in the push and on the approve page.
func Describe(c *model.Challenge) string {
	msg := c.DisplayUsername
	if c.IPAddr != "" {
		msg += " from " + c.IPAddr
	}
	if u, err := url.Parse(c.TargetURL); err == nil && u.Host != "" {
		msg += " to " + u.Host
	}
	return msg
}
