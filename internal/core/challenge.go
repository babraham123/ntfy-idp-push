package core

// A challenge is one pending login: created by Authenticate, decided once (allow, deny, fraud or
// timeout) by whichever comes first of the phone, the CLI, a revoke or disable, or expiry, and
// waited on by the blocked auth call. Deciding wakes the waiter in this process and clears the push
// from the phone; a decision made by another process (the CLI) is seen by polling.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/url"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/store"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

var (
	ErrGone     = errors.New("challenge already decided or expired")
	ErrBadToken = errors.New("invalid deny token")
)

// pollInterval bounds how long a decision made by another process (the CLI) takes to be seen.
const pollInterval = time.Second

// createChallenge stores a pending challenge for r on device d and returns it with the plaintext
// deny token.
func (s *Service) createChallenge(ctx context.Context, d *store.Device, r AuthRequest) (*store.Challenge, string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	denyToken := token.Random(32)
	now := time.Now()
	c := &store.Challenge{
		ID:              token.Random(16),
		Username:        d.Username,
		DeviceID:        d.ID,
		Nonce:           nonce,
		IPAddr:          r.IPAddr,
		TargetURL:       r.TargetURL,
		DisplayUsername: r.DisplayUsername,
		State:           store.StatePending,
		DenyTokenHash:   token.Hash(denyToken),
		CreatedAt:       now,
		ExpiresAt:       now.Add(r.Timeout),
	}
	s.waitMu.Lock()
	s.waiters[c.ID] = make(chan struct{})
	s.waitMu.Unlock()
	if err := s.Store.CreateChallenge(ctx, c); err != nil {
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

// decide moves a pending challenge to state, once.
func (s *Service) decide(ctx context.Context, id string, state store.ChallengeState) error {
	ok, err := s.Store.DecideChallenge(ctx, id, state, time.Now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrGone
	}
	s.decided(ctx, id)
	return nil
}

// decided runs once per challenge after it leaves pending.
func (s *Service) decided(ctx context.Context, id string) {
	s.release(id)
	if c, err := s.Store.Challenge(ctx, id); err == nil {
		s.clearPush(c)
	}
}

// clearPush deletes the login push once its challenge is decided, so stale requests vanish.
func (s *Service) clearPush(c *store.Challenge) {
	d, err := s.Store.Device(context.Background(), c.DeviceID)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Ntfy.DeleteMessage(ctx, d.NtfyTopic, c.ID); err != nil {
		s.Log.Debug("clear push", "challenge", c.ID, "err", err)
	}
}

// wait blocks until the challenge is decided, expires, or ctx ends, and returns the final state.
// Expiry and cancellation both resolve to timeout.
func (s *Service) wait(ctx context.Context, c *store.Challenge) (store.ChallengeState, error) {
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
		cur, err := s.Store.Challenge(bg, c.ID)
		if err != nil {
			return store.StateDeny, err
		}
		if cur.State != store.StatePending {
			s.release(c.ID)
			return cur.State, nil
		}
		if ctx.Err() != nil || !time.Now().Before(c.ExpiresAt) {
			if ok, err := s.Store.DecideChallenge(bg, c.ID, store.StateTimeout, time.Now()); err != nil {
				return store.StateDeny, err
			} else if ok {
				s.decided(bg, c.ID)
				return store.StateTimeout, nil
			}
			// Lost a race with a concurrent decision; loop to read it.
			continue
		}
	}
}

// denyPending denies the pending challenges matching f, waking their blocked auth calls.
func (s *Service) denyPending(ctx context.Context, f store.ChallengeFilter) error {
	return s.decidePending(ctx, f, store.StateDeny)
}

func (s *Service) decidePending(ctx context.Context, f store.ChallengeFilter, state store.ChallengeState) error {
	ids, err := s.Store.PendingChallengeIDs(ctx, f)
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
func (s *Service) PendingChallenge(ctx context.Context, id string) (*store.Challenge, error) {
	c, err := s.Store.Challenge(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrGone
	} else if err != nil {
		return nil, err
	}
	if c.State != store.StatePending || !time.Now().Before(c.ExpiresAt) {
		return nil, ErrGone
	}
	return c, nil
}

// Deny denies with the token from the push's Deny action.
func (s *Service) Deny(ctx context.Context, id, denyToken string) error {
	c, err := s.Store.Challenge(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrGone
	} else if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(c.DenyTokenHash, token.Hash(denyToken)) != 1 {
		return ErrBadToken
	}
	return s.decide(ctx, id, store.StateDeny)
}

// ReportFraud decides a pending challenge as fraud ("This wasn't me") and audits the reporter's ip.
func (s *Service) ReportFraud(ctx context.Context, id, ip string) error {
	c, err := s.PendingChallenge(ctx, id)
	if err != nil {
		return err
	}
	if err := s.decide(ctx, id, store.StateFraud); err != nil {
		return err
	}
	s.Store.Audit(ctx, c.Username, "fraud_reported", map[string]any{"challenge": id, "ip": ip})
	return nil
}

// Describe is the human summary shown in the push and on the approve page.
func Describe(c *store.Challenge) string {
	msg := c.DisplayUsername
	if c.IPAddr != "" {
		msg += " from " + c.IPAddr
	}
	if u, err := url.Parse(c.TargetURL); err == nil && u.Host != "" {
		msg += " to " + u.Host
	}
	return msg
}
