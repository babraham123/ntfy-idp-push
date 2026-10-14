// Package challenge tracks pending logins and wakes the blocked Duo auth call when one is decided.
package challenge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/store"
)

var (
	ErrGone     = errors.New("challenge already decided or expired")
	ErrBadToken = errors.New("invalid deny token")
)

// pollInterval bounds how long a decision made by another process (the CLI) takes to be seen.
const pollInterval = time.Second

type Manager struct {
	st *store.Store
	// OnDecided runs once per challenge after it leaves pending (e.g. to delete the push).
	OnDecided func(c *store.Challenge)

	mu      sync.Mutex
	waiters map[string]chan struct{}
}

func New(st *store.Store) *Manager {
	return &Manager{st: st, waiters: map[string]chan struct{}{}}
}

func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

type Params struct {
	Username, DeviceID, IPAddr, TargetURL, DisplayUsername string
	TTL                                                    time.Duration
}

// Create stores a pending challenge and returns it with the plaintext deny token.
func (m *Manager) Create(ctx context.Context, p Params) (*store.Challenge, string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	denyToken := RandomToken(32)
	now := time.Now()
	c := &store.Challenge{
		ID:              RandomToken(16),
		Username:        p.Username,
		DeviceID:        p.DeviceID,
		Nonce:           nonce,
		IPAddr:          p.IPAddr,
		TargetURL:       p.TargetURL,
		DisplayUsername: p.DisplayUsername,
		State:           store.StatePending,
		DenyTokenHash:   Hash(denyToken),
		CreatedAt:       now,
		ExpiresAt:       now.Add(p.TTL),
	}
	m.mu.Lock()
	m.waiters[c.ID] = make(chan struct{})
	m.mu.Unlock()
	if err := m.st.CreateChallenge(ctx, c); err != nil {
		m.release(c.ID)
		return nil, "", err
	}
	return c, denyToken, nil
}

func (m *Manager) release(id string) {
	m.mu.Lock()
	if ch, ok := m.waiters[id]; ok {
		close(ch)
		delete(m.waiters, id)
	}
	m.mu.Unlock()
}

// Decide moves a pending challenge to state, once.
func (m *Manager) Decide(ctx context.Context, id string, state store.ChallengeState) error {
	ok, err := m.st.DecideChallenge(ctx, id, state, time.Now())
	if err != nil {
		return err
	}
	if !ok {
		return ErrGone
	}
	m.decided(ctx, id)
	return nil
}

func (m *Manager) decided(ctx context.Context, id string) {
	m.release(id)
	if m.OnDecided != nil {
		if c, err := m.st.Challenge(ctx, id); err == nil {
			m.OnDecided(c)
		}
	}
}

// Deny denies with the token from the push's Deny action.
func (m *Manager) Deny(ctx context.Context, id, token string) error {
	c, err := m.st.Challenge(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrGone
	} else if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(c.DenyTokenHash, Hash(token)) != 1 {
		return ErrBadToken
	}
	return m.Decide(ctx, id, store.StateDeny)
}

// Wait blocks until the challenge is decided, expires, or ctx ends, and returns the final state.
// Expiry and cancellation both resolve to timeout.
func (m *Manager) Wait(ctx context.Context, c *store.Challenge) (store.ChallengeState, error) {
	m.mu.Lock()
	ch := m.waiters[c.ID]
	m.mu.Unlock()
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
		cur, err := m.st.Challenge(bg, c.ID)
		if err != nil {
			return store.StateDeny, err
		}
		if cur.State != store.StatePending {
			m.release(c.ID)
			return cur.State, nil
		}
		if ctx.Err() != nil || !time.Now().Before(c.ExpiresAt) {
			if ok, err := m.st.DecideChallenge(bg, c.ID, store.StateTimeout, time.Now()); err != nil {
				return store.StateDeny, err
			} else if ok {
				m.decided(bg, c.ID)
				return store.StateTimeout, nil
			}
			// Lost a race with a concurrent decision; loop to read it.
			continue
		}
	}
}
