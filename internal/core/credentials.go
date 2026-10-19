package core

// A user's ntfy password exists only in the welcome email. Nothing else in the shim knows or sets
// it: an account is created with a password nobody knows, a reset recreates it the same way, and
// both end here, where the welcome replaces the password and emails the new one. The welcome
// counts as owed (welcomed_at empty) from the moment the password is unknown until the mail server
// accepts the message, so a failure or crash anywhere between is retried by the next sync round.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/mail"
	"github.com/babraham123/ntfy-idp-push/internal/model"
	"github.com/babraham123/ntfy-idp-push/internal/ntfy"
	"github.com/babraham123/ntfy-idp-push/internal/token"
)

// Welcome gives the user a new random ntfy password and emails it with the server URL, app links
// and a subscribe link per default topic. Older passwords fail; apps already signed in keep their
// tokens. A welcome that does not complete stays owed, so the next sync round retries it.
func (s *Service) Welcome(ctx context.Context, username string) error {
	_, err := s.welcome(ctx, s.ntfy().Accounts(), username, false)
	return err
}

// passwordLost records that nobody knows u's ntfy password any more, so a welcome is owed. It is
// written before whatever made the password unknown is committed, so a crash leaves the welcome
// owed rather than a user locked out.
func (s *Service) passwordLost(ctx context.Context, u *model.User) error {
	return s.store.SetUserWelcomed(ctx, u.ID, nil)
}

// welcome sends the welcome, or with owedOnly, sends it only if one is still owed. It reports
// whether an email was sent.
//
// The owed marker is written before the password changes, and the success stamp only after the
// email is accepted. The bookkeeping ignores ctx's cancellation: a client that hangs up mid-send
// must not leave a password nobody received and no welcome owed. Welcomes for one user run one at
// a time, so the last email sent always carries the password ntfy holds.
func (s *Service) welcome(ctx context.Context, acc *ntfy.Accounts, username string, owedOnly bool) (bool, error) {
	unlock := s.welcoming.lock(username)
	defer unlock()
	// Read under the lock: an overlapping welcome may have just sent one.
	u, err := s.user(ctx, username)
	if err != nil {
		return false, err
	}
	if owedOnly && u.WelcomedAt != nil {
		return false, nil
	}
	book := context.WithoutCancel(ctx)
	if err := s.passwordLost(book, u); err != nil {
		return false, err
	}
	if err := s.sendWelcome(ctx, acc, u); err != nil {
		s.store.Audit(book, username, "welcome_failed", map[string]any{"error": err.Error()})
		return false, err
	}
	now := time.Now()
	if err := s.store.SetUserWelcomed(book, u.ID, &now); err != nil {
		return false, err
	}
	s.store.Audit(book, username, "welcome_sent", map[string]any{"email": u.Email})
	return true, nil
}

// sendWelcome replaces u's ntfy password and emails the new one. The account is created if it is
// gone; its grants are provision's business.
func (s *Service) sendWelcome(ctx context.Context, acc *ntfy.Accounts, u *model.User) error {
	if u.Email == "" {
		return ErrNoEmail
	}
	if !u.Enabled() {
		return ErrUserDisabled
	}
	if err := acc.Ensure(ctx, u.Username); err != nil {
		return err
	}
	password := token.Random(18)
	if err := s.ntfy().ChangePassword(ctx, u.Username, password); err != nil {
		return err
	}
	s.store.Audit(ctx, u.Username, "ntfy_password_set", nil)
	w := mail.Welcome{Username: u.Username, DisplayName: u.DisplayName, Password: password, ServerURL: s.Config().NtfyBaseURL}
	for _, l := range s.defaultTopicLinks(u.Username) {
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

// keyedMutex is a mutex per key. A key's entry lives only while someone holds or waits for it.
// The zero value is ready to use.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	sync.Mutex
	refs int
}

// lock locks key and returns its unlock.
func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l := k.locks[key]
	if l == nil {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()
	l.Lock()
	return func() {
		l.Unlock()
		k.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
