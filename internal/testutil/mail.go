package testutil

import (
	"context"
	"slices"
	"sync"

	"github.com/babraham123/ntfy-idp-push/internal/mail"
)

var _ mail.Sender = (*FakeMail)(nil)

// FakeMail is a mail.Sender that records every message it accepts. The zero value is ready to use.
type FakeMail struct {
	mu   sync.Mutex
	sent []mail.Message
	err  error
}

func NewFakeMail() *FakeMail { return &FakeMail{} }

func (f *FakeMail) Send(ctx context.Context, m mail.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

// Fail makes every later Send return err without recording; nil restores delivery.
func (f *FakeMail) Fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// Sent returns the accepted messages in send order.
func (f *FakeMail) Sent() []mail.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sent)
}

// To returns the accepted messages addressed to addr, in send order.
func (f *FakeMail) To(addr string) []mail.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []mail.Message
	for _, m := range f.sent {
		if m.To == addr {
			out = append(out, m)
		}
	}
	return out
}
