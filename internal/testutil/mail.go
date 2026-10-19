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
	// gate, while set, holds every Send until it is closed; each held Send is announced on held.
	gate chan struct{}
	held chan mail.Message
}

func NewFakeMail() *FakeMail { return &FakeMail{} }

func (f *FakeMail) Send(ctx context.Context, m mail.Message) error {
	f.mu.Lock()
	gate, held := f.gate, f.held
	f.mu.Unlock()
	if gate != nil {
		held <- m
		select {
		case <-gate:
		case <-ctx.Done():
		}
	}
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

// Block makes every later Send wait, like a stalled mail server, until Unblock or until its
// context ends, which it then returns. Each waiting Send is announced on the returned channel.
func (f *FakeMail) Block() <-chan mail.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate, f.held = make(chan struct{}), make(chan mail.Message, 100)
	return f.held
}

// Unblock releases the waiting Sends and stops holding later ones.
func (f *FakeMail) Unblock() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gate != nil {
		close(f.gate)
		f.gate = nil
	}
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
