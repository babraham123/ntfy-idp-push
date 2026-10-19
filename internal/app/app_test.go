package app_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/app"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// logBuffer collects log output written from Serve's goroutines.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// harness is a harness whose Serve listens on a free port; mutate may adjust its config further.
func harness(t *testing.T, mutate func(*config.Config)) *testutil.Harness {
	return testutil.NewHarness(t, func(c *config.Config) {
		c.ListenHTTP = "127.0.0.1:0"
		if mutate != nil {
			mutate(c)
		}
	})
}

// serve runs Serve on the harness's config, store and fakes until Serve returns or ctx ends, and
// returns what it logged.
func serve(t *testing.T, ctx context.Context, h *testutil.Harness) (string, error) {
	t.Helper()
	var logs logBuffer
	a, err := app.Build(h.Cfg, h.Store, slog.New(slog.NewTextHandler(&logs, nil)), h.Source(), h.Mail)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Serve(ctx, nil, func() (*config.Config, error) { return h.Cfg, nil })
	return logs.String(), err
}

// Serve refuses to start on a directory whose check fails, naming the key to fix, and starts once
// the check passes.
func TestServeRefusesFailedDirectoryCheck(t *testing.T) {
	h := harness(t, nil)
	noGroup := fmt.Errorf("directory: ldap group %q: %w", "cn=push", directory.ErrNoGroup)
	unreachable := errors.New("directory: ldap connect: connection refused")
	for _, c := range []struct {
		err error
		key string
	}{
		{noGroup, "directory-ldap-group-dn"},
		{unreachable, "directory-ldap-*"},
	} {
		h.Dir.FailCheck(c.err)
		_, err := serve(t, context.Background(), h)
		if err == nil || !strings.Contains(err.Error(), "directory check ("+c.key+")") || !errors.Is(err, c.err) {
			t.Errorf("%v: Serve returned %v, want a refusal naming %s", c.err, err, c.key)
		}
	}

	h.Dir.FailCheck(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := serve(t, ctx, h); err != nil {
		t.Fatalf("Serve with a passing directory check: %v", err)
	}
}

// With a directory, Serve's sync loop provisions the people it lists. Without one, Serve neither
// checks nor syncs a directory, and says once that sync is off.
func TestServeSyncsOnlyWithDirectory(t *testing.T) {
	carol := directory.Person{Username: "carol", Email: "carol@example.com"}

	h := harness(t, nil)
	h.Dir.Set(carol)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := serve(t, ctx, h)
		done <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); h.Ntfy.User("carol") == nil; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the sync loop never provisioned a listed person")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	h = harness(t, testutil.NoDirectory)
	h.Dir.Set(carol)
	h.Dir.FailCheck(errors.New("directory: ldap connect: connection refused"))
	ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	logs, err := serve(t, ctx, h)
	if err != nil {
		t.Fatalf("Serve without a directory: %v", err)
	}
	if n := strings.Count(logs, "directory sync off"); n != 1 {
		t.Errorf("logged %d sync-off notices, want 1:\n%s", n, logs)
	}
	if h.Ntfy.User("carol") != nil {
		t.Error("Serve synced without a directory")
	}
}
