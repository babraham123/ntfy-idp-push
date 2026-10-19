package app_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/app"
	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/directory"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// serve runs Serve on the harness's config, store and fakes with the directory type set, until
// Serve returns or ctx ends.
func serve(t *testing.T, ctx context.Context, h *testutil.Harness, dirType string) error {
	t.Helper()
	cfg := *h.Cfg
	cfg.DirectoryType = dirType
	a, err := app.Build(&cfg, h.Store, slog.New(slog.NewTextHandler(io.Discard, nil)), h.Dir, h.Mail)
	if err != nil {
		t.Fatal(err)
	}
	return a.Serve(ctx, nil, func() (*config.Config, error) { return &cfg, nil })
}

// Serve refuses to start on a directory whose check fails, naming the key to fix, and starts once
// the check passes.
func TestServeRefusesFailedDirectoryCheck(t *testing.T) {
	h := testutil.NewHarness(t, func(c *config.Config) { c.ListenHTTP = "127.0.0.1:0" })
	noGroup := fmt.Errorf("directory: group %q: %w", "push", directory.ErrNoGroup)
	unreachable := errors.New("directory: ldap connect: connection refused")
	for _, c := range []struct {
		dirType string
		err     error
		key     string
	}{
		{"ldap", noGroup, "directory-ldap-group-dn"},
		{"file", noGroup, "directory-group"},
		{"ldap", unreachable, "directory-ldap-*"},
		{"file", unreachable, "directory-file"},
	} {
		h.Dir.FailCheck(c.err)
		err := serve(t, context.Background(), h, c.dirType)
		if err == nil || !strings.Contains(err.Error(), "directory check ("+c.key+")") || !errors.Is(err, c.err) {
			t.Errorf("%s, %v: Serve returned %v, want a refusal naming %s", c.dirType, c.err, err, c.key)
		}
	}

	h.Dir.FailCheck(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := serve(t, ctx, h, "file"); err != nil {
		t.Fatalf("Serve with a passing directory check: %v", err)
	}
}
