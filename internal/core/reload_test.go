package core_test

import (
	"context"
	"errors"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/config"
	"github.com/babraham123/ntfy-idp-push/internal/core"
	"github.com/babraham123/ntfy-idp-push/internal/testutil"
)

// A reload reaches the ntfy adapter: a rotated admin token is used on the next ntfy call. Keys
// bound at startup refuse the reload and leave the running configuration untouched.
func TestReloadRotatesNtfyToken(t *testing.T) {
	ctx := context.Background()
	h := testutil.NewHarness(t, nil)
	h.Ntfy.AdminToken = "tk_rotated"
	if err := h.Svc.StartupChecks(ctx); err == nil {
		t.Fatal("fake ntfy accepted the stale token")
	}
	h.Reload(t, func(c *config.Config) { c.NtfyAdminToken = "tk_rotated" })
	if err := h.Svc.StartupChecks(ctx); err != nil {
		t.Fatalf("ntfy call after reload: %v", err)
	}

	next := *h.Cfg
	next.PublicURL = "https://elsewhere.test"
	next.WebAuthnAllowSynced = !next.WebAuthnAllowSynced
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	err := h.Svc.Reload(&next)
	if !errors.Is(err, core.ErrRestartRequired) || err.Error() != "restart required: public-url, webauthn-allow-synced changed" {
		t.Fatalf("restart-only keys: %v", err)
	}
	if h.Svc.Config().PublicURL != testutil.PublicURL {
		t.Fatal("refused reload changed the running config")
	}
}
