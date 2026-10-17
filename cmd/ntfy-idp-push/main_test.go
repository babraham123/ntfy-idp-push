package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// env points the CLI at a database in a temp dir with a complete configuration and no config
// file, so commands that do not need ntfy can run.
func env(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for k, v := range map[string]string{
		"NTFY_IDP_PUSH_CONFIG":              "",
		"NTFY_IDP_PUSH_DUO_HOSTNAME":        "push.test",
		"NTFY_IDP_PUSH_DUO_INTEGRATION_KEY": "DIAAAAAAAAAAAAAAAAAA",
		"NTFY_IDP_PUSH_DUO_SECRET_KEY":      "secretsecretsecretsecretsecretsecretsecr",
		"NTFY_IDP_PUSH_NTFY_BASE_URL":       "http://ntfy.test",
		"NTFY_IDP_PUSH_NTFY_ADMIN_TOKEN":    "tk_admin",
		"NTFY_IDP_PUSH_TRUSTED_PROXIES":     "10.0.0.5",
		"NTFY_IDP_PUSH_DATABASE":            filepath.Join(dir, "db.sqlite"),
	} {
		t.Setenv(k, v)
	}
	os.Unsetenv("NTFY_IDP_PUSH_CONFIG")
	return dir
}

func cli(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, &out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return out.String(), err
}

func TestSplitArgs(t *testing.T) {
	flags, pos := splitArgs([]string{"revoke", "--force", "dev1", "--", "-weird-user"})
	if !reflect.DeepEqual(flags, []string{"--force"}) || !reflect.DeepEqual(pos, []string{"revoke", "dev1", "-weird-user"}) {
		t.Fatalf("flags %v pos %v", flags, pos)
	}
}

func TestVersionAndUsage(t *testing.T) {
	env(t)
	if out, err := cli(t, "version"); err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("version: %q %v", out, err)
	}
	if _, err := cli(t); err == nil {
		t.Fatal("no command accepted")
	}
	if _, err := cli(t, "frobnicate"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command: %v", err)
	}
}

// The default config path may be missing when the environment configures everything; an explicit
// one must exist.
func TestConfigPath(t *testing.T) {
	env(t)
	if out, err := cli(t, "user", "list"); err != nil || !strings.HasPrefix(out, "USERNAME") {
		t.Fatalf("env-only config: %q %v", out, err)
	}
	if _, err := cli(t, "-c", "/nonexistent/server.yml", "user", "list"); err == nil {
		t.Fatal("missing explicit config accepted")
	}
}

func TestEnrollLinkAndBackup(t *testing.T) {
	dir := env(t)
	out, err := cli(t, "enroll-link", "alice")
	if err != nil || !strings.HasPrefix(out, "https://push.test/token/") {
		t.Fatalf("enroll-link: %q %v", out, err)
	}
	if out, err := cli(t, "audit", "alice"); err != nil || !strings.Contains(out, "enroll_link") {
		t.Fatalf("audit: %q %v", out, err)
	}
	out, err = cli(t, "backup", "-")
	if err != nil || !strings.HasPrefix(out, "SQLite format 3\x00") {
		t.Fatalf("backup to stdout: %v (%d bytes)", err, len(out))
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".backup-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	path := filepath.Join(dir, "copy.sqlite")
	if _, err := cli(t, "backup", path); err != nil {
		t.Fatal(err)
	}
	if _, err := cli(t, "backup", path); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
}
