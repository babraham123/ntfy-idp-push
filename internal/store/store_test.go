package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/babraham123/ntfy-idp-push/internal/store"
)

func TestBackup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.EnsureUser(ctx, "alice", "u1"); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "backup.sqlite")
	if err := st.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	// It holds passkeys and session IDs.
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file mode: %v %v", fi.Mode(), err)
	}
	// Restoring is opening the copy in place of the database.
	restored, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if u, err := restored.UserByName(ctx, "alice"); err != nil || u.ID != "u1" {
		t.Fatalf("restored user: %+v %v", u, err)
	}

	// An existing file is never overwritten.
	if err := st.Backup(ctx, path); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	if _, err := restored.UserByName(ctx, "alice"); err != nil {
		t.Fatalf("existing file damaged: %v", err)
	}
}
