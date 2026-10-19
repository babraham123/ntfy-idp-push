package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// A database from before the directory sync gains empty profiles: no email, never synced, and a
// welcome owed.
func TestMigrateAddsUserProfile(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	const before = 5 // the schema version before the profile columns
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:before] {
		if _, err := db.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, before)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, username, created_at, disabled_at) VALUES ('u1', 'alice', 1, 2)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.UserByName(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "" || u.DisplayName != "" || u.SyncedAt != nil || u.WelcomedAt != nil || u.DisabledAt == nil || u.DisabledBySync {
		t.Fatalf("migrated user %+v", u)
	}

	synced := time.Unix(1_700_000_000, 0)
	if err := st.SetUserProfile(ctx, u.ID, "alice@example.com", "Alice", synced); err != nil {
		t.Fatal(err)
	}
	welcomed := synced.Add(time.Minute)
	if err := st.SetUserWelcomed(ctx, u.ID, &welcomed); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserDisabled(ctx, u.ID, true, true); err != nil {
		t.Fatal(err)
	}
	u, _ = st.UserByName(ctx, "alice")
	if u.Email != "alice@example.com" || u.DisplayName != "Alice" || !u.SyncedAt.Equal(synced) ||
		!u.WelcomedAt.Equal(welcomed) || u.DisabledAt == nil || !u.DisabledBySync {
		t.Fatalf("profile not stored: %+v", u)
	}

	// Enabling clears the sync's mark, and a nil welcome time marks the welcome as owed again.
	if err := st.SetUserDisabled(ctx, u.ID, false, true); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserWelcomed(ctx, u.ID, nil); err != nil {
		t.Fatal(err)
	}
	u, _ = st.UserByName(ctx, "alice")
	if u.DisabledAt != nil || u.DisabledBySync || u.WelcomedAt != nil {
		t.Fatalf("after enable and owed welcome: %+v", u)
	}
}
