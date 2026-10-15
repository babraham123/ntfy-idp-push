// Package store persists users, devices, passkeys, challenges and the audit log in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

var migrations = []string{
	`CREATE TABLE users (
		id               TEXT PRIMARY KEY,
		username         TEXT NOT NULL UNIQUE,
		ntfy_grants_json TEXT NOT NULL DEFAULT '[]',
		disabled_at      INTEGER,
		created_at       INTEGER NOT NULL
	);
	CREATE TABLE devices (
		id                TEXT PRIMARY KEY,
		user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		name              TEXT NOT NULL,
		ntfy_topic        TEXT NOT NULL UNIQUE,
		verify_token_hash BLOB,
		verified_at       INTEGER,
		created_at        INTEGER NOT NULL,
		last_used_at      INTEGER
	);
	CREATE TABLE passkeys (
		cred_id         BLOB PRIMARY KEY,
		device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		credential_json BLOB NOT NULL,
		aaguid          BLOB,
		sign_count      INTEGER NOT NULL DEFAULT 0,
		created_at      INTEGER NOT NULL
	);
	CREATE TABLE challenges (
		id               TEXT PRIMARY KEY,
		username         TEXT NOT NULL,
		device_id        TEXT NOT NULL,
		nonce            BLOB NOT NULL,
		ipaddr           TEXT NOT NULL DEFAULT '',
		target_url       TEXT NOT NULL DEFAULT '',
		display_username TEXT NOT NULL DEFAULT '',
		state            TEXT NOT NULL CHECK (state IN ('pending','allow','deny','fraud','timeout')),
		deny_token_hash  BLOB NOT NULL,
		created_at       INTEGER NOT NULL,
		expires_at       INTEGER NOT NULL,
		decided_at       INTEGER
	);
	CREATE INDEX challenges_device ON challenges(device_id, state);
	CREATE TABLE enroll_codes (
		code_hash  BLOB PRIMARY KEY,
		username   TEXT NOT NULL,
		device_id  TEXT,
		expires_at INTEGER NOT NULL,
		used_at    INTEGER
	);
	CREATE TABLE oidc_sessions (
		id         TEXT PRIMARY KEY,
		username   TEXT NOT NULL,
		expires_at INTEGER NOT NULL
	);
	CREATE TABLE audit (
		ts          INTEGER NOT NULL,
		username    TEXT NOT NULL,
		event       TEXT NOT NULL,
		detail_json TEXT NOT NULL DEFAULT '{}'
	);
	CREATE INDEX audit_ts ON audit(ts);`,
	// A revoked device keeps its row until its ntfy cleanup succeeds, so a failed cleanup can be retried.
	`ALTER TABLE devices ADD COLUMN revoked_at INTEGER;`,
	// Authorizes the enrollment result page after a single-use enrollment code is spent; it must
	// survive a restart, so it is stored (hashed) rather than kept in memory.
	`ALTER TABLE devices ADD COLUMN result_token_hash BLOB;
	CREATE UNIQUE INDEX devices_result_token ON devices(result_token_hash);`,
	// Set while an ntfy user reset is unfinished, so the purge job completes it even after the
	// revoked device's row, which a manual retry needs, is gone.
	`ALTER TABLE users ADD COLUMN ntfy_reset_pending INTEGER NOT NULL DEFAULT 0;`,
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		// Each connection to :memory: is a separate database.
		db.SetMaxOpenConns(1)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Backup writes a consistent copy of the database to path, which must not exist. It is safe while
// the server runs. The copy is created 0600, as the database holds passkeys and session IDs.
func (s *Store) Backup(ctx context.Context, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for ; v < len(migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0)
	return &t
}

func (s *Store) Audit(ctx context.Context, username, event string, detail map[string]any) {
	b, _ := json.Marshal(detail)
	if detail == nil {
		b = []byte("{}")
	}
	// Audit failures must not change the outcome of the action being audited.
	_, _ = s.db.ExecContext(ctx, `INSERT INTO audit (ts, username, event, detail_json) VALUES (?,?,?,?)`,
		unix(time.Now()), username, event, string(b))
}

type AuditEntry struct {
	TS       time.Time
	Username string
	Event    string
	Detail   string
}

func (s *Store) AuditLog(ctx context.Context, username string, limit int) ([]AuditEntry, error) {
	q := `SELECT ts, username, event, detail_json FROM audit`
	args := []any{}
	if username != "" {
		q += ` WHERE username = ?`
		args = append(args, username)
	}
	q += ` ORDER BY ts DESC, rowid DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Username, &e.Event, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Purge removes old challenges, codes and sessions. A used enrollment code
// is kept as long as its device may still be awaiting setup, because an IdP keeps polling
// enroll_status past the code's expiry.
func (s *Store) Purge(ctx context.Context, now time.Time, unverifiedTTL, challengeTTL time.Duration) error {
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM challenges WHERE created_at < ?`, []any{unix(now.Add(-challengeTTL))}},
		{`DELETE FROM enroll_codes WHERE (used_at IS NULL AND expires_at < ?) OR used_at < ?`, []any{unix(now), unix(now.Add(-unverifiedTTL))}},
		{`DELETE FROM oidc_sessions WHERE expires_at < ?`, []any{unix(now)}},
	} {
		if _, err := s.db.ExecContext(ctx, q.sql, q.args...); err != nil {
			return err
		}
	}
	return nil
}

// StaleDevices lists devices never verified within unverifiedTTL and revoked devices whose ntfy
// cleanup has not finished.
func (s *Store) StaleDevices(ctx context.Context, now time.Time, unverifiedTTL time.Duration) ([]Device, error) {
	return s.queryDevices(ctx, `WHERE (d.verified_at IS NULL AND d.created_at < ?) OR d.revoked_at IS NOT NULL`, unix(now.Add(-unverifiedTTL)))
}
