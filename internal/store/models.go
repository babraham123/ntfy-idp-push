package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/babraham123/ntfy-idp-push/internal/config"
)

type User struct {
	ID         string
	Username   string
	Grants     []config.Grant // ntfy grants the shim applied from enroll-access
	DisabledAt *time.Time
	CreatedAt  time.Time
}

type Device struct {
	ID         string
	UserID     string
	Username   string
	Name       string
	NtfyTopic  string
	VerifiedAt *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

type Passkey struct {
	CredID         []byte
	DeviceID       string
	CredentialJSON []byte
	AAGUID         []byte
	SignCount      uint32
}

type ChallengeState string

const (
	StatePending ChallengeState = "pending"
	StateAllow   ChallengeState = "allow"
	StateDeny    ChallengeState = "deny"
	StateFraud   ChallengeState = "fraud"
	StateTimeout ChallengeState = "timeout"
)

type Challenge struct {
	ID              string
	Username        string
	DeviceID        string
	Nonce           []byte
	IPAddr          string
	TargetURL       string
	DisplayUsername string
	State           ChallengeState
	DenyTokenHash   []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
	DecidedAt       *time.Time
}

type EnrollCode struct {
	Username  string
	DeviceID  string // set for IdP-driven enrollment (/auth/v2/enroll)
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// ---- users

const userCols = `id, username, ntfy_grants_json, disabled_at, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var grants string
	var disabled sql.NullInt64
	var created int64
	if err := row.Scan(&u.ID, &u.Username, &grants, &disabled, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(grants), &u.Grants); err != nil {
		return nil, err
	}
	u.DisabledAt = fromUnix(disabled)
	u.CreatedAt = time.Unix(created, 0)
	return &u, nil
}

func (s *Store) UserByName(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// EnsureUser returns the user, creating it with id when missing.
func (s *Store) EnsureUser(ctx context.Context, username, id string) (*User, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, username, created_at) VALUES (?,?,?) ON CONFLICT(username) DO NOTHING`,
		id, username, unix(time.Now()))
	if err != nil {
		return nil, err
	}
	return s.UserByName(ctx, username)
}

func (s *Store) SetUserGrants(ctx context.Context, userID string, grants []config.Grant) error {
	if grants == nil {
		grants = []config.Grant{}
	}
	b, _ := json.Marshal(grants)
	_, err := s.db.ExecContext(ctx, `UPDATE users SET ntfy_grants_json = ? WHERE id = ?`, string(b), userID)
	return err
}

// SetNtfyResetPending records whether username's ntfy user reset is unfinished.
func (s *Store) SetNtfyResetPending(ctx context.Context, username string, pending bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET ntfy_reset_pending = ? WHERE username = ?`, pending, username)
	return err
}

// PendingNtfyResets lists the users whose ntfy user reset is unfinished.
func (s *Store) PendingNtfyResets(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username FROM users WHERE ntfy_reset_pending`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) SetUserDisabled(ctx context.Context, userID string, disabled bool) error {
	var v any
	if disabled {
		v = unix(time.Now())
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, v, userID)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

// ---- devices

const deviceCols = `d.id, d.user_id, u.username, d.name, d.ntfy_topic, d.verified_at, d.created_at, d.last_used_at, d.revoked_at`

func (s *Store) queryDevices(ctx context.Context, where string, args ...any) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices d JOIN users u ON u.id = d.user_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var verified, lastUsed, revoked sql.NullInt64
		var created int64
		if err := rows.Scan(&d.ID, &d.UserID, &d.Username, &d.Name, &d.NtfyTopic, &verified, &created, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		d.VerifiedAt, d.LastUsedAt, d.CreatedAt = fromUnix(verified), fromUnix(lastUsed), time.Unix(created, 0)
		d.RevokedAt = fromUnix(revoked)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) Device(ctx context.Context, id string) (*Device, error) {
	ds, err := s.queryDevices(ctx, `WHERE d.id = ?`, id)
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, ErrNotFound
	}
	return &ds[0], nil
}

// Devices lists a user's devices, most recently used first. activeOnly keeps only devices that can
// receive logins: verified and not revoked.
func (s *Store) Devices(ctx context.Context, userID string, activeOnly bool) ([]Device, error) {
	where := `WHERE d.user_id = ?`
	if activeOnly {
		where += ` AND d.verified_at IS NOT NULL AND d.revoked_at IS NULL`
	}
	return s.queryDevices(ctx, where+` ORDER BY COALESCE(d.last_used_at, d.verified_at, d.created_at) DESC, d.created_at DESC`, userID)
}

var ErrCodeUnavailable = errors.New("enrollment code used or expired")

// CreateEnrollment atomically claims the enrollment code (when codeHash is set) and inserts the
// unverified device with its passkey. It returns ErrCodeUnavailable if the code cannot be claimed.
func (s *Store) CreateEnrollment(ctx context.Context, d *Device, verifyTokenHash, resultTokenHash []byte, p *Passkey, codeHash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now()
	if codeHash != nil {
		res, err := tx.ExecContext(ctx, `UPDATE enroll_codes SET used_at = ?, device_id = ?
			WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`, unix(now), d.ID, codeHash, unix(now))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrCodeUnavailable
		}
	}
	d.CreatedAt = now
	if _, err := tx.ExecContext(ctx, `INSERT INTO devices (id, user_id, name, ntfy_topic, verify_token_hash, result_token_hash, created_at) VALUES (?,?,?,?,?,?,?)`,
		d.ID, d.UserID, d.Name, d.NtfyTopic, verifyTokenHash, resultTokenHash, unix(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO passkeys (cred_id, device_id, credential_json, aaguid, sign_count, created_at) VALUES (?,?,?,?,?,?)`,
		p.CredID, p.DeviceID, p.CredentialJSON, p.AAGUID, p.SignCount, unix(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// DeviceByResultToken returns the unrevoked device enrolled within ttl whose result token hashes
// to tokenHash.
func (s *Store) DeviceByResultToken(ctx context.Context, tokenHash []byte, now time.Time, ttl time.Duration) (*Device, error) {
	ds, err := s.queryDevices(ctx, `WHERE d.result_token_hash = ? AND d.created_at > ? AND d.revoked_at IS NULL`, tokenHash, unix(now.Add(-ttl)))
	if err != nil {
		return nil, err
	}
	if len(ds) == 0 {
		return nil, ErrNotFound
	}
	return &ds[0], nil
}

// SetVerifyToken replaces the verify token of a device still awaiting setup. It reports whether it did.
func (s *Store) SetVerifyToken(ctx context.Context, id string, tokenHash []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET verify_token_hash = ?
		WHERE id = ? AND verified_at IS NULL AND revoked_at IS NULL`, tokenHash, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// VerifyDevice marks the device active if tokenHash matches. It reports whether it did.
func (s *Store) VerifyDevice(ctx context.Context, id string, tokenHash []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET verified_at = ?, verify_token_hash = NULL
		WHERE id = ? AND verified_at IS NULL AND revoked_at IS NULL AND verify_token_hash = ?`, unix(time.Now()), id, tokenHash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (s *Store) TouchDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_used_at = ? WHERE id = ?`, unix(time.Now()), id)
	return err
}

// RevokeDevice marks the device revoked and deletes its passkeys, so it can approve nothing more.
func (s *Store) RevokeDevice(ctx context.Context, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked_at = COALESCE(revoked_at, ?), verify_token_hash = NULL WHERE id = ?`, unix(now), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM passkeys WHERE device_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	return err
}

// ---- passkeys

func (s *Store) Passkeys(ctx context.Context, deviceID string) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cred_id, device_id, credential_json, aaguid, sign_count FROM passkeys WHERE device_id = ?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		if err := rows.Scan(&p.CredID, &p.DeviceID, &p.CredentialJSON, &p.AAGUID, &p.SignCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePasskey(ctx context.Context, credID, credentialJSON []byte, signCount uint32) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET credential_json = ?, sign_count = ? WHERE cred_id = ?`, credentialJSON, signCount, credID)
	return err
}

// ---- challenges

func (s *Store) CreateChallenge(ctx context.Context, c *Challenge) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO challenges
		(id, username, device_id, nonce, ipaddr, target_url, display_username, state, deny_token_hash, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Username, c.DeviceID, c.Nonce, c.IPAddr, c.TargetURL, c.DisplayUsername, string(StatePending), c.DenyTokenHash,
		unix(c.CreatedAt), unix(c.ExpiresAt))
	return err
}

func (s *Store) Challenge(ctx context.Context, id string) (*Challenge, error) {
	var c Challenge
	var state string
	var created, expires int64
	var decided sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, username, device_id, nonce, ipaddr, target_url, display_username, state,
		deny_token_hash, created_at, expires_at, decided_at FROM challenges WHERE id = ?`, id).
		Scan(&c.ID, &c.Username, &c.DeviceID, &c.Nonce, &c.IPAddr, &c.TargetURL, &c.DisplayUsername, &state,
			&c.DenyTokenHash, &created, &expires, &decided)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	c.State = ChallengeState(state)
	c.CreatedAt, c.ExpiresAt, c.DecidedAt = time.Unix(created, 0), time.Unix(expires, 0), fromUnix(decided)
	return &c, nil
}

// DecideChallenge moves a pending, unexpired challenge to state. It reports whether this call
// made the decision; a challenge is decided at most once. Allow additionally requires, in the same
// statement, that the device is active and its user enabled: core's eligibility rule (less the kill
// switch, which lives in config), repeated here so a concurrent revoke or disable cannot slip
// between core's check and the update.
func (s *Store) DecideChallenge(ctx context.Context, id string, state ChallengeState, now time.Time) (bool, error) {
	cond := ` AND expires_at > ?`
	args := []any{string(state), unix(now), id, unix(now)}
	switch state {
	case StateTimeout:
		cond, args = ``, args[:3]
	case StateAllow:
		cond += ` AND EXISTS (SELECT 1 FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = challenges.device_id
			AND d.verified_at IS NOT NULL AND d.revoked_at IS NULL AND u.disabled_at IS NULL)`
	}
	res, err := s.db.ExecContext(ctx, `UPDATE challenges SET state = ?, decided_at = ? WHERE id = ? AND state = 'pending'`+cond, args...)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ChallengeFilter selects pending challenges by device, username or expiry; the zero value selects
// all.
type ChallengeFilter struct {
	DeviceID string
	Username string
	// ExpiredBy, when set, keeps challenges that expired at or before it.
	ExpiredBy time.Time
}

// PendingChallengeIDs lists undecided challenges matching f, used when revoking, disabling or
// purging.
func (s *Store) PendingChallengeIDs(ctx context.Context, f ChallengeFilter) ([]string, error) {
	q, args := `SELECT id FROM challenges WHERE state = 'pending'`, []any{}
	if f.DeviceID != "" {
		q, args = q+` AND device_id = ?`, append(args, f.DeviceID)
	}
	if f.Username != "" {
		q, args = q+` AND username = ?`, append(args, f.Username)
	}
	if !f.ExpiredBy.IsZero() {
		q, args = q+` AND expires_at <= ?`, append(args, unix(f.ExpiredBy))
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---- enrollment codes

func (s *Store) CreateEnrollCode(ctx context.Context, codeHash []byte, e EnrollCode) error {
	var dev any
	if e.DeviceID != "" {
		dev = e.DeviceID
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO enroll_codes (code_hash, username, device_id, expires_at) VALUES (?,?,?,?)`,
		codeHash, e.Username, dev, unix(e.ExpiresAt))
	return err
}

func (s *Store) EnrollCode(ctx context.Context, codeHash []byte) (*EnrollCode, error) {
	var e EnrollCode
	var dev sql.NullString
	var expires int64
	var used sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT username, device_id, expires_at, used_at FROM enroll_codes WHERE code_hash = ?`, codeHash).
		Scan(&e.Username, &dev, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	e.DeviceID, e.ExpiresAt, e.UsedAt = dev.String, time.Unix(expires, 0), fromUnix(used)
	return &e, nil
}

// ReleaseEnrollCode makes a code claimed by a failed enrollment usable again.
func (s *Store) ReleaseEnrollCode(ctx context.Context, codeHash []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enroll_codes SET used_at = NULL, device_id = NULL WHERE code_hash = ?`, codeHash)
	return err
}

// ---- OIDC sessions

func (s *Store) CreateSession(ctx context.Context, id, username string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_sessions (id, username, expires_at) VALUES (?,?,?)`, id, username, unix(expires))
	return err
}

func (s *Store) SessionUser(ctx context.Context, id string, now time.Time) (string, error) {
	var u string
	err := s.db.QueryRowContext(ctx, `SELECT username FROM oidc_sessions WHERE id = ? AND expires_at > ?`, id, unix(now)).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return u, err
}
