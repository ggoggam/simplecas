package db

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// A session is one sign-in: the browser holds a signed cookie carrying a
// random token, and the session is live while a row here holds that token's
// hash and has not expired. Revoking a session deletes its row, so the next
// request carrying the cookie finds nothing and is signed out.

// Display-only request details are cut to these many bytes before they are
// stored, so a client cannot grow the table with an enormous header.
const (
	maxUserAgentBytes = 256
	maxIPBytes        = 64
)

// NewSession is what a completed sign-in records.
type NewSession struct {
	// TokenHash is the SHA-256 of the bearer token in the cookie. The token
	// itself is never stored.
	TokenHash []byte
	UserID    int64
	ExpiresAt time.Time
	UserAgent string
	IP        string
}

// LiveSession is what an authenticated request learns from its session row.
type LiveSession struct {
	ID     uuid.UUID
	UserID int64
}

// CreateSession records a sign-in and returns the session's public id.
func (d *DB) CreateSession(ctx context.Context, s NewSession) (uuid.UUID, error) {
	id := uuid.New()
	_, err := d.pool.Exec(ctx, `
		INSERT INTO sessions (id, token_hash, user_id, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, s.TokenHash, s.UserID, s.ExpiresAt,
		truncateUTF8(s.UserAgent, maxUserAgentBytes), truncateUTF8(s.IP, maxIPBytes))
	if err != nil {
		return uuid.Nil, apperr.Internal(err)
	}
	return id, nil
}

// TouchSession is the per-request check: it returns the live session whose
// token hashes to tokenHash, provided it belongs to the user (issuer,
// subject) and has not expired. ok is false when there is no such session —
// it never existed, was revoked, or has lapsed.
//
// It is one statement, a primary-key-sized lookup on the token_hash unique
// index joined to the user by primary key. The same statement moves
// last_seen_at forward when it is more than touchAfter old, so a busy session
// is written once every touchAfter rather than on every request. The update
// re-checks the stored last_seen_at, so concurrent requests that all saw a
// stale value write it once between them.
func (d *DB) TouchSession(ctx context.Context, tokenHash []byte, issuer, subject string, touchAfter time.Duration) (session LiveSession, ok bool, err error) {
	err = d.pool.QueryRow(ctx, `
		WITH live AS (
		    SELECT s.id, s.user_id
		    FROM sessions s
		    JOIN users u ON u.id = s.user_id
		    WHERE s.token_hash = $1 AND s.expires_at > now()
		      AND u.issuer = $2 AND u.subject = $3
		), touched AS (
		    UPDATE sessions s SET last_seen_at = now()
		    FROM live
		    WHERE s.id = live.id
		      AND s.last_seen_at < now() - make_interval(secs => $4)
		)
		SELECT id, user_id FROM live`,
		tokenHash, issuer, subject, touchAfter.Seconds()).Scan(&session.ID, &session.UserID)
	switch {
	case err == nil:
		return session, true, nil
	case notFound(err):
		return LiveSession{}, false, nil
	default:
		return LiveSession{}, false, apperr.Internal(err)
	}
}

// ListSessions returns userID's unexpired sessions, most recently used first.
func (d *DB) ListSessions(ctx context.Context, userID int64) ([]Session, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT id, created_at, last_seen_at, expires_at, user_agent, ip
		FROM sessions
		WHERE user_id = $1 AND expires_at > now()
		ORDER BY last_seen_at DESC, created_at DESC, id`, userID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Session])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return out, nil
}

// RevokeSession ends one of userID's sessions. A session that belongs to
// someone else is NoSuchSession, the same as one that does not exist, so ids
// cannot be probed across users.
func (d *DB) RevokeSession(ctx context.Context, userID int64, id uuid.UUID) error {
	tag, err := d.pool.Exec(ctx,
		"DELETE FROM sessions WHERE id = $1 AND user_id = $2", id, userID)
	if err != nil {
		return apperr.Internal(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNoSuchSession
	}
	return nil
}

// RevokeOtherSessions ends every session of userID's except keep, returning
// how many it ended.
func (d *DB) RevokeOtherSessions(ctx context.Context, userID int64, keep uuid.UUID) (int64, error) {
	tag, err := d.pool.Exec(ctx,
		"DELETE FROM sessions WHERE user_id = $1 AND id <> $2", userID, keep)
	if err != nil {
		return 0, apperr.Internal(err)
	}
	return tag.RowsAffected(), nil
}

// RevokeAllSessions ends every session of userID's, returning how many it
// ended.
func (d *DB) RevokeAllSessions(ctx context.Context, userID int64) (int64, error) {
	tag, err := d.pool.Exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
	if err != nil {
		return 0, apperr.Internal(err)
	}
	return tag.RowsAffected(), nil
}

// DeleteSessionByToken ends the session whose token hashes to tokenHash, if
// there is one. Signing out calls it with the cookie's own token, so it needs
// no user id: holding the token is the authority to end its session.
func (d *DB) DeleteSessionByToken(ctx context.Context, tokenHash []byte) error {
	_, err := d.pool.Exec(ctx, "DELETE FROM sessions WHERE token_hash = $1", tokenHash)
	return apperr.Internal(err)
}

// SweepSessions deletes expired sessions, returning how many. Revoked ones
// are already gone, so this is all the cleanup the table needs.
func (d *DB) SweepSessions(ctx context.Context) (int64, error) {
	tag, err := d.pool.Exec(ctx, "DELETE FROM sessions WHERE expires_at <= now()")
	if err != nil {
		return 0, apperr.Internal(err)
	}
	return tag.RowsAffected(), nil
}

// truncateUTF8 cuts s to at most n bytes without splitting a character, and
// drops any invalid UTF-8, which Postgres would refuse in a TEXT column.
func truncateUTF8(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
