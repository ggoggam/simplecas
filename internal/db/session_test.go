package db

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// testIssuer is the issuer mustUser signs users in with.
const testIssuer = "https://issuer.test"

// openSession records a session for the user signed in with email, lasting
// ttl, and returns its id and token hash.
func openSession(t *testing.T, d *DB, email string, ttl time.Duration) (uuid.UUID, []byte) {
	t.Helper()
	hash := sha256.Sum256([]byte(uuid.NewString()))
	id, err := d.CreateSession(t.Context(), NewSession{
		TokenHash: hash[:], UserID: mustUser(t, d, email), ExpiresAt: time.Now().Add(ttl),
		UserAgent: "agent/" + email, IP: "192.0.2.1",
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return id, hash[:]
}

// sessionIDs lists the ids of userID's sessions.
func sessionIDs(t *testing.T, d *DB, userID int64) []uuid.UUID {
	t.Helper()
	sessions, err := d.ListSessions(t.Context(), userID)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uuid.UUID, 0, len(sessions))
	for _, s := range sessions {
		ids = append(ids, s.ID)
	}
	return ids
}

func TestTouchSession(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	id, hash := openSession(t, d, "dev@example.com", time.Hour)

	live, ok, err := d.TouchSession(ctx, hash, testIssuer, "sub-dev@example.com", time.Minute)
	if err != nil || !ok {
		t.Fatalf("touch = %v, %v; want the live session", ok, err)
	}
	if live.ID != id || live.UserID != mustUser(t, d, "dev@example.com") {
		t.Errorf("live session = %+v", live)
	}

	// The same token presented under another identity finds nothing.
	for _, subject := range []string{"sub-other@example.com", ""} {
		if _, ok, err := d.TouchSession(ctx, hash, testIssuer, subject, time.Minute); ok || err != nil {
			t.Errorf("subject %q: ok=%v err=%v, want no session", subject, ok, err)
		}
	}
	if _, ok, err := d.TouchSession(ctx, hash, "https://other.test", "sub-dev@example.com", time.Minute); ok || err != nil {
		t.Errorf("another issuer: ok=%v err=%v, want no session", ok, err)
	}
	// And so does an unknown token.
	unknown := sha256.Sum256([]byte("unknown"))
	if _, ok, err := d.TouchSession(ctx, unknown[:], testIssuer, "sub-dev@example.com", time.Minute); ok || err != nil {
		t.Errorf("unknown token: ok=%v err=%v, want no session", ok, err)
	}
}

// last_seen_at moves only once it is older than the touch interval, so a busy
// session is not a write per request.
func TestTouchSessionThrottlesLastSeen(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	id, hash := openSession(t, d, "dev@example.com", time.Hour)

	lastSeen := func() time.Time {
		t.Helper()
		var at time.Time
		if err := d.pool.QueryRow(ctx, "SELECT last_seen_at FROM sessions WHERE id = $1", id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	setLastSeen := func(ago time.Duration) time.Time {
		t.Helper()
		_, err := d.pool.Exec(ctx,
			"UPDATE sessions SET last_seen_at = now() - make_interval(secs => $2) WHERE id = $1",
			id, ago.Seconds())
		if err != nil {
			t.Fatal(err)
		}
		return lastSeen()
	}
	touch := func() {
		t.Helper()
		if _, ok, err := d.TouchSession(ctx, hash, testIssuer, "sub-dev@example.com", 5*time.Minute); !ok || err != nil {
			t.Fatalf("touch = %v, %v", ok, err)
		}
	}

	// Seen a minute ago: within the interval, so left alone.
	recent := setLastSeen(time.Minute)
	touch()
	touch()
	if got := lastSeen(); !got.Equal(recent) {
		t.Errorf("last_seen_at moved from %v to %v inside the interval", recent, got)
	}

	// Seen ten minutes ago: stale, so moved up to now.
	stale := setLastSeen(10 * time.Minute)
	touch()
	got := lastSeen()
	if !got.After(stale.Add(9 * time.Minute)) {
		t.Errorf("last_seen_at = %v, want it moved forward from %v", got, stale)
	}
	// And then left alone again.
	touch()
	if again := lastSeen(); !again.Equal(got) {
		t.Errorf("last_seen_at moved again from %v to %v straight after a touch", got, again)
	}
}

func TestExpiredSessionIsNotLive(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	_, hash := openSession(t, d, "dev@example.com", -time.Second)

	if _, ok, err := d.TouchSession(ctx, hash, testIssuer, "sub-dev@example.com", time.Minute); ok || err != nil {
		t.Errorf("touch = %v, %v; want an expired session to be no session", ok, err)
	}
	if ids := sessionIDs(t, d, mustUser(t, d, "dev@example.com")); len(ids) != 0 {
		t.Errorf("listed %v, want an expired session left out", ids)
	}
}

func TestRevokeSession(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	mine, hash := openSession(t, d, "dev@example.com", time.Hour)
	kept, _ := openSession(t, d, "dev@example.com", time.Hour)
	theirs, _ := openSession(t, d, "other@example.com", time.Hour)
	me, them := mustUser(t, d, "dev@example.com"), mustUser(t, d, "other@example.com")

	// Someone else's session is as absent as one that never existed, and
	// survives the attempt.
	for _, id := range []uuid.UUID{theirs, uuid.New()} {
		if err := d.RevokeSession(ctx, me, id); !errors.Is(err, apperr.ErrNoSuchSession) {
			t.Errorf("revoke %s = %v, want NoSuchSession", id, err)
		}
	}
	if ids := sessionIDs(t, d, them); len(ids) != 1 || ids[0] != theirs {
		t.Errorf("their sessions = %v, want theirs untouched", ids)
	}

	if err := d.RevokeSession(ctx, me, mine); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.TouchSession(ctx, hash, testIssuer, "sub-dev@example.com", time.Minute); ok {
		t.Error("a revoked session is still live")
	}
	if ids := sessionIDs(t, d, me); len(ids) != 1 || ids[0] != kept {
		t.Errorf("my sessions = %v, want only %s", ids, kept)
	}
	if err := d.RevokeSession(ctx, me, mine); !errors.Is(err, apperr.ErrNoSuchSession) {
		t.Errorf("revoking twice = %v, want NoSuchSession", err)
	}
}

func TestRevokeOtherAndAllSessions(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	current, _ := openSession(t, d, "dev@example.com", time.Hour)
	openSession(t, d, "dev@example.com", time.Hour)
	openSession(t, d, "dev@example.com", time.Hour)
	theirs, _ := openSession(t, d, "other@example.com", time.Hour)
	me, them := mustUser(t, d, "dev@example.com"), mustUser(t, d, "other@example.com")

	n, err := d.RevokeOtherSessions(ctx, me, current)
	if err != nil || n != 2 {
		t.Fatalf("revoke others = %d, %v; want 2", n, err)
	}
	if ids := sessionIDs(t, d, me); len(ids) != 1 || ids[0] != current {
		t.Errorf("my sessions = %v, want only the current one", ids)
	}

	n, err = d.RevokeAllSessions(ctx, me)
	if err != nil || n != 1 {
		t.Fatalf("revoke all = %d, %v; want 1", n, err)
	}
	if ids := sessionIDs(t, d, me); len(ids) != 0 {
		t.Errorf("my sessions = %v, want none", ids)
	}
	if ids := sessionIDs(t, d, them); len(ids) != 1 || ids[0] != theirs {
		t.Errorf("their sessions = %v, want theirs untouched", ids)
	}
}

func TestDeleteSessionByToken(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	_, hash := openSession(t, d, "dev@example.com", time.Hour)
	kept, _ := openSession(t, d, "dev@example.com", time.Hour)

	if err := d.DeleteSessionByToken(ctx, hash); err != nil {
		t.Fatal(err)
	}
	if ids := sessionIDs(t, d, mustUser(t, d, "dev@example.com")); len(ids) != 1 || ids[0] != kept {
		t.Errorf("sessions = %v, want only %s", ids, kept)
	}
	// A token with no session is nothing to do.
	if err := d.DeleteSessionByToken(ctx, hash); err != nil {
		t.Errorf("deleting again = %v", err)
	}
}

func TestSweepSessions(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	openSession(t, d, "dev@example.com", -time.Minute)
	openSession(t, d, "other@example.com", -time.Second)
	live, _ := openSession(t, d, "dev@example.com", time.Hour)

	n, err := d.SweepSessions(ctx)
	if err != nil || n != 2 {
		t.Fatalf("sweep = %d, %v; want the 2 expired sessions", n, err)
	}
	var left []uuid.UUID
	rows, err := d.pool.Query(ctx, "SELECT id FROM sessions")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if rows.Err() != nil || len(left) != 1 || left[0] != live {
		t.Errorf("rows left = %v, want only the live session", left)
	}

	if n, err := d.SweepSessions(ctx); err != nil || n != 0 {
		t.Errorf("second sweep = %d, %v; want nothing left to do", n, err)
	}
}

func TestListSessionsShowsTheRecordedDetails(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	older, _ := openSession(t, d, "dev@example.com", time.Hour)
	newer, _ := openSession(t, d, "dev@example.com", time.Hour)
	if _, err := d.pool.Exec(ctx,
		"UPDATE sessions SET last_seen_at = now() - interval '1 hour' WHERE id = $1", older); err != nil {
		t.Fatal(err)
	}

	sessions, err := d.ListSessions(ctx, mustUser(t, d, "dev@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || sessions[0].ID != newer || sessions[1].ID != older {
		t.Fatalf("sessions = %+v, want the most recently seen first", sessions)
	}
	s := sessions[0]
	if s.UserAgent != "agent/dev@example.com" || s.IP != "192.0.2.1" {
		t.Errorf("session = %+v", s)
	}
	if !s.ExpiresAt.After(s.CreatedAt) || s.LastSeenAt.Before(s.CreatedAt) {
		t.Errorf("session times = %+v", s)
	}
}

// What a browser sends is kept for display, within bounds.
func TestCreateSessionTruncatesRequestDetails(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	hash := sha256.Sum256([]byte("t"))
	// A multi-byte character straddling the limit must not be split.
	agent := strings.Repeat("a", maxUserAgentBytes-1) + "é" + strings.Repeat("b", 1000)
	_, err := d.CreateSession(ctx, NewSession{
		TokenHash: hash[:], UserID: mustUser(t, d, "dev@example.com"), ExpiresAt: time.Now().Add(time.Hour),
		UserAgent: agent, IP: strings.Repeat("1", 500),
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := d.ListSessions(ctx, mustUser(t, d, "dev@example.com"))
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions = %+v, %v", sessions, err)
	}
	if got := sessions[0].UserAgent; got != strings.Repeat("a", maxUserAgentBytes-1) {
		t.Errorf("user agent kept %d bytes: %q…", len(got), got[:min(len(got), 16)])
	}
	if got := sessions[0].IP; len(got) != maxIPBytes {
		t.Errorf("ip kept %d bytes, want %d", len(got), maxIPBytes)
	}
}

func TestTruncateUTF8(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly", 7, "exactly"},
		{"abcdef", 3, "abc"},
		{"aé", 2, "a"},
		{"aéb", 3, "aé"},
		{"a\xffb", 10, "ab"},
		{"", 5, ""},
	}
	for _, tc := range tests {
		if got := truncateUTF8(tc.in, tc.n); got != tc.want {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
