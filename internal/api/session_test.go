package api

import (
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/auth"
	"github.com/ggoggam/simplecas/internal/db"
)

// openSession signs email in on a new browser: a sessions row, and a caller
// carrying its ids the way the guard attaches them after checking the cookie.
// The caller is the new session afterwards.
func (f *fixture) openSession(t *testing.T, email, userAgent string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	user, err := f.db.ResolveUser(ctx, testIssuer, "sub-"+email, email, "")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(uuid.NewString()))
	id, err := f.db.CreateSession(ctx, db.NewSession{
		TokenHash: hash[:], UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour),
		UserAgent: userAgent, IP: "192.0.2.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.caller = &auth.Session{
		Issuer: testIssuer, Subject: "sub-" + email, Email: email, EmailVerified: true, Provider: "test",
		ID: id, UserID: user.ID,
	}
	return id
}

// listSessions is the caller's sessions list, by id.
func listSessions(t *testing.T, f *fixture) map[string]map[string]any {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/me/sessions", "")
	mustStatus(t, w, http.StatusOK)
	out := map[string]map[string]any{}
	for _, s := range decodeArray(t, w) {
		out[s["id"].(string)] = s
	}
	return out
}

func TestSessionEndpointsRequireSignIn(t *testing.T) {
	f := newFixture(t)

	// With OIDC off there are no sessions, and these answer like every other
	// endpoint that needs a user.
	for _, req := range [][2]string{
		{http.MethodGet, "/api/me/sessions"},
		{http.MethodDelete, "/api/me/sessions/" + uuid.NewString()},
		{http.MethodPost, "/api/me/sessions/revoke-others"},
		{http.MethodPost, "/api/me/sessions/revoke-all"},
	} {
		w := f.do(t, req[0], req[1], "")
		mustStatus(t, w, http.StatusForbidden)
		if code, _ := errorBody(t, w); code != "AccessDenied" {
			t.Errorf("%s %s code = %q", req[0], req[1], code)
		}
	}
}

func TestListSessions(t *testing.T) {
	f := newFixture(t)
	f.openSession(t, "other@example.com", "Theirs/1.0")
	laptop := f.openSession(t, "dev@example.com", "Laptop/1.0")
	phone := f.openSession(t, "dev@example.com", "Phone/1.0")

	sessions := listSessions(t, f)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %#v, want the caller's two and nobody else's", sessions)
	}
	// The PWA's Session type.
	current := sessions[phone.String()]
	for _, key := range []string{"id", "created_at", "last_seen_at", "expires_at", "user_agent", "ip", "current"} {
		if _, ok := current[key]; !ok {
			t.Errorf("missing %s: %#v", key, current)
		}
	}
	if current["user_agent"] != "Phone/1.0" || current["ip"] != "192.0.2.1" || current["current"] != true {
		t.Errorf("current session = %#v", current)
	}
	if other := sessions[laptop.String()]; other["current"] != false || other["user_agent"] != "Laptop/1.0" {
		t.Errorf("other session = %#v", other)
	}
}

func TestRevokeOneOfMySessions(t *testing.T) {
	f := newFixture(t)
	laptop := f.openSession(t, "dev@example.com", "Laptop/1.0")
	phone := f.openSession(t, "dev@example.com", "Phone/1.0")

	mustStatus(t, f.do(t, http.MethodDelete, "/api/me/sessions/"+laptop.String(), ""), http.StatusNoContent)

	sessions := listSessions(t, f)
	if _, ok := sessions[laptop.String()]; ok || len(sessions) != 1 {
		t.Errorf("sessions = %#v, want only %s", sessions, phone)
	}

	// Gone is gone.
	w := f.do(t, http.MethodDelete, "/api/me/sessions/"+laptop.String(), "")
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchSession" {
		t.Errorf("code = %q", code)
	}

	w = f.do(t, http.MethodDelete, "/api/me/sessions/not-a-uuid", "")
	mustStatus(t, w, http.StatusBadRequest)
	if code, _ := errorBody(t, w); code != "InvalidArgument" {
		t.Errorf("code = %q", code)
	}
}

// Someone else's session id is not found, exactly as an id nobody holds, and
// survives the attempt.
func TestCannotRevokeAnotherUsersSession(t *testing.T) {
	f := newFixture(t)
	theirs := f.openSession(t, "other@example.com", "Theirs/1.0")
	f.openSession(t, "dev@example.com", "Mine/1.0")

	w := f.do(t, http.MethodDelete, "/api/me/sessions/"+theirs.String(), "")
	mustStatus(t, w, http.StatusNotFound)
	if code, _ := errorBody(t, w); code != "NoSuchSession" {
		t.Errorf("code = %q", code)
	}

	f.openSession(t, "other@example.com", "Theirs/2.0")
	if _, ok := listSessions(t, f)[theirs.String()]; !ok {
		t.Error("their session was revoked by someone else")
	}
}

func TestRevokeOtherSessionsKeepsTheCurrentOne(t *testing.T) {
	f := newFixture(t)
	f.openSession(t, "dev@example.com", "A")
	f.openSession(t, "dev@example.com", "B")
	theirs := f.openSession(t, "other@example.com", "Theirs")
	current := f.openSession(t, "dev@example.com", "C")

	w := f.do(t, http.MethodPost, "/api/me/sessions/revoke-others", "")
	mustStatus(t, w, http.StatusOK)
	if got := decodeObject(t, w)["revoked"]; got != float64(2) {
		t.Errorf("revoked = %v, want 2", got)
	}

	sessions := listSessions(t, f)
	if s, ok := sessions[current.String()]; !ok || len(sessions) != 1 || s["current"] != true {
		t.Errorf("sessions = %#v, want only the current one", sessions)
	}

	f.openSession(t, "other@example.com", "Theirs again")
	if _, ok := listSessions(t, f)[theirs.String()]; !ok {
		t.Error("another user's session was revoked")
	}
}

// A caller attached without a session row has nothing to keep, so "everywhere
// else" would mean everywhere; it is refused rather than guessed at.
func TestRevokeOtherSessionsNeedsACurrentSession(t *testing.T) {
	f := newFixture(t)
	f.openSession(t, "dev@example.com", "A")
	f.signIn("dev@example.com")

	mustStatus(t, f.do(t, http.MethodPost, "/api/me/sessions/revoke-others", ""), http.StatusForbidden)
	sessions := listSessions(t, f)
	if len(sessions) != 1 {
		t.Errorf("sessions = %#v, want the one left alone", sessions)
	}
	for _, s := range sessions {
		if s["current"] != false {
			t.Errorf("session %v is marked current for a caller with none", s["id"])
		}
	}
}

func TestRevokeAllSessions(t *testing.T) {
	f := newFixture(t)
	f.openSession(t, "other@example.com", "Theirs")
	f.openSession(t, "dev@example.com", "A")
	f.openSession(t, "dev@example.com", "B")

	w := f.do(t, http.MethodPost, "/api/me/sessions/revoke-all", "")
	mustStatus(t, w, http.StatusOK)
	if got := decodeObject(t, w)["revoked"]; got != float64(2) {
		t.Errorf("revoked = %v, want 2", got)
	}
	if got := strings.TrimSpace(f.do(t, http.MethodGet, "/api/me/sessions", "").Body.String()); got != "[]" {
		t.Errorf("sessions after revoking all = %s, want []", got)
	}

	f.openSession(t, "other@example.com", "Theirs again")
	if n := len(listSessions(t, f)); n != 2 {
		t.Errorf("the other user has %d sessions, want both", n)
	}
}

// Revoking is a state change, so it is refused from another site.
func TestRevokingSessionsIsRefusedCrossSite(t *testing.T) {
	f := newFixture(t)
	f.openSession(t, "dev@example.com", "A")

	w := f.do(t, http.MethodPost, "/api/me/sessions/revoke-all", "",
		"Sec-Fetch-Site", "cross-site")
	mustStatus(t, w, http.StatusForbidden)
	if n := len(listSessions(t, f)); n != 1 {
		t.Errorf("%d sessions left, want the one untouched", n)
	}
}
