package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// These tests run sign-in, the guard and logout against Postgres, so the
// session lifecycle is checked through the same queries a server makes.

type dbFixture struct {
	reg  *Registry
	idp  *fakeIdP
	db   *db.DB
	pool *pgxpool.Pool
}

func newDBFixture(t *testing.T) *dbFixture {
	t.Helper()
	dsn := testdb.URL(t)
	database, err := db.Connect(t.Context(), dsn, 4)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)
	// A raw pool for the assertions and adjustments no server path makes.
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	t.Cleanup(pool.Close)

	idp := newFakeIdP(t)
	return &dbFixture{
		reg:  flowRegistryWith(t, idp, &config.OidcConfig{}, database),
		idp:  idp,
		db:   database,
		pool: pool,
	}
}

// login runs the whole authorization-code flow from a browser sending
// userAgent, and returns the session cookie it ends with.
func (f *dbFixture) login(t *testing.T, userAgent string) *http.Cookie {
	t.Helper()
	authURL, flow := start(t, f.reg, "")
	f.idp.nonce = authURL.Query().Get("nonce")
	f.idp.claims = map[string]any{"email": "dev@example.com", "email_verified": true, "name": "Dev"}

	query := url.Values{"code": {"c"}, "state": {authURL.Query().Get("state")}}
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/fake/callback?"+query.Encode(), nil)
	r.Header.Set("User-Agent", userAgent)
	r.AddCookie(flow)
	w := httptest.NewRecorder()
	f.reg.Handler().ServeHTTP(w, r)

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatalf("no session cookie was issued; Location = %s", w.Header().Get("Location"))
	return nil
}

// userID is the id of the user the fake provider signs in.
func (f *dbFixture) userID(t *testing.T) int64 {
	t.Helper()
	var id int64
	err := f.pool.QueryRow(t.Context(),
		"SELECT id FROM users WHERE issuer = $1 AND subject = 'sub-abc'", f.idp.server.URL).Scan(&id)
	if err != nil {
		t.Fatalf("look up user: %v", err)
	}
	return id
}

// guarded sends a request carrying cookie through the guard to path and
// returns the session it reached the handler with, or nil and the status.
func (f *dbFixture) guarded(t *testing.T, path string, cookie *http.Cookie) (*Session, int) {
	t.Helper()
	var seen *Session
	h := f.reg.Guard(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = FromContext(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return seen, w.Code
}

// assertSignedOut checks that cookie no longer opens anything: the API says
// 401, a page goes to the login page, and the login page offers sign-in
// rather than bouncing back to the PWA, which would loop.
func (f *dbFixture) assertSignedOut(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if seen, status := f.guarded(t, "/api/stats", cookie); seen != nil || status != http.StatusUnauthorized {
		t.Errorf("API: session=%+v status=%d, want a 401", seen, status)
	}
	if seen, status := f.guarded(t, "/ui/", cookie); seen != nil || status != http.StatusSeeOther {
		t.Errorf("page: session=%+v status=%d, want a redirect to sign in", seen, status)
	}

	for path, want := range map[string]int{"/auth/login?redirect=/ui/": http.StatusOK, "/auth/me": http.StatusUnauthorized} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.reg.Handler().ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s status = %d, want %d", path, w.Code, want)
		}
	}
}

func TestLoginCreatesASessionRow(t *testing.T) {
	f := newDBFixture(t)
	cookie := f.login(t, "Mozilla/5.0 (test)")

	sessions, err := f.db.ListSessions(t.Context(), f.userID(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v, want the one just opened", sessions)
	}
	s := sessions[0]
	if s.UserAgent != "Mozilla/5.0 (test)" || s.IP != "192.0.2.1" {
		t.Errorf("session = %+v, want the signing-in browser's agent and address", s)
	}
	if got := s.ExpiresAt.Sub(s.CreatedAt).Seconds(); got < 3590 || got > 3610 {
		t.Errorf("session lasts %.0fs, want the configured 3600", got)
	}

	// Only the token's hash is stored, never the token.
	_, token := sessionFromCookie(requestWith(cookie), f.reg.cfg)
	var stored []byte
	if err := f.pool.QueryRow(t.Context(), "SELECT token_hash FROM sessions").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(hashToken(token)) {
		t.Error("the stored hash is not the cookie token's")
	}

	// The cookie opens the API, carrying the row's ids.
	seen, status := f.guarded(t, "/api/stats", cookie)
	if status != http.StatusOK || seen == nil {
		t.Fatalf("status = %d, want the guard to let the session through", status)
	}
	if seen.ID != s.ID || seen.UserID != f.userID(t) {
		t.Errorf("session in context = %+v, want row %s of user %d", seen, s.ID, f.userID(t))
	}

	// A second sign-in is a second session.
	f.login(t, "Other/1.0")
	sessions, err = f.db.ListSessions(t.Context(), f.userID(t))
	if err != nil || len(sessions) != 2 {
		t.Errorf("sessions = %+v, %v; want two", sessions, err)
	}
}

func TestRevokedSessionIsSignedOut(t *testing.T) {
	f := newDBFixture(t)
	revoked := f.login(t, "A")
	kept := f.login(t, "B")

	seen, _ := f.guarded(t, "/api/stats", revoked)
	if seen == nil {
		t.Fatal("the session was not live to begin with")
	}
	if err := f.db.RevokeSession(t.Context(), seen.UserID, seen.ID); err != nil {
		t.Fatal(err)
	}

	f.assertSignedOut(t, revoked)
	if seen, _ := f.guarded(t, "/api/stats", kept); seen == nil {
		t.Error("revoking one session signed out another")
	}
}

// The row's expiry decides, even while the cookie's own claim is still good.
func TestExpiredSessionIsSignedOut(t *testing.T) {
	f := newDBFixture(t)
	cookie := f.login(t, "A")

	_, err := f.pool.Exec(t.Context(), "UPDATE sessions SET expires_at = now() - interval '1 second'")
	if err != nil {
		t.Fatal(err)
	}
	if cookieClaims(requestWith(cookie), f.reg.cfg) == nil {
		t.Fatal("the cookie itself should still be unexpired")
	}
	f.assertSignedOut(t, cookie)
}

func TestLogoutDeletesTheSessionRow(t *testing.T) {
	f := newDBFixture(t)
	cookie := f.login(t, "A")
	other := f.login(t, "B")

	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.reg.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || !sessionCleared(w, sessionCookie) {
		t.Fatalf("status = %d, cookies = %v", w.Code, w.Result().Cookies())
	}

	sessions, err := f.db.ListSessions(t.Context(), f.userID(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].UserAgent != "B" {
		t.Errorf("sessions = %+v, want only the other browser's", sessions)
	}
	// A copy of the signed-out cookie is dead; the other browser is not.
	f.assertSignedOut(t, cookie)
	if seen, _ := f.guarded(t, "/api/stats", other); seen == nil {
		t.Error("signing out one browser signed out another")
	}
}
