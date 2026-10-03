package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
)

// memStore is a SessionStore in memory, for the handler tests that need live
// sessions but not a database. The database-backed tests in session_db_test.go
// run the same flows against *db.DB.
type memStore struct {
	mu       sync.Mutex
	users    map[[2]string]int64
	sessions map[string]memSession
	// err, when set, fails every call.
	err error
}

type memSession struct {
	id       uuid.UUID
	userID   int64
	identity [2]string
	expires  time.Time
}

func newMemStore() *memStore {
	return &memStore{users: map[[2]string]int64{}, sessions: map[string]memSession{}}
}

func (m *memStore) ResolveUser(_ context.Context, issuer, subject, email, name string) (db.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return db.User{}, m.err
	}
	key := [2]string{issuer, subject}
	id, ok := m.users[key]
	if !ok {
		id = int64(len(m.users) + 1)
		m.users[key] = id
	}
	return db.User{ID: id, Email: email, Name: name}, nil
}

func (m *memStore) CreateSession(_ context.Context, s db.NewSession) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return uuid.Nil, m.err
	}
	var identity [2]string
	for k, id := range m.users {
		if id == s.UserID {
			identity = k
		}
	}
	id := uuid.New()
	m.sessions[string(s.TokenHash)] = memSession{
		id: id, userID: s.UserID, identity: identity, expires: s.ExpiresAt,
	}
	return id, nil
}

func (m *memStore) TouchSession(_ context.Context, tokenHash []byte, issuer, subject string, _ time.Duration) (db.LiveSession, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return db.LiveSession{}, false, m.err
	}
	s, ok := m.sessions[string(tokenHash)]
	if !ok || !time.Now().Before(s.expires) || s.identity != [2]string{issuer, subject} {
		return db.LiveSession{}, false, nil
	}
	return db.LiveSession{ID: s.id, UserID: s.userID}, true, nil
}

func (m *memStore) DeleteSessionByToken(_ context.Context, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	delete(m.sessions, string(tokenHash))
	return nil
}

// count is how many sessions the store holds.
func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// signIn opens a live session for s the way a completed login does, and
// returns the cookie that carries it.
func (r *Registry) signIn(t *testing.T, s Session) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/fake/callback", nil)
	token, err := r.openSession(req, &s)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	return setCookie(sessionCookie, token, 3600, secureCookies(r.cfg))
}

// liveSession is a session that expires in an hour.
func liveSession(subject string) Session {
	return Session{
		Issuer: "https://idp.test", Subject: subject, Provider: "google",
		Expires: time.Now().Add(time.Hour).Unix(),
	}
}

// A cookie names its row by token and identity together: the row of one user
// does not admit a cookie claiming to be another.
func TestAuthenticateBindsTheTokenToItsIdentity(t *testing.T) {
	reg := testRegistry(t)
	cookie := reg.signIn(t, liveSession("sub-1"))
	_, token := sessionFromCookie(requestWith(cookie), reg.cfg)

	// Re-sign the same token under another subject, as someone holding the
	// signing secret but not the database could.
	other := liveSession("sub-2")
	forged, err := signSession(testSecret, other, token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reg.authenticate(requestWith(setCookie(sessionCookie, forged, 3600, false)))
	if err != nil || got != nil {
		t.Errorf("authenticate = %+v, %v; want no session", got, err)
	}

	if got, err := reg.authenticate(requestWith(cookie)); err != nil || got == nil {
		t.Errorf("the genuine cookie = %+v, %v; want its session", got, err)
	}
}

// requestWith is a page request carrying cookie.
func requestWith(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	r.AddCookie(cookie)
	return r
}

// When the store cannot answer, the guard says so rather than treating the
// caller as signed out (and sending them round the login loop) or as signed in.
func TestGuardReportsAStoreFailure(t *testing.T) {
	reg := testRegistry(t)
	cookie := reg.signIn(t, liveSession("sub-1"))
	reg.store.(*memStore).err = errors.New("database down")

	var reached bool
	guarded := reg.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	for _, path := range []string{"/api/stats", "/ui/"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		if reached || w.Code != http.StatusInternalServerError {
			t.Errorf("%s: reached=%v status=%d, want a 500", path, reached, w.Code)
		}
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	reg := testRegistry(t)
	store := reg.store.(*memStore)
	cookie := reg.signIn(t, liveSession("sub-1"))

	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther || !sessionCleared(w, sessionCookie) {
		t.Fatalf("status = %d, cookies = %v; want a 303 clearing the cookie", w.Code, w.Result().Cookies())
	}
	if n := store.count(); n != 0 {
		t.Errorf("%d sessions left, want the row gone", n)
	}
	// A copy of the cookie kept elsewhere is dead too.
	if got, _ := reg.authenticate(requestWith(cookie)); got != nil {
		t.Error("the signed-out cookie still authenticates")
	}
}

// If the row cannot be deleted, signing out fails visibly and keeps the
// cookie, so trying again can still end the session.
func TestLogoutKeepsTheCookieWhenTheRowCannotBeDeleted(t *testing.T) {
	reg := testRegistry(t)
	cookie := reg.signIn(t, liveSession("sub-1"))
	reg.store.(*memStore).err = errors.New("database down")

	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	reg.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if sessionCleared(w, sessionCookie) {
		t.Error("the cookie was cleared although its session is still live")
	}
}

// A callback that cannot record the session issues no cookie.
func TestCallbackFailsWhenTheSessionCannotBeStored(t *testing.T) {
	idp := newFakeIdP(t)
	store := newMemStore()
	reg := flowRegistryWith(t, idp, &config.OidcConfig{}, store)

	authURL, flow := start(t, reg, "")
	idp.nonce = authURL.Query().Get("nonce")
	store.err = errors.New("database down")

	w := callback(t, reg, flow, url.Values{
		"code": {"c"}, "state": {authURL.Query().Get("state")},
	})
	assertLoginError(t, w, "server_error")
}
