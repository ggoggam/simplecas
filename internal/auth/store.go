package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/db"
)

// touchInterval is how stale a session's last_seen_at may get before a request
// moves it forward. The sessions list only needs it to the nearest few
// minutes, and this keeps a busy session from being a write per request.
const touchInterval = 5 * time.Minute

// SessionStore keeps sessions and the users they belong to. A server uses
// *db.DB; the handlers take an interface so they can be tested without a
// database.
type SessionStore interface {
	ResolveUser(ctx context.Context, issuer, subject, email, name string) (db.User, error)
	CreateSession(ctx context.Context, s db.NewSession) (uuid.UUID, error)
	TouchSession(ctx context.Context, tokenHash []byte, issuer, subject string, touchAfter time.Duration) (db.LiveSession, bool, error)
	DeleteSessionByToken(ctx context.Context, tokenHash []byte) error
}

// authenticate returns the caller's session if their cookie is genuine and its
// row is still there and unexpired, with the row's id and user id filled in.
// nil with no error means signed out, whether there was no cookie, a forged or
// pre-upgrade one, or a session that has been revoked or has lapsed; an error
// means the database could not say.
func (r *Registry) authenticate(req *http.Request) (*Session, error) {
	session, token := sessionFromCookie(req, r.cfg)
	if session == nil {
		return nil, nil
	}
	live, ok, err := r.store.TouchSession(req.Context(), hashToken(token),
		session.Issuer, session.Subject, touchInterval)
	if err != nil || !ok {
		return nil, err
	}
	session.ID, session.UserID = live.ID, live.UserID
	return session, nil
}

// openSession records a session for an identity that has just signed in,
// creating its user on first sight, and returns the cookie value that carries
// it.
//
// The user's email and name are refreshed here, from what the provider has
// just asserted, and nowhere else: a session's claims do not change after it
// is opened.
func (r *Registry) openSession(req *http.Request, s *Session) (string, error) {
	ctx := req.Context()
	user, err := r.store.ResolveUser(ctx, s.Issuer, s.Subject, s.VerifiedEmail(), s.Name)
	if err != nil {
		return "", err
	}
	token := randomToken()
	_, err = r.store.CreateSession(ctx, db.NewSession{
		TokenHash: hashToken(token),
		UserID:    user.ID,
		ExpiresAt: time.Unix(s.Expires, 0),
		UserAgent: req.UserAgent(),
		IP:        clientIP(req),
	})
	if err != nil {
		return "", err
	}
	return signSession(r.cfg.SessionSecret, *s, token)
}

// closeSession deletes the row behind the caller's session cookie, if it
// carries a genuine one. Holding the token is all the authority this needs.
func (r *Registry) closeSession(req *http.Request) error {
	session, token := sessionFromCookie(req, r.cfg)
	if session == nil {
		return nil
	}
	return r.store.DeleteSessionByToken(req.Context(), hashToken(token))
}
