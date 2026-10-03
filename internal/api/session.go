package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/auth"
	"github.com/ggoggam/simplecas/internal/db"
)

// A user's sessions are their sign-ins, one per browser. They can see where
// they are signed in and end any of those sessions, which takes effect on that
// browser's next request. Each endpoint touches only the caller's own sessions;
// another user's session id is NoSuchSession, as if it did not exist.

type sessionJSON struct {
	// ID addresses the session in the revoke endpoint.
	ID         uuid.UUID `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// UserAgent and IP are what the browser sent when it signed in, for
	// display only. The IP is the peer address, which behind a reverse proxy
	// is the proxy's.
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
	// Current marks the session making this request.
	Current bool `json:"current"`
}

// revokedJSON reports how many sessions a bulk revocation ended.
type revokedJSON struct {
	Revoked int64 `json:"revoked"`
}

// callerSession returns the signed-in caller and the id of the session they
// are calling with: uuid.Nil for a session that was attached without being
// checked against the sessions table, which has no row to call current.
func callerSession(r *http.Request) (db.User, uuid.UUID, error) {
	user, err := requireUser(r)
	if err != nil {
		return db.User{}, uuid.Nil, err
	}
	return user, auth.FromContext(r.Context()).ID, nil
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	user, current, err := callerSession(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	sessions, err := h.db.ListSessions(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	out := make([]sessionJSON, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionJSON{
			ID: s.ID, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt,
			UserAgent: s.UserAgent, IP: s.IP,
			Current: current != uuid.Nil && s.ID == current,
		})
	}
	h.writeJSON(w, http.StatusOK, out)
}

// revokeSession ends one of the caller's sessions. Ending the current one is
// allowed and signs this browser out on its next request, though logout is the
// way to do that and clear the cookie too.
func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	user, _, err := callerSession(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, apperr.InvalidArgument("session id must be a UUID"))
		return
	}
	if err := h.db.RevokeSession(r.Context(), user.ID, id); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeOtherSessions signs the caller out everywhere but here.
func (h *Handler) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	user, current, err := callerSession(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	// Without a current session to keep this would end every one of them,
	// which is not what was asked.
	if current == uuid.Nil {
		h.writeError(w, r, apperr.Forbidden("this request carries no stored session to keep"))
		return
	}
	n, err := h.db.RevokeOtherSessions(r.Context(), user.ID, current)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, revokedJSON{Revoked: n})
}

// revokeAllSessions signs the caller out everywhere, here included. The cookie
// is left to the caller to clear with logout, which the PWA does next.
func (h *Handler) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	user, _, err := callerSession(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	n, err := h.db.RevokeAllSessions(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, revokedJSON{Revoked: n})
}
