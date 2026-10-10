package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// A team's audit log: who changed its membership, invitations, S3 keys and
// namespaces, newest first. Owner-only, like the invitation and key listings
// whose changes it records. See internal/db/audit.go for what is recorded.

// Audit listing page sizes.
const (
	defaultAuditLimit = 50
	maxAuditLimit     = 500
)

// auditEventJSON is one event. The field names match the keys of the "audit"
// group the server logs for the same event, so one parser reads both.
type auditEventJSON struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	// ActorUserID is null for a change made with an S3 key or through an
	// open plane; ActorAccessKeyID is "" for one made by a signed-in user.
	ActorUserID      *int64         `json:"actor_user_id"`
	ActorEmail       string         `json:"actor_email"`
	ActorAccessKeyID string         `json:"actor_access_key_id"`
	RequestID        string         `json:"request_id"`
	Target           string         `json:"target"`
	Details          map[string]any `json:"details"`
}

type auditPageJSON struct {
	Events []auditEventJSON `json:"events"`
	// NextBefore is the before= value for the next, older page, or null on
	// the last one.
	NextBefore *int64 `json:"next_before"`
}

// listAuditEvents pages a team's events. ?before=<id> continues from an
// earlier page's next_before; ?limit= sets the page size.
func (h *Handler) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	query := r.URL.Query()

	var before int64
	if raw := query.Get("before"); raw != "" {
		before, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || before <= 0 {
			h.writeError(w, r, apperr.InvalidArgument("before must be a positive event id"))
			return
		}
	}
	limit := defaultAuditLimit
	if raw := query.Get("limit"); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil || n < 1 || n > maxAuditLimit {
			h.writeError(w, r, apperr.InvalidArgument("limit must be between 1 and %d", maxAuditLimit))
			return
		}
		limit = n
	}

	// One past the page, to learn whether another follows.
	events, err := h.db.ListAuditEvents(r.Context(), tenantID, before, limit+1)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	out := auditPageJSON{Events: make([]auditEventJSON, 0, min(len(events), limit))}
	for i, ev := range events {
		if i == limit {
			next := events[limit-1].ID
			out.NextBefore = &next
			break
		}
		out.Events = append(out.Events, auditEventJSON{
			ID: ev.ID, At: ev.At, Action: ev.Action,
			ActorUserID: ev.ActorUserID, ActorEmail: ev.ActorEmail, ActorAccessKeyID: ev.ActorAccessKeyID,
			RequestID: ev.RequestID, Target: ev.Target, Details: ev.Details,
		})
	}
	h.writeJSON(w, http.StatusOK, out)
}
