package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/auth"
	"github.com/ggoggam/simplecas/internal/db"
)

// Team membership belongs to users, and users are identity-provider accounts
// (issuer, subject). An owner cannot add someone directly: they invite an email
// address, and the invitation becomes a membership only when a signed-in user
// whose provider has verified that address accepts it. That keeps a membership
// from following an address to whoever controls it later, and gives the
// invitee a say in which teams they join.

// invitationTTL is how long an invitation can be accepted. Re-inviting the same
// address replaces it with a fresh one.
const invitationTTL = 7 * 24 * time.Hour

// parseRole validates a role from a request body; empty means member.
func parseRole(raw string) (string, error) {
	switch raw {
	case "":
		return "member", nil
	case "member", "owner":
		return raw, nil
	default:
		return "", apperr.InvalidArgument("role must be 'owner' or 'member'")
	}
}

// parseUserID reads the {user} path segment.
func parseUserID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("user"), 10, 64)
	if err != nil || id <= 0 {
		return 0, apperr.InvalidArgument("member id must be a positive integer")
	}
	return id, nil
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

type memberJSON struct {
	// ID addresses the member in the role-change and removal endpoints. Email
	// is display only, and empty for a user whose provider verified none.
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	// You marks the caller's own row, which is the one they may remove to
	// leave the team.
	You bool `json:"you"`
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	access, err := h.authorizeTenantAccess(r, r.PathValue("tenant"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	members, err := h.db.ListMembers(r.Context(), access.id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	out := make([]memberJSON, 0, len(members))
	for _, m := range members {
		out = append(out, memberJSON{
			ID: m.UserID, Email: m.Email, Name: m.Name, Role: m.Role, CreatedAt: m.CreatedAt,
			You: m.UserID == access.user.ID,
		})
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) setMemberRole(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	userID, err := parseUserID(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, err)
		return
	}
	if req.Role == "" {
		h.writeError(w, r, apperr.InvalidArgument("role is required"))
		return
	}
	role, err := parseRole(req.Role)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.db.SetMemberRole(r.Context(), tenantID, userID, role); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeMember removes someone from a team. Owners may remove anyone; any
// member may remove themselves, which is how they leave. Either way a team
// keeps at least one owner.
func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	access, err := h.authorizeTenantAccess(r, r.PathValue("tenant"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	userID, err := parseUserID(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if access.role != "owner" && userID != access.user.ID {
		h.writeError(w, r, apperr.Forbidden("owner role required"))
		return
	}
	if err := h.db.RemoveMember(r.Context(), access.id, userID); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Invitations, from the team's side
// ---------------------------------------------------------------------------

type invitationJSON struct {
	Tenant string `json:"tenant"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	// InvitedBy is the inviter's address, or null when they had none.
	InvitedBy *string   `json:"invited_by"`
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is null only for a membership carried over from before
	// invitations existed.
	ExpiresAt *time.Time `json:"expires_at"`
}

func invitationsJSON(invitations []db.Invitation) []invitationJSON {
	out := make([]invitationJSON, 0, len(invitations))
	for _, inv := range invitations {
		j := invitationJSON{
			Tenant: inv.Tenant, Email: inv.Email, Role: inv.Role,
			CreatedAt: inv.CreatedAt, ExpiresAt: inv.ExpiresAt,
		}
		if inv.InvitedBy != "" {
			j.InvitedBy = &inv.InvitedBy
		}
		out = append(out, j)
	}
	return out
}

// listInvitations is owner-only: the people an owner has invited are theirs
// to manage, and are not members yet.
func (h *Handler) listInvitations(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	invitations, err := h.db.ListInvitations(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, invitationsJSON(invitations))
}

func (h *Handler) createInvitation(w http.ResponseWriter, r *http.Request) {
	access, err := h.authorizeTenantAccess(r, r.PathValue("tenant"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if access.role != "owner" {
		h.writeError(w, r, apperr.Forbidden("owner role required"))
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		h.writeError(w, r, err)
		return
	}

	// Normalised the way a login's address is, or the invitation would never
	// match the session that comes to accept it.
	email := auth.NormalizeEmail(req.Email)
	if email == "" || !strings.Contains(email, "@") {
		h.writeError(w, r, apperr.InvalidArgument("a valid email is required"))
		return
	}
	role, err := parseRole(req.Role)
	if err != nil {
		h.writeError(w, r, err)
		return
	}

	if err := h.db.Invite(r.Context(), access.id, email, role, access.user.ID, invitationTTL); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.authorizeTenant(r, r.PathValue("tenant"), true)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	email := auth.NormalizeEmail(r.PathValue("email"))
	if err := h.db.RevokeInvitation(r.Context(), tenantID, email); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Invitations, from the invitee's side
// ---------------------------------------------------------------------------

// myInvitations lists the invitations addressed to the caller's verified
// address. A caller whose provider verified none has nothing addressed to
// them, which is an empty list rather than an error.
func (h *Handler) myInvitations(w http.ResponseWriter, r *http.Request) {
	if _, err := requireUser(r); err != nil {
		h.writeError(w, r, err)
		return
	}
	email := auth.FromContext(r.Context()).VerifiedEmail()
	if email == "" {
		h.writeJSON(w, http.StatusOK, []invitationJSON{})
		return
	}
	invitations, err := h.db.PendingInvitations(r.Context(), email)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, invitationsJSON(invitations))
}

// inviteeEmail returns the signed-in caller and the verified address their
// invitations are matched against, or a 403 when they have none.
func inviteeEmail(r *http.Request) (db.User, string, error) {
	user, err := requireUser(r)
	if err != nil {
		return db.User{}, "", err
	}
	email := auth.FromContext(r.Context()).VerifiedEmail()
	if email == "" {
		return db.User{}, "", apperr.Forbidden("a verified email is required to answer an invitation")
	}
	return user, email, nil
}

func (h *Handler) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	user, email, err := inviteeEmail(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.db.AcceptInvitation(r.Context(), r.PathValue("tenant"), email, user.ID); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) declineInvitation(w http.ResponseWriter, r *http.Request) {
	_, email, err := inviteeEmail(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.db.DeclineInvitation(r.Context(), r.PathValue("tenant"), email); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
