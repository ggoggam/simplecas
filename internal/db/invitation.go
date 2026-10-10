package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// An invitation is how an email address becomes a membership. An owner
// addresses one to an email; it grants nothing until a signed-in user whose
// provider has verified that address accepts it, and the membership that
// results belongs to that user, not to the address. Accepting needs the user's
// consent, and an invitation lapses after its TTL, so a mailbox that changes
// hands later inherits nothing.

// unexpired is the predicate every read of a live invitation applies. An
// expired row is treated as absent; it lingers only until the next invitation
// to the same tenant purges it.
const unexpired = "(i.expires_at IS NULL OR i.expires_at > now())"

const invitationColumns = `t.name, i.email, i.role, COALESCE(u.email, ''), i.created_at, i.expires_at
	FROM tenant_invitations i
	JOIN tenants t ON t.id = i.tenant_id
	LEFT JOIN users u ON u.id = i.invited_by`

// Invite offers email membership of tenantID with role, for ttl. Inviting an
// address that already has a pending invitation replaces it — new role, new
// inviter, a fresh expiry — so re-sending is how an owner extends one.
func (d *DB) Invite(ctx context.Context, tenantID int64, email, role string, invitedBy int64, ttl time.Duration) error {
	return d.audited(ctx, func(tx pgx.Tx, record recordFunc) error {
		_, err := tx.Exec(ctx, `
			DELETE FROM tenant_invitations
			WHERE tenant_id = $1 AND expires_at <= now()`, tenantID)
		if err != nil {
			return apperr.Internal(err)
		}
		var expiresAt time.Time
		err = tx.QueryRow(ctx, `
			INSERT INTO tenant_invitations (tenant_id, email, role, invited_by, expires_at)
			VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))
			ON CONFLICT (tenant_id, email) DO UPDATE SET
			    role       = EXCLUDED.role,
			    invited_by = EXCLUDED.invited_by,
			    created_at = now(),
			    expires_at = EXCLUDED.expires_at
			RETURNING expires_at`,
			tenantID, email, role, invitedBy, ttl.Seconds()).Scan(&expiresAt)
		if err != nil {
			return apperr.Internal(err)
		}
		return record(&tenantID, EventInvitationCreate, email, map[string]any{
			"role": role, "expires_at": expiresAt.UTC(),
		})
	})
}

// ListInvitations returns tenantID's live invitations, newest first.
func (d *DB) ListInvitations(ctx context.Context, tenantID int64) ([]Invitation, error) {
	rows, err := d.pool.Query(ctx, "SELECT "+invitationColumns+`
		WHERE i.tenant_id = $1 AND `+unexpired+`
		ORDER BY i.created_at DESC, i.email`, tenantID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Invitation])
	return out, apperr.Internal(err)
}

// PendingInvitations returns the live invitations addressed to email, in
// tenant name order. email must be a verified, normalised address: whoever
// holds it may accept them.
func (d *DB) PendingInvitations(ctx context.Context, email string) ([]Invitation, error) {
	rows, err := d.pool.Query(ctx, "SELECT "+invitationColumns+`
		WHERE i.email = $1 AND `+unexpired+`
		ORDER BY t.name`, email)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Invitation])
	return out, apperr.Internal(err)
}

// RevokeInvitation withdraws a pending invitation. Withdrawing one that does
// not exist succeeds, so the call is idempotent.
func (d *DB) RevokeInvitation(ctx context.Context, tenantID int64, email string) error {
	return d.audited(ctx, func(tx pgx.Tx, record recordFunc) error {
		var role string
		err := tx.QueryRow(ctx,
			"DELETE FROM tenant_invitations WHERE tenant_id = $1 AND email = $2 RETURNING role",
			tenantID, email).Scan(&role)
		if notFound(err) {
			return nil
		}
		if err != nil {
			return apperr.Internal(err)
		}
		return record(&tenantID, EventInvitationRevoke, email, map[string]any{"role": role})
	})
}

// AcceptInvitation turns the live invitation of email to tenantName into a
// membership for userID, with the invitation's role, and consumes it. The
// caller must have established that userID's provider verified email.
//
// A user who is already a member keeps the role they have: an invitation adds
// people, and changing a member's role is SetMemberRole's job, with its
// last-owner check.
func (d *DB) AcceptInvitation(ctx context.Context, tenantName, email string, userID int64) error {
	return d.audited(ctx, func(tx pgx.Tx, record recordFunc) error {
		var (
			tenantID int64
			role     string
		)
		// Locking the invitation makes a concurrent accept or revoke of the
		// same one wait, then find it gone.
		err := tx.QueryRow(ctx, `
			SELECT i.tenant_id, i.role
			FROM tenant_invitations i
			JOIN tenants t ON t.id = i.tenant_id
			WHERE t.name = $1 AND i.email = $2 AND `+unexpired+`
			FOR UPDATE OF i`, tenantName, email).Scan(&tenantID, &role)
		if notFound(err) {
			return apperr.ErrNoSuchInvitation
		}
		if err != nil {
			return apperr.Internal(err)
		}

		tag, err := tx.Exec(ctx, `
			INSERT INTO tenant_members (tenant_id, user_id, role) VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, user_id) DO NOTHING`,
			tenantID, userID, role)
		if err != nil {
			return apperr.Internal(err)
		}
		_, err = tx.Exec(ctx,
			"DELETE FROM tenant_invitations WHERE tenant_id = $1 AND email = $2",
			tenantID, email)
		if err != nil {
			return apperr.Internal(err)
		}
		// joined is false for someone who was already a member, whose role
		// the invitation did not change.
		return record(&tenantID, EventInvitationAccept, email, map[string]any{
			"user_id": userID, "role": role, "joined": tag.RowsAffected() == 1,
		})
	})
}

// DeclineInvitation discards the live invitation of email to tenantName.
func (d *DB) DeclineInvitation(ctx context.Context, tenantName, email string) error {
	return d.audited(ctx, func(tx pgx.Tx, record recordFunc) error {
		var (
			tenantID int64
			role     string
		)
		err := tx.QueryRow(ctx, `
			DELETE FROM tenant_invitations i
			USING tenants t
			WHERE t.id = i.tenant_id AND t.name = $1 AND i.email = $2 AND `+unexpired+`
			RETURNING i.tenant_id, i.role`,
			tenantName, email).Scan(&tenantID, &role)
		if notFound(err) {
			return apperr.ErrNoSuchInvitation
		}
		if err != nil {
			return apperr.Internal(err)
		}
		return record(&tenantID, EventInvitationDecline, email, map[string]any{"role": role})
	})
}
