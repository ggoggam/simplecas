package db

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// Membership is keyed by user id, which is keyed by the identity provider's
// (issuer, subject). An email address grants nothing by itself: it addresses an
// invitation (see invitation.go), and a membership exists only once a
// signed-in user accepts one.

// ListTenantsForUser returns the tenants userID belongs to, each with the
// caller's own role, in name order.
func (d *DB) ListTenantsForUser(ctx context.Context, userID int64) ([]TenantMembership, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT t.name, m.role, t.created_at
		FROM tenants t
		JOIN tenant_members m ON m.tenant_id = t.id
		WHERE m.user_id = $1
		ORDER BY t.name`, userID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[TenantMembership])
	return out, apperr.Internal(err)
}

// TenantIDsForUser returns the tenant ids userID belongs to, for scoping
// listings and stats.
func (d *DB) TenantIDsForUser(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := d.pool.Query(ctx,
		"SELECT tenant_id FROM tenant_members WHERE user_id = $1", userID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	// Never nil: the caller passes this straight into `= ANY($1)`.
	if ids == nil {
		ids = []int64{}
	}
	return ids, nil
}

// TenantIDByName resolves a tenant name to its id.
func (d *DB) TenantIDByName(ctx context.Context, name string) (int64, error) {
	var id int64
	err := d.pool.QueryRow(ctx, "SELECT id FROM tenants WHERE name = $1", name).Scan(&id)
	if notFound(err) {
		return 0, apperr.ErrNoSuchTenant
	}
	if err != nil {
		return 0, apperr.Internal(err)
	}
	return id, nil
}

// TenantRole returns userID's role in tenantID, or ok=false when they are not a
// member.
func (d *DB) TenantRole(ctx context.Context, tenantID, userID int64) (role string, ok bool, err error) {
	err = d.pool.QueryRow(ctx,
		"SELECT role FROM tenant_members WHERE tenant_id = $1 AND user_id = $2",
		tenantID, userID).Scan(&role)
	if notFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, apperr.Internal(err)
	}
	return role, true, nil
}

// CreateTenant creates a tenant with ownerID as its sole owner. Both rows go in
// together, so a tenant never exists without an owner.
func (d *DB) CreateTenant(ctx context.Context, name string, ownerID int64) (int64, error) {
	var id int64
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			"INSERT INTO tenants (name) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id",
			name).Scan(&id)
		if notFound(err) {
			return apperr.ErrTenantAlreadyExists
		}
		if err != nil {
			return apperr.Internal(err)
		}
		_, err = tx.Exec(ctx,
			"INSERT INTO tenant_members (tenant_id, user_id, role) VALUES ($1, $2, 'owner')",
			id, ownerID)
		return apperr.Internal(err)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ListMembers returns a tenant's membership, ordered by email and then by user
// id so members with no address still list in a stable order.
func (d *DB) ListMembers(ctx context.Context, tenantID int64) ([]Member, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT u.id, u.email, u.name, m.role, m.created_at
		FROM tenant_members m
		JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1
		ORDER BY u.email, u.id`, tenantID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
	return out, apperr.Internal(err)
}

// lockTenant serialises membership changes within one tenant.
//
// The last-owner checks below count owners and then write. Locking only the
// member row being changed is not enough under READ COMMITTED: two owners
// removing (or demoting) each other at once would each lock their own target,
// each count two owners, and together leave none. Taking the tenant row first
// makes the second change wait and then count what the first left behind.
//
// NO KEY UPDATE rather than UPDATE, so it does not also block the foreign-key
// checks of unrelated inserts that reference the tenant.
func lockTenant(ctx context.Context, tx pgx.Tx, tenantID int64) error {
	var id int64
	err := tx.QueryRow(ctx,
		"SELECT id FROM tenants WHERE id = $1 FOR NO KEY UPDATE", tenantID).Scan(&id)
	if notFound(err) {
		return apperr.ErrNoSuchTenant
	}
	return apperr.Internal(err)
}

// otherOwners counts tenantID's owners other than userID. Call it only with the
// tenant locked.
func otherOwners(ctx context.Context, tx pgx.Tx, tenantID, userID int64) (int64, error) {
	var n int64
	err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM tenant_members
		WHERE tenant_id = $1 AND role = 'owner' AND user_id <> $2`,
		tenantID, userID).Scan(&n)
	return n, apperr.Internal(err)
}

// SetMemberRole changes an existing member's role, refusing to demote a
// tenant's last owner — which would leave it unmanageable.
func (d *DB) SetMemberRole(ctx context.Context, tenantID, userID int64, role string) error {
	return d.InTx(ctx, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		var current string
		err := tx.QueryRow(ctx,
			"SELECT role FROM tenant_members WHERE tenant_id = $1 AND user_id = $2",
			tenantID, userID).Scan(&current)
		if notFound(err) {
			return apperr.ErrNoSuchMember
		}
		if err != nil {
			return apperr.Internal(err)
		}
		if current == role {
			return nil
		}

		if current == "owner" {
			owners, err := otherOwners(ctx, tx, tenantID, userID)
			if err != nil {
				return err
			}
			if owners == 0 {
				return apperr.InvalidArgument("cannot demote the last owner of a tenant")
			}
		}

		_, err = tx.Exec(ctx,
			"UPDATE tenant_members SET role = $3 WHERE tenant_id = $1 AND user_id = $2",
			tenantID, userID, role)
		return apperr.Internal(err)
	})
}

// RemoveMember removes a member, refusing to strip a tenant of its last owner.
// Removing someone who is not a member succeeds, so the call is idempotent.
func (d *DB) RemoveMember(ctx context.Context, tenantID, userID int64) error {
	return d.InTx(ctx, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		var role string
		err := tx.QueryRow(ctx,
			"SELECT role FROM tenant_members WHERE tenant_id = $1 AND user_id = $2",
			tenantID, userID).Scan(&role)
		if notFound(err) {
			return nil
		}
		if err != nil {
			return apperr.Internal(err)
		}

		if role == "owner" {
			owners, err := otherOwners(ctx, tx, tenantID, userID)
			if err != nil {
				return err
			}
			if owners == 0 {
				return apperr.InvalidArgument("cannot remove the last owner of a tenant")
			}
		}

		_, err = tx.Exec(ctx,
			"DELETE FROM tenant_members WHERE tenant_id = $1 AND user_id = $2",
			tenantID, userID)
		return apperr.Internal(err)
	})
}

// DeleteTenant deletes an empty tenant; its membership, invitations and S3
// credentials cascade. A tenant that still owns namespaces is a conflict,
// mirroring non-empty namespace deletion.
func (d *DB) DeleteTenant(ctx context.Context, tenantID int64) error {
	return d.InTx(ctx, func(tx pgx.Tx) error {
		var occupied bool
		err := tx.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM namespaces WHERE tenant_id = $1)",
			tenantID).Scan(&occupied)
		if err != nil {
			return apperr.Internal(err)
		}
		if occupied {
			return apperr.ErrTenantNotEmpty
		}
		_, err = tx.Exec(ctx, "DELETE FROM tenants WHERE id = $1", tenantID)
		return apperr.Internal(err)
	})
}
