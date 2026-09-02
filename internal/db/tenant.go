package db

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// Membership is keyed by verified email rather than by a user id, because
// invitations are issued by email — before the invitee has ever signed in.

// ListTenantsForEmail returns the tenants email belongs to, each with the
// caller's own role, in name order.
func (d *DB) ListTenantsForEmail(ctx context.Context, email string) ([]TenantMembership, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT t.name, m.role, t.created_at
		FROM tenants t
		JOIN tenant_members m ON m.tenant_id = t.id
		WHERE m.email = $1
		ORDER BY t.name`, email)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[TenantMembership])
	return out, apperr.Internal(err)
}

// TenantIDsForEmail returns the tenant ids email belongs to, for scoping
// listings and stats.
func (d *DB) TenantIDsForEmail(ctx context.Context, email string) ([]int64, error) {
	rows, err := d.pool.Query(ctx,
		"SELECT tenant_id FROM tenant_members WHERE email = $1", email)
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

// TenantRole returns the caller's role in tenantID, or ok=false when they are
// not a member.
func (d *DB) TenantRole(ctx context.Context, tenantID int64, email string) (role string, ok bool, err error) {
	err = d.pool.QueryRow(ctx,
		"SELECT role FROM tenant_members WHERE tenant_id = $1 AND email = $2",
		tenantID, email).Scan(&role)
	if notFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, apperr.Internal(err)
	}
	return role, true, nil
}

// CreateTenant creates a tenant with ownerEmail as its sole owner. Both rows go
// in together, so a tenant never exists without an owner.
func (d *DB) CreateTenant(ctx context.Context, name, ownerEmail string) (int64, error) {
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
			"INSERT INTO tenant_members (tenant_id, email, role) VALUES ($1, $2, 'owner')",
			id, ownerEmail)
		return apperr.Internal(err)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// ListMembers returns a tenant's membership in email order.
func (d *DB) ListMembers(ctx context.Context, tenantID int64) ([]Member, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT email, role, created_at FROM tenant_members
		WHERE tenant_id = $1 ORDER BY email`, tenantID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
	return out, apperr.Internal(err)
}

// AddMember invites a member, or re-roles one who is already there.
func (d *DB) AddMember(ctx context.Context, tenantID int64, email, role string) error {
	_, err := d.pool.Exec(ctx, `
		INSERT INTO tenant_members (tenant_id, email, role) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, email) DO UPDATE SET role = $3`,
		tenantID, email, role)
	return apperr.Internal(err)
}

// RemoveMember removes a member, refusing to strip a tenant of its last owner —
// which would leave it unmanageable. Removing someone who is not a member
// succeeds, so the call is idempotent.
func (d *DB) RemoveMember(ctx context.Context, tenantID int64, email string) error {
	return d.InTx(ctx, func(tx pgx.Tx) error {
		var role string
		err := tx.QueryRow(ctx,
			"SELECT role FROM tenant_members WHERE tenant_id = $1 AND email = $2 FOR UPDATE",
			tenantID, email).Scan(&role)
		if notFound(err) {
			return nil
		}
		if err != nil {
			return apperr.Internal(err)
		}

		if role == "owner" {
			var owners int64
			err := tx.QueryRow(ctx,
				"SELECT COUNT(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner'",
				tenantID).Scan(&owners)
			if err != nil {
				return apperr.Internal(err)
			}
			if owners <= 1 {
				return apperr.InvalidArgument("cannot remove the last owner of a tenant")
			}
		}

		_, err = tx.Exec(ctx,
			"DELETE FROM tenant_members WHERE tenant_id = $1 AND email = $2",
			tenantID, email)
		return apperr.Internal(err)
	})
}

// DeleteTenant deletes an empty tenant; its membership cascades. A tenant that
// still owns namespaces is a conflict, mirroring non-empty namespace deletion.
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
