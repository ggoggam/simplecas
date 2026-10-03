package db

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

const namespaceColumns = "id, name, created_at, tenant_id"

// ListNamespaces returns every namespace in name order, owned or not. Only the
// superuser planes use it: the S3 gateway's admin credential, and /api when
// OIDC is off. Tenant-scoped callers go through ListNamespacesForTenants.
func (d *DB) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	rows, err := d.pool.Query(ctx,
		"SELECT "+namespaceColumns+" FROM namespaces ORDER BY name")
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Namespace])
	return out, apperr.Internal(err)
}

// ListNamespacesForTenants returns the namespaces owned by any of tenantIDs, in
// name order. The tenant-scoped /api and /ui plane uses this so a caller sees
// only their own teams' namespaces; unowned (NULL-tenant) namespaces never match.
func (d *DB) ListNamespacesForTenants(ctx context.Context, tenantIDs []int64) ([]Namespace, error) {
	rows, err := d.pool.Query(ctx,
		"SELECT "+namespaceColumns+` FROM namespaces
		 WHERE tenant_id = ANY($1) ORDER BY name`, tenantIDs)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Namespace])
	return out, apperr.Internal(err)
}

// GetNamespace resolves a namespace by name, with no tenant check.
func (d *DB) GetNamespace(ctx context.Context, name string) (Namespace, error) {
	rows, err := d.pool.Query(ctx,
		"SELECT "+namespaceColumns+" FROM namespaces WHERE name = $1", name)
	if err != nil {
		return Namespace{}, apperr.Internal(err)
	}
	ns, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Namespace])
	if notFound(err) {
		return Namespace{}, apperr.ErrNoSuchNamespace
	}
	return ns, apperr.Internal(err)
}

// GetNamespaceForMember resolves a namespace only if userID is a member of its
// owning tenant. Every other case — missing namespace, unowned namespace, or a
// caller who is not a member — resolves to NoSuchNamespace, so the tenant plane
// never reveals that a namespace it cannot reach exists.
func (d *DB) GetNamespaceForMember(ctx context.Context, name string, userID int64) (Namespace, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT n.id, n.name, n.created_at, n.tenant_id
		FROM namespaces n
		JOIN tenant_members m ON m.tenant_id = n.tenant_id AND m.user_id = $2
		WHERE n.name = $1`, name, userID)
	if err != nil {
		return Namespace{}, apperr.Internal(err)
	}
	ns, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Namespace])
	if notFound(err) {
		return Namespace{}, apperr.ErrNoSuchNamespace
	}
	return ns, apperr.Internal(err)
}

// GetNamespaceForTenant resolves a namespace only if tenantID owns it. A
// namespace that is missing, unowned, or another tenant's all resolve to
// NoSuchNamespace, so a tenanted S3 credential cannot tell them apart.
//
// This is the S3 plane's counterpart to GetNamespaceForMember: that one scopes
// by a signed-in human's membership, this one by the tenant a credential
// belongs to.
func (d *DB) GetNamespaceForTenant(ctx context.Context, name string, tenantID int64) (Namespace, error) {
	rows, err := d.pool.Query(ctx,
		"SELECT "+namespaceColumns+` FROM namespaces
		 WHERE name = $1 AND tenant_id = $2`, name, tenantID)
	if err != nil {
		return Namespace{}, apperr.Internal(err)
	}
	ns, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Namespace])
	if notFound(err) {
		return Namespace{}, apperr.ErrNoSuchNamespace
	}
	return ns, apperr.Internal(err)
}

// CreateNamespace inserts a namespace owned by tenantID, or unowned when
// tenantID is nil.
//
// Names are unique across every tenant, so a clash may be with a namespace the
// caller cannot see. It is reported as ErrNamespaceAlreadyExists whoever owns
// the name; the caller decides, through its own scoping, whether to tell its
// principal the namespace is theirs.
func (d *DB) CreateNamespace(ctx context.Context, name string, tenantID *int64) error {
	tag, err := d.pool.Exec(ctx,
		"INSERT INTO namespaces (name, tenant_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		name, tenantID)
	if err != nil {
		return apperr.Internal(err)
	}
	if tag.RowsAffected() == 0 {
		return apperr.ErrNamespaceAlreadyExists
	}
	return nil
}

// DeleteNamespace removes an empty namespace. S3 semantics: deleting one that
// still holds objects is a conflict, not a cascade. The row is locked first so
// a concurrent upload cannot slip an object in between the check and the delete.
func (d *DB) DeleteNamespace(ctx context.Context, name string) error {
	return d.InTx(ctx, func(tx pgx.Tx) error {
		var id int64
		err := tx.QueryRow(ctx,
			"SELECT id FROM namespaces WHERE name = $1 FOR UPDATE", name).Scan(&id)
		if notFound(err) {
			return apperr.ErrNoSuchNamespace
		}
		if err != nil {
			return apperr.Internal(err)
		}

		var occupied bool
		err = tx.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM objects WHERE namespace_id = $1)", id).Scan(&occupied)
		if err != nil {
			return apperr.Internal(err)
		}
		if occupied {
			return apperr.ErrNamespaceNotEmpty
		}

		_, err = tx.Exec(ctx, "DELETE FROM namespaces WHERE id = $1", id)
		return apperr.Internal(err)
	})
}
