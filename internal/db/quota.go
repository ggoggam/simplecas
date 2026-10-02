package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ---------------------------------------------------------------------------
// Team quotas
//
// A team is charged the logical size of what it stores: every object in its
// namespaces, plus the staged parts of its unfinished multipart uploads.
// Deduplication is global, so content another team also stores still costs
// this team its full size. Splitting the cost by refcount would let a team
// learn what other teams store by watching its own usage move.
//
// Usage is summed from the rows rather than kept in a counter. The namespace
// and upload deletes cascade to objects and parts, and a counter maintained
// beside them would drift the first time a path forgot it. The sum costs a
// scan of the team's objects per write, and only when a quota is configured.
// ---------------------------------------------------------------------------

// QuotaCheck describes the write being charged, so usage can leave out what
// the write is about to replace.
type QuotaCheck struct {
	NamespaceID int64
	// Bytes is the size of what the write adds.
	Bytes int64
	// Key, when set, is the object the write overwrites; its current size is
	// not counted.
	Key string
	// Upload, when set, is a multipart upload whose parts are not counted:
	// all of them when PartNumber is 0 (the upload is being completed, and
	// its parts are about to be dropped), or just that part (it is being
	// re-uploaded).
	Upload     uuid.UUID
	PartNumber int32
}

// CheckQuota fails with QuotaExceeded when the write described by c would take
// the namespace's team past quota. It takes no lock: it is the early check
// that refuses an over-quota upload before any bytes are promoted, and a
// concurrent writer can still slip past it. EnforceQuota is the authoritative
// check.
func CheckQuota(ctx context.Context, tx pgx.Tx, quota int64, c QuotaCheck) error {
	if quota <= 0 {
		return nil
	}
	tenantID, err := namespaceTenant(ctx, tx, c.NamespaceID)
	if err != nil || tenantID == nil {
		return err
	}
	used, err := tenantUsage(ctx, tx, *tenantID, c)
	if err != nil {
		return err
	}
	return overQuota(used+c.Bytes, quota)
}

// EnforceQuota fails with QuotaExceeded when the team owning namespaceID is
// over quota once this transaction's writes are counted. Call it as the last
// statement of the transaction, after the object or part row is written:
//
//   - It takes a transaction-scoped lock on the team, so two writers cannot
//     both see room for themselves and together overshoot. The sum runs after
//     the lock is granted, so under READ COMMITTED it sees whatever the
//     previous holder committed.
//   - Nothing is locked after it. Writes lock blob rows (claim, release) and
//     object keys in varying orders, and a team lock taken between them could
//     close a deadlock cycle with another writer in the same team. Taken last,
//     the transaction holding it waits on nothing.
//
// upload names a multipart upload whose parts are left out (the one being
// completed); pass uuid.Nil otherwise.
func EnforceQuota(ctx context.Context, tx pgx.Tx, quota int64, namespaceID int64, upload uuid.UUID) error {
	if quota <= 0 {
		return nil
	}
	tenantID, err := namespaceTenant(ctx, tx, namespaceID)
	if err != nil || tenantID == nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"SELECT pg_advisory_xact_lock(hashtextextended('tenant-quota', $1))", *tenantID); err != nil {
		return apperr.Internal(err)
	}
	used, err := tenantUsage(ctx, tx, *tenantID, QuotaCheck{Upload: upload})
	if err != nil {
		return err
	}
	return overQuota(used, quota)
}

// namespaceTenant returns the team owning a namespace, or nil for an unowned
// one, which no quota applies to.
func namespaceTenant(ctx context.Context, tx pgx.Tx, namespaceID int64) (*int64, error) {
	var tenantID *int64
	err := tx.QueryRow(ctx, "SELECT tenant_id FROM namespaces WHERE id = $1", namespaceID).Scan(&tenantID)
	if notFound(err) {
		return nil, apperr.ErrNoSuchNamespace
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return tenantID, nil
}

// tenantUsage sums a team's objects and staged parts, leaving out the object
// and parts c says are being replaced.
func tenantUsage(ctx context.Context, tx pgx.Tx, tenantID int64, c QuotaCheck) (int64, error) {
	var used int64
	err := tx.QueryRow(ctx, `
		SELECT
		    COALESCE((
		        SELECT SUM(o.size) FROM objects o
		        JOIN namespaces n ON n.id = o.namespace_id
		        WHERE n.tenant_id = $1
		          AND NOT (o.namespace_id = $2 AND o.key = $3)
		    ), 0)
		  + COALESCE((
		        SELECT SUM(p.size) FROM multipart_parts p
		        JOIN multipart_uploads u ON u.id = p.upload_id
		        JOIN namespaces n ON n.id = u.namespace_id
		        WHERE n.tenant_id = $1
		          AND NOT (p.upload_id = $4 AND ($5 = 0 OR p.part_number = $5))
		    ), 0)`,
		tenantID, c.NamespaceID, c.Key, c.Upload, c.PartNumber).Scan(&used)
	if err != nil {
		return 0, apperr.Internal(err)
	}
	return used, nil
}

func overQuota(used, quota int64) error {
	if used > quota {
		return apperr.QuotaExceeded("this would use %d bytes of the team's %d-byte quota", used, quota)
	}
	return nil
}
