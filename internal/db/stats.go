package db

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// Stats reports global dedup accounting across every namespace.
func (d *DB) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	err := d.pool.QueryRow(ctx, "SELECT COUNT(*) FROM namespaces").Scan(&s.NamespaceCount)
	if err != nil {
		return Stats{}, apperr.Internal(err)
	}
	err = d.pool.QueryRow(ctx,
		"SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM objects").
		Scan(&s.ObjectCount, &s.LogicalBytes)
	if err != nil {
		return Stats{}, apperr.Internal(err)
	}
	err = d.pool.QueryRow(ctx,
		"SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM blobs WHERE refcount > 0").
		Scan(&s.BlobCount, &s.PhysicalBytes)
	if err != nil {
		return Stats{}, apperr.Internal(err)
	}
	return s, nil
}

// StatsForTenants restricts the accounting to namespaces owned by tenantIDs.
//
// Under global dedup a blob shared by two tenants counts toward each tenant's
// physical footprint, so per-tenant PhysicalBytes summed across tenants can
// exceed the global figure. It is "the footprint attributable to your data",
// not a partition of the total.
func (d *DB) StatsForTenants(ctx context.Context, tenantIDs []int64) (Stats, error) {
	var s Stats
	err := d.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM namespaces WHERE tenant_id = ANY($1)", tenantIDs).
		Scan(&s.NamespaceCount)
	if err != nil {
		return Stats{}, apperr.Internal(err)
	}
	err = d.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(o.size), 0)::BIGINT
		FROM objects o
		JOIN namespaces n ON n.id = o.namespace_id
		WHERE n.tenant_id = ANY($1)`, tenantIDs).
		Scan(&s.ObjectCount, &s.LogicalBytes)
	if err != nil {
		return Stats{}, apperr.Internal(err)
	}
	err = d.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM (
		    SELECT DISTINCT b.hash, b.size
		    FROM blobs b
		    JOIN objects o ON o.blob_hash = b.hash
		    JOIN namespaces n ON n.id = o.namespace_id
		    WHERE n.tenant_id = ANY($1)
		) distinct_blobs`, tenantIDs).
		Scan(&s.BlobCount, &s.PhysicalBytes)
	if err != nil {
		return Stats{}, apperr.Internal(err)
	}
	return s, nil
}

// GCSweep deletes blobs that have sat at refcount 0 past the grace period,
// calling deleteBytes for each one, and stops after limit blobs.
//
// The bytes are deleted while the blob's row lock is held, and ClaimBlob
// contends on that same lock, so a blob can never be resurrected halfway
// through its own deletion: a claimer either wins the lock first (and the sweep
// then sees refcount > 0) or waits until the row is gone.
//
// deleteBytes failing aborts the sweep with the row still present, so the blob
// is retried on the next pass rather than leaving a metadata row with no bytes.
func (d *DB) GCSweep(ctx context.Context, graceSecs int64, limit int64, deleteBytes func(ctx context.Context, hash string) error) (int64, error) {
	var swept int64
	for swept < limit {
		var done bool
		err := d.InTx(ctx, func(tx pgx.Tx) error {
			var hash string
			err := tx.QueryRow(ctx, `
				SELECT hash FROM blobs
				WHERE refcount = 0 AND updated_at < now() - make_interval(secs => $1)
				LIMIT 1
				FOR UPDATE SKIP LOCKED`, float64(graceSecs)).Scan(&hash)
			if notFound(err) {
				done = true
				return nil
			}
			if err != nil {
				return apperr.Internal(err)
			}

			if err := deleteBytes(ctx, hash); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "DELETE FROM blobs WHERE hash = $1", hash)
			return apperr.Internal(err)
		})
		if err != nil {
			return swept, err
		}
		if done {
			break
		}
		swept++
	}
	return swept, nil
}
