package db

import (
	"context"
	"errors"
	"fmt"

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
// then sees refcount > 0) or waits until the row is gone. Deleting the bytes
// after the commit instead would let an upload recreate the row and write fresh
// bytes in between, which the late delete would then destroy.
//
// Within the transaction the row is deleted before the bytes. A delete that
// fails — the objects foreign key catching a reference the refcount missed —
// then aborts before any bytes are touched. The one window left is a crash or
// failed commit after deleteBytes, which leaves a zero-ref row with no bytes;
// ClaimBlob treats any revival from zero as needing its bytes rewritten, and
// ClaimExistingBlob refuses zero-ref rows, so that row is never handed out
// without its bytes. The next pass collects it, deleteBytes being idempotent.
//
// Candidates must also have no object pointing at them. The refcount is a
// cache of that fact, and if it ever drifts low the sweep must not take the
// count's word over the objects table and destroy live data.
//
// A failure on one blob does not end the pass. That blob's transaction rolls
// back, so its row survives to be retried on the next pass, and it is excluded
// for the rest of this one; the sweep carries on with the others. Candidates
// are taken oldest first, so the order is stable and one bad row cannot be
// picked again and again while the rest wait. The per-blob failures come back
// joined in err, alongside the count of blobs that were swept. Only a failure
// to find candidates at all ends the pass early.
func (d *DB) GCSweep(ctx context.Context, graceSecs int64, limit int64, deleteBytes func(ctx context.Context, hash string) error) (int64, error) {
	var (
		swept int64
		errs  []error
		// failed must be non-nil: a nil slice is sent as NULL, and
		// `hash <> ALL(NULL)` matches nothing.
		failed = []string{}
	)
	for swept+int64(len(failed)) < limit {
		var (
			hash string
			done bool
		)
		err := d.InTx(ctx, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `
				SELECT hash FROM blobs
				WHERE refcount = 0
				  AND updated_at < now() - make_interval(secs => $1)
				  AND hash <> ALL($2)
				  AND NOT EXISTS (SELECT 1 FROM objects o WHERE o.blob_hash = blobs.hash)
				ORDER BY updated_at, hash
				LIMIT 1
				FOR UPDATE SKIP LOCKED`, float64(graceSecs), failed).Scan(&hash)
			if notFound(err) {
				done = true
				return nil
			}
			if err != nil {
				return apperr.Internal(err)
			}

			if _, err := tx.Exec(ctx, "DELETE FROM blobs WHERE hash = $1", hash); err != nil {
				return apperr.Internal(err)
			}
			return deleteBytes(ctx, hash)
		})
		if err != nil {
			if hash == "" {
				// Not tied to any one blob: the candidate query itself failed.
				return swept, errors.Join(append(errs, err)...)
			}
			failed = append(failed, hash)
			errs = append(errs, fmt.Errorf("blob %s: %w", hash, err))
			continue
		}
		if done {
			break
		}
		swept++
	}
	return swept, errors.Join(errs...)
}
