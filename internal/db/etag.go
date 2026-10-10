package db

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ETagBackfill is a blob that some object serves without a recorded ETag. MD5
// is the blob's MD5 when it is already known, or "" when the bytes have to be
// read to find it.
type ETagBackfill struct {
	Hash string
	Size int64
	MD5  string
}

// ETagsToBackfill returns up to limit blobs referenced by an object stored
// before ETags were recorded. The partial index on objects keeps this cheap
// once the backfill is done and the set is empty.
func (d *DB) ETagsToBackfill(ctx context.Context, limit int) ([]ETagBackfill, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT p.blob_hash, b.size, COALESCE(b.md5, '')
		FROM (SELECT DISTINCT blob_hash FROM objects WHERE etag IS NULL LIMIT $1) p
		JOIN blobs b ON b.hash = p.blob_hash`, limit)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ETagBackfill])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return pending, nil
}

// RecordBlobMD5 records md5 as the MD5 of blob hash, unless one is recorded
// already, and gives every object of that blob still without an ETag the
// recorded MD5 as its ETag.
//
// A legacy multipart object gets the MD5 of its whole content rather than the
// "-N" form, because its part boundaries were never kept; either is a valid S3
// ETag for the bytes.
func (d *DB) RecordBlobMD5(ctx context.Context, hash, md5 string) error {
	return d.InTx(ctx, func(tx pgx.Tx) error {
		var recorded string
		err := tx.QueryRow(ctx, `
			UPDATE blobs SET md5 = COALESCE(md5, $2) WHERE hash = $1 RETURNING md5`,
			hash, md5).Scan(&recorded)
		if notFound(err) {
			// Collected since it was listed; nothing references it any more.
			return nil
		}
		if err != nil {
			return apperr.Internal(err)
		}
		_, err = tx.Exec(ctx,
			"UPDATE objects SET etag = $2 WHERE blob_hash = $1 AND etag IS NULL", hash, recorded)
		return apperr.Internal(err)
	})
}
