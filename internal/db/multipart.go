package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// CreateMultipart opens a multipart upload and returns its id.
func (d *DB) CreateMultipart(ctx context.Context, namespaceID int64, key, contentType string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := d.pool.Exec(ctx, `
		INSERT INTO multipart_uploads (id, namespace_id, key, content_type)
		VALUES ($1, $2, $3, $4)`, id, namespaceID, key, contentType)
	if err != nil {
		return uuid.Nil, apperr.Internal(err)
	}
	return id, nil
}

// GetMultipart resolves an upload, requiring the namespace and key to match the
// ones it was opened against.
func (d *DB) GetMultipart(ctx context.Context, namespaceID int64, key string, id uuid.UUID) (MultipartUpload, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT id, namespace_id, key, content_type FROM multipart_uploads
		WHERE id = $1 AND namespace_id = $2 AND key = $3`, id, namespaceID, key)
	if err != nil {
		return MultipartUpload{}, apperr.Internal(err)
	}
	up, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[MultipartUpload])
	if notFound(err) {
		return MultipartUpload{}, apperr.ErrNoSuchUpload
	}
	return up, apperr.Internal(err)
}

// PutPart records a staged part. It returns the staging key of any previous
// upload of the same part number, whose bytes the caller must delete — a client
// retrying a part would otherwise orphan the first attempt.
//
// Staged parts count against the team's quota (0 means none): without that, a
// team could park unbounded bytes in uploads it never completes.
func (d *DB) PutPart(ctx context.Context, uploadID uuid.UUID, partNumber int32, stagingKey string, size int64, etag string, quota int64) (replaced string, err error) {
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT staging_key FROM multipart_parts
			WHERE upload_id = $1 AND part_number = $2 FOR UPDATE`,
			uploadID, partNumber).Scan(&replaced)
		if err != nil && !notFound(err) {
			return apperr.Internal(err)
		}
		if notFound(err) {
			replaced = ""
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO multipart_parts (upload_id, part_number, staging_key, size, etag)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (upload_id, part_number) DO UPDATE
			    SET staging_key = $3, size = $4, etag = $5, created_at = now()`,
			uploadID, partNumber, stagingKey, size, etag)
		if err != nil || quota <= 0 {
			return apperr.Internal(err)
		}

		var namespaceID int64
		err = tx.QueryRow(ctx,
			"SELECT namespace_id FROM multipart_uploads WHERE id = $1", uploadID).Scan(&namespaceID)
		if err != nil {
			return apperr.Internal(err)
		}
		return EnforceQuota(ctx, tx, quota, namespaceID, uuid.Nil)
	})
	if err != nil {
		return "", err
	}
	return replaced, nil
}

// ListParts returns every staged part of an upload, in part-number order.
func (d *DB) ListParts(ctx context.Context, uploadID uuid.UUID) ([]PartMeta, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT part_number, staging_key, size, etag FROM multipart_parts
		WHERE upload_id = $1 ORDER BY part_number`, uploadID)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[PartMeta])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if out == nil {
		out = []PartMeta{}
	}
	return out, nil
}

// PartPage is one page of ListParts output.
type PartPage struct {
	Parts       []PartMeta
	IsTruncated bool
}

// ListPartsPage returns the parts numbered above after, capped at limit. One
// extra row is fetched to decide truncation without a second count query.
func (d *DB) ListPartsPage(ctx context.Context, uploadID uuid.UUID, after int32, limit int64) (PartPage, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT part_number, staging_key, size, etag FROM multipart_parts
		WHERE upload_id = $1 AND part_number > $2 ORDER BY part_number LIMIT $3`,
		uploadID, after, limit+1)
	if err != nil {
		return PartPage{}, apperr.Internal(err)
	}
	parts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[PartMeta])
	if err != nil {
		return PartPage{}, apperr.Internal(err)
	}

	page := PartPage{Parts: parts, IsTruncated: int64(len(parts)) > limit}
	if page.IsTruncated {
		page.Parts = parts[:limit]
	}
	if page.Parts == nil {
		page.Parts = []PartMeta{}
	}
	return page, nil
}

// ListMultipartUploads returns in-progress uploads in a namespace whose key
// starts with prefix, ordered by key then id. Bounded by limit rather than
// paginated, which is adequate for the number of concurrent uploads this server
// expects.
func (d *DB) ListMultipartUploads(ctx context.Context, namespaceID int64, prefix string, limit int64) ([]MultipartUploadEntry, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT id, key, created_at FROM multipart_uploads
		WHERE namespace_id = $1 AND key LIKE $2 || '%'
		ORDER BY key, id LIMIT $3`, namespaceID, prefix, limit)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[MultipartUploadEntry])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if out == nil {
		out = []MultipartUploadEntry{}
	}
	return out, nil
}

// RemoveMultipart deletes an upload and its part rows, returning the staging
// keys whose bytes the caller must clean up.
func (d *DB) RemoveMultipart(ctx context.Context, uploadID uuid.UUID) ([]string, error) {
	var keys []string
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			"SELECT staging_key FROM multipart_parts WHERE upload_id = $1 FOR UPDATE",
			uploadID)
		if err != nil {
			return apperr.Internal(err)
		}
		keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return apperr.Internal(err)
		}
		// Part rows cascade with the upload.
		_, err = tx.Exec(ctx, "DELETE FROM multipart_uploads WHERE id = $1", uploadID)
		return apperr.Internal(err)
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// SweptMultipart reports what an expiry sweep reclaimed.
type SweptMultipart struct {
	// Uploads is how many upload rows were deleted, with or without parts.
	Uploads int64
	// StagingKeys are the staged part files whose bytes the caller must delete.
	StagingKeys []string
}

// SweepMultipart abandons uploads with no activity — neither the initiation nor
// any part — inside the expiry window, returning their part staging keys.
//
// Because the staging sweeper deliberately protects part-referenced files from
// collection, this is the only thing that ever reclaims the bytes of an
// abandoned upload.
func (d *DB) SweepMultipart(ctx context.Context, expirySecs int64) (SweptMultipart, error) {
	var swept SweptMultipart
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT u.id FROM multipart_uploads u
			WHERE u.created_at < now() - make_interval(secs => $1)
			  AND NOT EXISTS (
			      SELECT 1 FROM multipart_parts p
			      WHERE p.upload_id = u.id
			        AND p.created_at >= now() - make_interval(secs => $1)
			  )
			FOR UPDATE SKIP LOCKED`, float64(expirySecs))
		if err != nil {
			return apperr.Internal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return apperr.Internal(err)
		}
		if len(ids) == 0 {
			return nil
		}

		keyRows, err := tx.Query(ctx,
			"SELECT staging_key FROM multipart_parts WHERE upload_id = ANY($1)", ids)
		if err != nil {
			return apperr.Internal(err)
		}
		swept.StagingKeys, err = pgx.CollectRows(keyRows, pgx.RowTo[string])
		if err != nil {
			return apperr.Internal(err)
		}

		tag, err := tx.Exec(ctx, "DELETE FROM multipart_uploads WHERE id = ANY($1)", ids)
		if err != nil {
			return apperr.Internal(err)
		}
		swept.Uploads = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return SweptMultipart{}, err
	}
	return swept, nil
}

// StagingKeyReferenced reports whether a live multipart part still points at a
// staging file, which is what stops the staging sweeper from collecting the
// parts of an upload that is merely slow rather than abandoned.
func (d *DB) StagingKeyReferenced(ctx context.Context, stagingKey string) (bool, error) {
	var referenced bool
	err := d.pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM multipart_parts WHERE staging_key = $1)",
		stagingKey).Scan(&referenced)
	if err != nil {
		return false, apperr.Internal(err)
	}
	return referenced, nil
}
