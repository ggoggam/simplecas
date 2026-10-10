package db

import (
	"context"
	"encoding/base64"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ---------------------------------------------------------------------------
// Blob references
//
// Every object points at a row in the global `blobs` table, keyed by content
// hash and shared across all namespaces and tenants. `refcount` counts the
// objects pointing at it; GC deletes a blob that has stayed at zero past the
// grace period. The row locks taken here are what make that safe against a
// concurrent sweep — see GCSweep.
// ---------------------------------------------------------------------------

// ClaimBlob takes a reference to hash inside tx, creating the blob row if it is
// new. It reports needsBytes when no live reference vouches for the bytes, in
// which case the caller must (re)write them before committing — so a committed
// reference always has bytes behind it.
//
// md5 is the content's hex MD5 when the caller measured it, or "" when it did
// not (a copy reads no bytes). It is recorded on a row that has none yet, and
// the row's MD5 comes back as storedMD5, or "" for a blob stored before MD5s
// were recorded that the backfill has not reached.
//
// needsBytes covers two cases. A fresh row obviously has no bytes yet. A row
// revived from refcount 0 may not either: GCSweep deletes the bytes before its
// transaction commits, so a crash or failed commit in that window leaves a
// zero-ref row whose bytes are already gone. The claim cannot tell that row
// apart from one still awaiting collection, so it treats both as missing. The
// re-copy is idempotent — the content is addressed by its hash — and only costs
// anything on the rare revival of a blob GC was about to collect.
//
// The ON CONFLICT row lock serialises against GC's SELECT ... FOR UPDATE, so a
// blob being swept cannot be re-referenced underneath the sweep. After the
// increment, a refcount of 1 means nothing else held a reference before.
func ClaimBlob(ctx context.Context, tx pgx.Tx, hash string, size int64, md5 string) (needsBytes bool, storedMD5 string, err error) {
	err = tx.QueryRow(ctx, `
		INSERT INTO blobs (hash, size, refcount, md5) VALUES ($1, $2, 1, NULLIF($3, ''))
		ON CONFLICT (hash) DO UPDATE
		    SET refcount = blobs.refcount + 1, updated_at = now(),
		        md5 = COALESCE(blobs.md5, EXCLUDED.md5)
		RETURNING refcount = 1, COALESCE(md5, '')`, hash, size, md5).Scan(&needsBytes, &storedMD5)
	if err != nil {
		return false, "", apperr.Internal(err)
	}
	return needsBytes, storedMD5, nil
}

// ClaimExistingBlob takes a reference to hash only if the blob is live — some
// object already references it — returning its authoritative size. ok is false
// otherwise, which tells the dedup "link" path to fall back to a real upload
// rather than create a dangling reference. md5 is the blob's recorded MD5, or ""
// when the backfill has not reached it yet.
//
// A blob at refcount 0 is declined even though its row exists: GC may have
// deleted its bytes and crashed before removing the row (see ClaimBlob), and
// the link path has no staged copy to restore them from. The fallback upload
// goes through ClaimBlob, which revives the row and rewrites the bytes.
func ClaimExistingBlob(ctx context.Context, tx pgx.Tx, hash string) (size int64, md5 string, ok bool, err error) {
	err = tx.QueryRow(ctx, `
		UPDATE blobs SET refcount = refcount + 1, updated_at = now()
		WHERE hash = $1 AND refcount > 0 RETURNING size, COALESCE(md5, '')`, hash).Scan(&size, &md5)
	if notFound(err) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, apperr.Internal(err)
	}
	return size, md5, true, nil
}

// ReleaseBlob drops one reference. It never takes the count below zero, so a
// double release cannot underflow into a negative refcount that would hide the
// blob from GC forever.
//
// A release that finds nothing to drop — the row already at zero, or gone —
// means the refcount has drifted from the objects that really reference the
// blob. That is logged rather than failed: the write it belongs to is still
// correct, and GCSweep refuses to collect a blob any object still points at, so
// a count that drifted low costs no data. The warning is there so the drift is
// noticed rather than silently absorbed.
func ReleaseBlob(ctx context.Context, tx pgx.Tx, hash string) error {
	tag, err := tx.Exec(ctx, `
		UPDATE blobs SET refcount = refcount - 1, updated_at = now()
		WHERE hash = $1 AND refcount > 0`, hash)
	if err != nil {
		return apperr.Internal(err)
	}
	if tag.RowsAffected() == 0 {
		slog.WarnContext(ctx, "blob refcount would go below zero; refcount has drifted", "hash", hash)
	}
	return nil
}

// BlobReferencedInTenant reports whether any object inside tenantID's
// namespaces references hash. This gates the dedup "link" fast path so it
// cannot be used as a cross-tenant existence oracle: a caller only gets a
// zero-byte link for content their own tenant already holds.
//
// Physical dedup stays global regardless — a real upload of the same bytes
// still hits ClaimBlob and stores nothing new.
func BlobReferencedInTenant(ctx context.Context, tx pgx.Tx, hash string, tenantID int64) (bool, error) {
	var referenced bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(
		    SELECT 1 FROM objects o
		    JOIN namespaces n ON n.id = o.namespace_id
		    WHERE o.blob_hash = $1 AND n.tenant_id = $2
		)`, hash, tenantID).Scan(&referenced)
	if err != nil {
		return false, apperr.Internal(err)
	}
	return referenced, nil
}

// BlobReferencedInNamespace reports whether any object in namespaceID already
// references hash. A commit writes the bytes of any content new to its
// namespace, even when the blob is already stored for someone else, so that an
// upload takes as long whether or not another tenant holds the same content;
// only content the namespace itself already holds skips the write. See
// cas.Store.commit.
func BlobReferencedInNamespace(ctx context.Context, tx pgx.Tx, hash string, namespaceID int64) (bool, error) {
	var referenced bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM objects WHERE blob_hash = $1 AND namespace_id = $2)`,
		hash, namespaceID).Scan(&referenced)
	if err != nil {
		return false, apperr.Internal(err)
	}
	return referenced, nil
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

// UpsertObject points key at hash, releasing whatever blob it referenced
// before. It assumes ClaimBlob has already run for hash in this transaction.
// etag is the object's ETag, unquoted, or "" when it is not known yet (a copy
// or link of a blob stored before MD5s were recorded), for the backfill to
// fill in.
//
// Releasing the old hash also nets out the double count when an object is
// overwritten with byte-identical content: the claim incremented, this
// decrements, and the refcount is unchanged.
//
// The transaction-scoped advisory lock on (namespace, key) is what makes the
// read of the old hash trustworthy. SELECT ... FOR UPDATE locks nothing when the
// key does not exist yet, so two concurrent PUTs to a new key would both see no
// previous blob; the second upsert would then overwrite the first's row without
// releasing its reference, and that blob could never be collected. Holding the
// key lock across the select and the upsert serialises writers per key, and the
// select runs after the lock is granted, so under READ COMMITTED it sees
// whatever the previous holder committed. Two keys whose hashes collide merely
// serialise against each other, which is harmless.
func UpsertObject(ctx context.Context, tx pgx.Tx, namespaceID int64, key, hash, etag string, size int64, contentType string) error {
	_, err := tx.Exec(ctx,
		"SELECT pg_advisory_xact_lock(hashtextextended($2, $1))", namespaceID, key)
	if err != nil {
		return apperr.Internal(err)
	}

	var oldHash string
	err = tx.QueryRow(ctx,
		"SELECT blob_hash FROM objects WHERE namespace_id = $1 AND key = $2 FOR UPDATE",
		namespaceID, key).Scan(&oldHash)
	hadOld := true
	if notFound(err) {
		hadOld = false
	} else if err != nil {
		return apperr.Internal(err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO objects (namespace_id, key, blob_hash, etag, size, content_type)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)
		ON CONFLICT (namespace_id, key) DO UPDATE
		    SET blob_hash = $3, etag = NULLIF($4, ''), size = $5, content_type = $6, updated_at = now()`,
		namespaceID, key, hash, etag, size, contentType)
	if err != nil {
		return apperr.Internal(err)
	}

	if hadOld {
		return ReleaseBlob(ctx, tx, oldHash)
	}
	return nil
}

// GetObject reads one object's metadata.
func (d *DB) GetObject(ctx context.Context, namespaceID int64, key string) (ObjectMeta, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT key, blob_hash, COALESCE(etag, ''), size, content_type, updated_at
		FROM objects WHERE namespace_id = $1 AND key = $2`, namespaceID, key)
	if err != nil {
		return ObjectMeta{}, apperr.Internal(err)
	}
	obj, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[ObjectMeta])
	if notFound(err) {
		return ObjectMeta{}, apperr.ErrNoSuchKey
	}
	return obj, apperr.Internal(err)
}

// DeleteObject removes an object and releases its blob reference. It reports
// whether the key existed; S3's DELETE is a 204 either way, but the admin API
// and the batch delete both surface the distinction.
func (d *DB) DeleteObject(ctx context.Context, namespaceID int64, key string) (existed bool, err error) {
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		var hash string
		err := tx.QueryRow(ctx,
			"DELETE FROM objects WHERE namespace_id = $1 AND key = $2 RETURNING blob_hash",
			namespaceID, key).Scan(&hash)
		if notFound(err) {
			return nil
		}
		if err != nil {
			return apperr.Internal(err)
		}
		existed = true
		return ReleaseBlob(ctx, tx, hash)
	})
	if err != nil {
		return false, err
	}
	return existed, nil
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

// ListResult is one page of a listing. NextMarker is meaningful only when
// IsTruncated is set.
type ListResult struct {
	Objects        []ObjectMeta
	CommonPrefixes []string
	IsTruncated    bool
	// NextMarker is the raw key to resume strictly after. The API layers
	// encode it before handing it to a client.
	NextMarker string
}

// escapeLike neutralises the LIKE metacharacters in a user-supplied prefix, so
// a key prefix containing % or _ matches literally.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// listBatch is how many rows are pulled per round trip while grouping.
const listBatch = 1000

// ListObjects is the core of ListObjects/ListObjectsV2. marker is the raw key
// to resume strictly after; delimiter is 0 for no grouping.
//
// Delimiter grouping is computed by walking key order in batches. When a key
// falls inside a group, the group's common prefix is emitted and the scan jumps
// past every key in it by incrementing the prefix's final byte. Keys are stored
// COLLATE "C", so that byte successor is exactly the next key outside the group
// under Postgres's ordering. Callers restrict the delimiter to a printable
// ASCII byte, which keeps the incremented byte inside ASCII and therefore valid
// UTF-8.
func (d *DB) ListObjects(ctx context.Context, namespaceID int64, prefix string, delimiter byte, marker string, maxKeys int) (ListResult, error) {
	result := ListResult{
		Objects:        []ObjectMeta{},
		CommonPrefixes: []string{},
	}
	like := escapeLike(prefix) + "%"

outer:
	for {
		rows, err := d.pool.Query(ctx, `
			SELECT key, blob_hash, COALESCE(etag, ''), size, content_type, updated_at
			FROM objects
			WHERE namespace_id = $1 AND key LIKE $2 AND key > $3
			ORDER BY key
			LIMIT $4`, namespaceID, like, marker, listBatch)
		if err != nil {
			return ListResult{}, apperr.Internal(err)
		}
		batch, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ObjectMeta])
		if err != nil {
			return ListResult{}, apperr.Internal(err)
		}
		exhausted := len(batch) < listBatch

		for _, row := range batch {
			if len(result.Objects)+len(result.CommonPrefixes) >= maxKeys {
				result.IsTruncated = true
				result.NextMarker = marker
				break outer
			}

			rest := row.Key[len(prefix):]
			idx := -1
			if delimiter != 0 {
				idx = strings.IndexByte(rest, delimiter)
			}
			if idx < 0 {
				marker = row.Key
				result.Objects = append(result.Objects, row)
				continue
			}

			group := prefix + rest[:idx+1]
			// Jump past every key in this group: the byte successor of the
			// group's trailing delimiter.
			jump := []byte(group)
			jump[len(jump)-1]++
			marker = string(jump)
			result.CommonPrefixes = append(result.CommonPrefixes, group)
			// Rows left in this batch may belong to the group just skipped,
			// so refetch from the new marker rather than trusting them.
			continue outer
		}

		if exhausted {
			break
		}
	}
	return result, nil
}

// EncodeMarker makes a raw resume marker opaque, so clients treat it as a
// continuation token rather than a key they can construct or reason about.
func EncodeMarker(marker string) string {
	return base64.StdEncoding.EncodeToString([]byte(marker))
}

// DecodeMarker recovers a raw marker from a continuation token.
func DecodeMarker(token string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
