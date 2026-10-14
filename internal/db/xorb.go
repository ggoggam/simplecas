package db

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ---------------------------------------------------------------------------
// Xorbs and terms
//
// A chunked blob is stored as Xet stores a file: its bytes are a list of
// terms, each a run of chunks [Start, End) in one xorb, concatenated in order.
// A xorb is a content-addressed object holding a sequence of chunks;
// xorb_chunks records where each one sits in it. xorbs.refcount counts the
// blobs with a term on the xorb. A blob's terms are written once, when its
// row is created, and deleted with the row, so the xorbs it uses stay
// referenced for exactly as long as the row exists — including while it sits
// at refcount 0 waiting for GC. That is what lets a blob be revived from zero
// without its bytes being rewritten.
// ---------------------------------------------------------------------------

// ChunkRef is one chunk of a blob's content: the bytes [Pos, Pos+Size) of it,
// with their Xet chunk hash.
type ChunkRef struct {
	Hash string
	Pos  int64
	Size int32
}

// XorbChunk is one chunk as stored in a xorb: the bytes [Offset,
// Offset+Length) of the xorb hold its header and compressed data, and Size is
// its length once decompressed.
type XorbChunk struct {
	Hash   string
	Offset int64
	Length int32
	Size   int32
}

// NewXorb is a xorb a commit wrote, with its chunks in order.
type NewXorb struct {
	Hash string
	Size int64
	// KeyID is the encryption key its chunks are sealed under, or "" for a
	// xorb written in the clear.
	KeyID string
	// Existed means the object was already in the backend and the write left
	// it alone, so Chunks' offsets describe this commit's serialization, not
	// necessarily the stored one.
	Existed bool
	Chunks  []XorbChunk
}

// Term is a run of a blob's bytes, [Pos, Pos+Size), held by the chunks
// [Start, End) of Xorb.
type Term struct {
	Pos        int64
	Xorb       string
	Start, End int32
	Size       int64
}

// ChunkLocation is a chunk's place in a xorb.
type ChunkLocation struct {
	Xorb  string
	Index int32
}

// ErrStaleXorbs means a commit planned against xorbs that changed before it
// could claim them: one it meant to reuse was collected, or one it wrote is
// not in the backend after all. The caller plans again.
var ErrStaleXorbs = errors.New("xorbs changed under the commit")

// locatePage is how many chunk hashes one lookup sends.
const locatePage = 4096

// LocateChunks returns, for each of hashes that some live xorb holds, every
// place it is held. Only xorbs with a reference are considered: one at zero
// may be collected, its bytes first, at any moment. Nor are damaged ones: a
// chunk found there may be one of those that failed its check.
func (d *DB) LocateChunks(ctx context.Context, hashes []string) (map[string][]ChunkLocation, error) {
	found := make(map[string][]ChunkLocation)
	for page := range slices.Chunk(hashes, locatePage) {
		rows, err := d.pool.Query(ctx, `
			SELECT xc.chunk_hash, xc.xorb_hash, xc.idx
			FROM xorb_chunks xc JOIN xorbs x ON x.hash = xc.xorb_hash
			WHERE xc.chunk_hash = ANY($1) AND x.refcount > 0 AND x.damaged_at IS NULL
			ORDER BY xc.xorb_hash, xc.idx`, page)
		if err != nil {
			return nil, apperr.Internal(err)
		}
		for rows.Next() {
			var (
				hash string
				loc  ChunkLocation
			)
			if err := rows.Scan(&hash, &loc.Xorb, &loc.Index); err != nil {
				rows.Close()
				return nil, apperr.Internal(err)
			}
			found[hash] = append(found[hash], loc)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, apperr.Internal(err)
		}
	}
	return found, nil
}

// TermsHeldInNamespace reports, for each of terms, whether some object in
// the namespace already has a blob with a term on the same xorb covering all
// of its chunks. Skipping the write of such a run tells the uploader only
// what its own namespace holds.
func (d *DB) TermsHeldInNamespace(ctx context.Context, namespaceID int64, terms []Term) ([]bool, error) {
	held := make([]bool, len(terms))
	if len(terms) == 0 {
		return held, nil
	}
	xorbs := make([]string, len(terms))
	starts := make([]int32, len(terms))
	ends := make([]int32, len(terms))
	for i, t := range terms {
		xorbs[i], starts[i], ends[i] = t.Xorb, t.Start, t.End
	}
	rows, err := d.pool.Query(ctx, `
		SELECT q.i FROM unnest($2::text[], $3::int[], $4::int[]) WITH ORDINALITY AS q(x, s, e, i)
		WHERE EXISTS (
		    SELECT 1 FROM blob_terms t JOIN objects o ON o.blob_hash = t.blob_hash
		    WHERE o.namespace_id = $1 AND t.xorb_hash = q.x
		      AND t.chunk_start <= q.s AND t.chunk_end >= q.e)`,
		namespaceID, xorbs, starts, ends)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	idx, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	for _, i := range idx {
		held[i-1] = true
	}
	return held, nil
}

// XorbBytes is how AttachTerms reaches a xorb's bytes in the backend.
type XorbBytes interface {
	// Present reports whether the xorb's bytes are there.
	Present(ctx context.Context, hash string) (bool, error)
	// Discard deletes them.
	Discard(ctx context.Context, hash string) error
}

// AttachTerms writes the terms of a blob row this transaction has just
// created and takes a reference to each xorb they use, creating the rows of
// those this commit wrote (written). Every xorb whose row this claim creates
// or finds at zero is checked, under its row lock, to be in the backend: GC
// may have taken such a xorb's bytes. A xorb that is gone, or that the commit
// meant to reuse and is no longer live or has since been found damaged, fails
// the claim with ErrStaleXorbs.
//
// The xorb rows are locked in hash order, one at a time. The blob sweep
// locks the rows it releases in the same order, so two transactions can
// wait on each other only one way round.
func AttachTerms(ctx context.Context, tx pgx.Tx, blobHash string, written []NewXorb, terms []Term, store XorbBytes) error {
	if len(terms) == 0 {
		return nil
	}
	mine := make(map[string]NewXorb, len(written))
	for _, x := range written {
		mine[x.Hash] = x
	}
	var used []string
	for _, t := range terms {
		if !slices.Contains(used, t.Xorb) {
			used = append(used, t.Xorb)
		}
	}
	slices.Sort(used)

	var revived []string
	for _, hash := range used {
		var x *NewXorb
		if nx, ok := mine[hash]; ok {
			x = &nx
		}
		wasZero, err := claimXorb(ctx, tx, hash, x, store)
		if err != nil {
			return err
		}
		if wasZero && x == nil {
			revived = append(revived, hash)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE xorbs SET refcount = refcount + 1, updated_at = now() WHERE hash = ANY($1)`, used); err != nil {
		return apperr.Internal(err)
	}
	if len(revived) > 0 {
		// A xorb reused from zero was given up by every blob before this
		// one, which may use only a few of its chunks: compaction looks.
		if _, err := tx.Exec(ctx, `
			UPDATE xorbs SET released_at = COALESCE(released_at, now()) WHERE hash = ANY($1)`, revived); err != nil {
			return apperr.Internal(err)
		}
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"blob_terms"},
		[]string{"blob_hash", "pos", "xorb_hash", "chunk_start", "chunk_end", "size"},
		pgx.CopyFromSlice(len(terms), func(i int) ([]any, error) {
			t := terms[i]
			return []any{blobHash, t.Pos, t.Xorb, t.Start, t.End, t.Size}, nil
		}))
	return apperr.Internal(err)
}

// claimXorb locks a xorb's row for a claim that is about to reference it,
// creating the row if x is the xorb as this caller wrote it (nil means the
// caller found it stored). It checks what AttachTerms describes: a xorb whose
// row this creates, or finds at zero, has its bytes in the backend, and one
// the caller only found stored is still live and undamaged. wasZero reports
// a row that existed at refcount 0.
func claimXorb(ctx context.Context, tx pgx.Tx, hash string, x *NewXorb, store XorbBytes) (wasZero bool, err error) {
	var (
		fresh, damaged bool
		refcount       int64
	)
	if x != nil {
		err := tx.QueryRow(ctx, `
			INSERT INTO xorbs (hash, size, key_id) VALUES ($1, $2, NULLIF($3, ''))
			ON CONFLICT (hash) DO UPDATE SET updated_at = now()
			RETURNING xmax = 0, refcount`, hash, x.Size, x.KeyID).Scan(&fresh, &refcount)
		if err != nil {
			return false, apperr.Internal(err)
		}
	} else {
		err := tx.QueryRow(ctx, `
			SELECT refcount, damaged_at IS NOT NULL FROM xorbs WHERE hash = $1 FOR UPDATE`, hash).
			Scan(&refcount, &damaged)
		if notFound(err) {
			return false, ErrStaleXorbs
		}
		if err != nil {
			return false, apperr.Internal(err)
		}
		if damaged {
			// Found damaged since the plan was made: its chunks are not
			// to be trusted to a new blob.
			return false, ErrStaleXorbs
		}
	}
	if fresh && x.Existed {
		// Bytes this caller did not write, with no row to describe them:
		// left by a commit that failed after writing them, and perhaps
		// serialized differently, so this caller's offsets cannot be
		// trusted to match them. Nothing reads a xorb with no row, so they
		// are deleted under the new row's lock, and a retry writes its own.
		if err := store.Discard(ctx, hash); err != nil {
			return false, err
		}
		return false, ErrStaleXorbs
	}
	if fresh || refcount == 0 {
		ok, err := store.Present(ctx, hash)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, ErrStaleXorbs
		}
	}
	if fresh {
		if err := insertXorbChunks(ctx, tx, *x); err != nil {
			return false, err
		}
	}
	return !fresh && refcount == 0, nil
}

func insertXorbChunks(ctx context.Context, tx pgx.Tx, x NewXorb) error {
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"xorb_chunks"},
		[]string{"xorb_hash", "idx", "chunk_hash", "byte_start", "length", "size"},
		pgx.CopyFromSlice(len(x.Chunks), func(i int) ([]any, error) {
			c := x.Chunks[i]
			return []any{x.Hash, int32(i), c.Hash, c.Offset, c.Length, c.Size}, nil
		}))
	return apperr.Internal(err)
}

// detachTerms deletes a blob's terms and drops its reference to each xorb
// they use, inside the transaction that deletes the blob row. The xorb bytes
// are left for the xorb sweep, which collects a xorb once nothing uses it.
//
// A xorb already at zero means its refcount drifted from the terms that use
// it. As with blobs that is logged, not failed: the xorb sweep refuses to
// collect a xorb any term still uses.
func detachTerms(ctx context.Context, tx pgx.Tx, blobHash string) error {
	rows, err := tx.Query(ctx, `
		SELECT hash FROM xorbs
		WHERE hash IN (SELECT xorb_hash FROM blob_terms WHERE blob_hash = $1)
		ORDER BY hash
		FOR UPDATE`, blobHash)
	if err != nil {
		return apperr.Internal(err)
	}
	hashes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return apperr.Internal(err)
	}
	if len(hashes) == 0 {
		return nil
	}

	if _, err := tx.Exec(ctx, "DELETE FROM blob_terms WHERE blob_hash = $1", blobHash); err != nil {
		return apperr.Internal(err)
	}
	// A xorb other blobs still use may now hold chunks none of them do,
	// and is marked for compaction to look at.
	tag, err := tx.Exec(ctx, `
		UPDATE xorbs SET refcount = refcount - 1, updated_at = now(),
		    released_at = CASE WHEN refcount > 1 THEN COALESCE(released_at, now()) ELSE released_at END
		WHERE hash = ANY($1) AND refcount > 0`, hashes)
	if err != nil {
		return apperr.Internal(err)
	}
	if n := tag.RowsAffected(); n != int64(len(hashes)) {
		slog.WarnContext(ctx, "xorb refcount would go below zero; refcount has drifted",
			"blob", blobHash, "xorbs", len(hashes)-int(n))
	}
	return nil
}

// BlobChunked reports whether hash is stored as xorb terms (true) or as one
// file under blobs/ (false, for content stored before chunking). A blob with
// no row is ErrNoSuchKey: whatever pointed at it is gone too.
func (d *DB) BlobChunked(ctx context.Context, hash string) (bool, error) {
	var chunked bool
	err := d.pool.QueryRow(ctx, "SELECT chunked FROM blobs WHERE hash = $1", hash).Scan(&chunked)
	if notFound(err) {
		return false, apperr.ErrNoSuchKey
	}
	if err != nil {
		return false, apperr.Internal(err)
	}
	return chunked, nil
}

// BlobTerms returns, in order, up to limit terms of blobHash that overlap the
// bytes [from, to).
func (d *DB) BlobTerms(ctx context.Context, blobHash string, from, to int64, limit int) ([]Term, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT pos, xorb_hash, chunk_start, chunk_end, size FROM blob_terms
		WHERE blob_hash = $1 AND pos < $3
		  AND pos >= COALESCE((SELECT max(pos) FROM blob_terms WHERE blob_hash = $1 AND pos <= $2), 0)
		ORDER BY pos
		LIMIT $4`, blobHash, from, to, limit)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	terms, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Term])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return terms, nil
}

// XorbChunks returns the chunks [start, end) of a xorb, in order.
func (d *DB) XorbChunks(ctx context.Context, xorb string, start, end int32) ([]XorbChunk, error) {
	rows, err := d.pool.Query(ctx, `
		SELECT chunk_hash, byte_start, length, size FROM xorb_chunks
		WHERE xorb_hash = $1 AND idx >= $2 AND idx < $3
		ORDER BY idx`, xorb, start, end)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	chunks, err := pgx.CollectRows(rows, pgx.RowToStructByPos[XorbChunk])
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return chunks, nil
}

// BlobPlacement says where a blob stands before a commit plans its writes:
// whether its row exists, and whether an object of the namespace already
// uses it.
func (d *DB) BlobPlacement(ctx context.Context, hash string, namespaceID int64) (exists, held bool, err error) {
	err = d.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM blobs WHERE hash = $1),
		       EXISTS(SELECT 1 FROM objects WHERE blob_hash = $1 AND namespace_id = $2)`,
		hash, namespaceID).Scan(&exists, &held)
	if err != nil {
		return false, false, apperr.Internal(err)
	}
	return exists, held, nil
}

// GCSweepXorbs deletes xorbs that have sat at refcount 0 past the grace
// period, calling deleteBytes for each one, and stops after limit xorbs. It
// works as GCSweep does for blobs, under the xorb's row lock, which a commit
// claiming the xorb contends on too; and a xorb some term still uses is never
// a candidate, whatever its refcount says.
func (d *DB) GCSweepXorbs(ctx context.Context, graceSecs int64, limit int64, deleteBytes func(ctx context.Context, hash string) error) (int64, error) {
	return d.sweepRows(ctx, "xorb", limit, func(ctx context.Context, tx pgx.Tx, failed []string) (string, error) {
		var hash string
		err := tx.QueryRow(ctx, `
			SELECT hash FROM xorbs
			WHERE refcount = 0
			  AND updated_at < now() - make_interval(secs => $1)
			  AND hash <> ALL($2)
			  AND NOT EXISTS (SELECT 1 FROM blob_terms t WHERE t.xorb_hash = xorbs.hash)
			ORDER BY updated_at, hash
			LIMIT 1
			FOR UPDATE SKIP LOCKED`, float64(graceSecs), failed).Scan(&hash)
		return hash, err
	}, func(ctx context.Context, tx pgx.Tx, hash string) error {
		if _, err := tx.Exec(ctx, "DELETE FROM xorbs WHERE hash = $1", hash); err != nil {
			return apperr.Internal(err)
		}
		return deleteBytes(ctx, hash)
	})
}

// StoredKeys lists every encryption key some xorb is sealed under. It runs
// at startup, so it reads the key index once per distinct key rather than
// scanning every xorb.
func (d *DB) StoredKeys(ctx context.Context) ([]string, error) {
	rows, err := d.pool.Query(ctx, `
		WITH RECURSIVE k AS (
		    (SELECT key_id FROM xorbs WHERE key_id IS NOT NULL ORDER BY key_id LIMIT 1)
		    UNION ALL
		    SELECT (SELECT x.key_id FROM xorbs x
		            WHERE x.key_id IS NOT NULL AND x.key_id > k.key_id
		            ORDER BY x.key_id LIMIT 1)
		    FROM k WHERE k.key_id IS NOT NULL
		)
		SELECT key_id FROM k WHERE key_id IS NOT NULL`)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return keys, apperr.Internal(err)
}

// RecordStorageKeys records the fingerprint of each key in fingerprints
// (id → fingerprint) whose id is not yet on record, and returns the
// fingerprint on record for each of them, which differs from the one given
// when that id was first recorded with another key.
func (d *DB) RecordStorageKeys(ctx context.Context, fingerprints map[string]string) (map[string]string, error) {
	ids := make([]string, 0, len(fingerprints))
	fps := make([]string, 0, len(fingerprints))
	for id, fp := range fingerprints {
		ids = append(ids, id)
		fps = append(fps, fp)
	}
	if _, err := d.pool.Exec(ctx, `
		INSERT INTO storage_keys (id, fingerprint)
		SELECT * FROM unnest($1::text[], $2::text[])
		ON CONFLICT (id) DO NOTHING`, ids, fps); err != nil {
		return nil, apperr.Internal(err)
	}
	rows, err := d.pool.Query(ctx, "SELECT id, fingerprint FROM storage_keys WHERE id = ANY($1)", ids)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	recorded := make(map[string]string, len(ids))
	for rows.Next() {
		var id, fp string
		if err := rows.Scan(&id, &fp); err != nil {
			rows.Close()
			return nil, apperr.Internal(err)
		}
		recorded[id] = fp
	}
	rows.Close()
	return recorded, apperr.Internal(rows.Err())
}

// StorageKeyRecorded reports whether storage_keys holds the key id.
func (d *DB) StorageKeyRecorded(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := d.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM storage_keys WHERE id = $1)", id).Scan(&ok)
	return ok, apperr.Internal(err)
}
