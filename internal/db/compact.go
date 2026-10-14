package db

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ---------------------------------------------------------------------------
// Compaction
//
// A xorb lives as long as any blob uses any of its chunks, so once most of
// the blobs that used it are gone it can be mostly dead chunks. Compaction
// writes the chunks still in use to a new xorb and moves every term onto it.
// The old xorb is left at refcount 0, and the xorb sweep collects it after
// the grace period, as it would any other.
//
// Only a xorb that has lost a blob can have dead chunks, so detachTerms marks
// those (released_at), and compaction looks at nothing else.
// ---------------------------------------------------------------------------

// ClaimCompaction takes up to limit xorbs that lost a blob at least graceSecs
// ago, unmarking them so that other instances move on. The wait lets a burst
// of deletes settle before a xorb is rewritten. A xorb that has since gone to
// zero is unmarked but not returned: the sweep will take it whole.
func (d *DB) ClaimCompaction(ctx context.Context, graceSecs int64, limit int) ([]string, error) {
	rows, err := d.pool.Query(ctx, `
		UPDATE xorbs SET released_at = NULL
		WHERE hash IN (
		    SELECT hash FROM xorbs
		    WHERE released_at < now() - make_interval(secs => $1)
		    ORDER BY released_at, hash
		    LIMIT $2
		    FOR UPDATE SKIP LOCKED)
		RETURNING hash, refcount`, float64(graceSecs), limit)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	var hashes []string
	for rows.Next() {
		var (
			hash     string
			refcount int64
		)
		if err := rows.Scan(&hash, &refcount); err != nil {
			rows.Close()
			return nil, apperr.Internal(err)
		}
		if refcount > 0 {
			hashes = append(hashes, hash)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, apperr.Internal(err)
	}
	slices.Sort(hashes)
	return hashes, nil
}

// RequeueCompaction marks a xorb again after a compaction that could not be
// carried out this time, so a later pass retries it.
func (d *DB) RequeueCompaction(ctx context.Context, hash string) error {
	_, err := d.pool.Exec(ctx, `
		UPDATE xorbs SET released_at = COALESCE(released_at, now()) WHERE hash = $1 AND refcount > 0`, hash)
	return apperr.Internal(err)
}

// XorbUse is a xorb as compaction sees it: every chunk, and which of them
// some blob's term uses.
type XorbUse struct {
	Size    int64
	Damaged bool
	Chunks  []XorbChunk
	Live    []bool
}

// LiveBytes is how many of the xorb's stored bytes hold live chunks.
func (u XorbUse) LiveBytes() int64 {
	var n int64
	for i, c := range u.Chunks {
		if u.Live[i] {
			n += int64(c.Length)
		}
	}
	return n
}

// XorbUse reads a live xorb's chunks and which of them are in use. ok is
// false for a xorb with no row or no reference.
func (d *DB) XorbUse(ctx context.Context, hash string) (use XorbUse, ok bool, err error) {
	err = d.pool.QueryRow(ctx, `
		SELECT size, damaged_at IS NOT NULL FROM xorbs WHERE hash = $1 AND refcount > 0`, hash).
		Scan(&use.Size, &use.Damaged)
	if notFound(err) {
		return XorbUse{}, false, nil
	}
	if err != nil {
		return XorbUse{}, false, apperr.Internal(err)
	}
	if use.Chunks, err = d.XorbChunks(ctx, hash, 0, 1<<31-1); err != nil {
		return XorbUse{}, false, err
	}
	rows, err := d.pool.Query(ctx, `
		SELECT DISTINCT chunk_start, chunk_end FROM blob_terms WHERE xorb_hash = $1`, hash)
	if err != nil {
		return XorbUse{}, false, apperr.Internal(err)
	}
	use.Live = make([]bool, len(use.Chunks))
	for rows.Next() {
		var start, end int32
		if err := rows.Scan(&start, &end); err != nil {
			rows.Close()
			return XorbUse{}, false, apperr.Internal(err)
		}
		for i := max(start, 0); i < min(end, int32(len(use.Live))); i++ {
			use.Live[i] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return XorbUse{}, false, apperr.Internal(err)
	}
	return use, true, nil
}

// CompactLockTimeout bounds every lock wait of a compaction's transaction.
// Compaction takes its locks in a different order from a commit (blobs, then
// xorbs, then nothing; a commit can lock a blob after a xorb, when it
// releases the blob an overwritten object used), so it must be the side that
// gives up: with this well under Postgres's deadlock_timeout, it times out
// and rolls back before the deadlock detector would pick a victim, and it
// never holds up an upload for longer than this.
var CompactLockTimeout = 200 * time.Millisecond

// MoveTerms points every term on the xorb from at the same chunks in to, a
// xorb the caller wrote holding the chunks of from that are in use: chunk i
// of from is chunk index[i] of to, or index[i] is -1 when to does not hold
// it. It reports how many blobs were moved.
//
// to's row is created as AttachTerms creates the row of a xorb a commit
// wrote, with the same checks. from is left at refcount 0, with no terms, for
// the xorb sweep to collect after the grace period: a read that looked its
// terms up before the move can still fetch from it until then, and finds the
// chunks in to after that (see cas.Open).
//
// The move is refused with ErrStaleXorbs when the terms on from changed since
// the caller read them in a way the new xorb does not cover, a lock is held
// by someone else for longer than CompactLockTimeout, or from is no longer
// live. Nothing is changed then, and the caller tries again later.
func (d *DB) MoveTerms(ctx context.Context, from string, to NewXorb, index []int32, store XorbBytes) (moved int, err error) {
	if from == to.Hash {
		return 0, fmt.Errorf("compaction of xorb %s rewrote it whole", from)
	}
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		timeout := fmt.Sprintf("SET LOCAL lock_timeout = %d", CompactLockTimeout.Milliseconds())
		if _, err := tx.Exec(ctx, timeout); err != nil {
			return apperr.Internal(err)
		}

		// The blobs first, as a commit and the blob sweep lock a blob
		// before its xorbs. Locking them keeps the sweep from detaching
		// them midway.
		rows, err := tx.Query(ctx, `
			SELECT hash FROM blobs
			WHERE hash IN (SELECT blob_hash FROM blob_terms WHERE xorb_hash = $1)
			ORDER BY hash
			FOR UPDATE`, from)
		if err != nil {
			return lockLost(err)
		}
		blobs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return lockLost(err)
		}

		// Then both xorbs, in hash order as AttachTerms takes them.
		for _, hash := range sortedPair(from, to.Hash) {
			if hash == to.Hash {
				if _, err := claimXorb(ctx, tx, to.Hash, &to, store); err != nil {
					return lockLost(err)
				}
				continue
			}
			var refcount int64
			err := tx.QueryRow(ctx, "SELECT refcount FROM xorbs WHERE hash = $1 FOR UPDATE", from).Scan(&refcount)
			if notFound(err) || (err == nil && refcount == 0) {
				return ErrStaleXorbs
			}
			if err != nil {
				return lockLost(err)
			}
		}

		// With from locked no claim can add a term to it, so the terms
		// read now are all there are. Every one must belong to a blob
		// locked above, and use only chunks to holds.
		rows, err = tx.Query(ctx, `
			SELECT blob_hash, chunk_start, chunk_end FROM blob_terms WHERE xorb_hash = $1`, from)
		if err != nil {
			return apperr.Internal(err)
		}
		type term struct {
			Blob       string
			Start, End int32
		}
		terms, err := pgx.CollectRows(rows, pgx.RowToStructByPos[term])
		if err != nil {
			return apperr.Internal(err)
		}
		for _, t := range terms {
			if _, ok := slices.BinarySearch(blobs, t.Blob); !ok {
				return ErrStaleXorbs
			}
			if t.Start < 0 || int(t.End) > len(index) || t.Start >= t.End {
				return ErrStaleXorbs
			}
			for i := t.Start; i < t.End; i++ {
				if index[i] < 0 || index[i] != index[t.Start]+(i-t.Start) {
					return ErrStaleXorbs
				}
			}
		}

		olds, news := make([]int32, 0, len(index)), make([]int32, 0, len(index))
		for i, n := range index {
			if n >= 0 {
				olds, news = append(olds, int32(i)), append(news, n)
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE blob_terms t
			SET xorb_hash = $2, chunk_start = m.n, chunk_end = m.n + (t.chunk_end - t.chunk_start)
			FROM unnest($3::int[], $4::int[]) AS m(o, n)
			WHERE t.xorb_hash = $1 AND t.chunk_start = m.o`, from, to.Hash, olds, news); err != nil {
			return apperr.Internal(err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE xorbs SET refcount = 0, released_at = NULL, updated_at = now() WHERE hash = $1`, from); err != nil {
			return apperr.Internal(err)
		}
		// Counted rather than added to, in case some of the blobs already
		// used to: a xorb's refcount counts each blob once.
		if _, err := tx.Exec(ctx, `
			UPDATE xorbs SET updated_at = now(),
			    refcount = (SELECT COUNT(DISTINCT blob_hash) FROM blob_terms WHERE xorb_hash = $1)
			WHERE hash = $1`, to.Hash); err != nil {
			return apperr.Internal(err)
		}
		moved = len(blobs)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return moved, nil
}

// lockLost turns a lock wait that ran out into ErrStaleXorbs, which the caller
// retries later; anything else is a real failure.
func lockLost(err error) error {
	if lockNotAvailable(err) {
		return ErrStaleXorbs
	}
	if errors.Is(err, ErrStaleXorbs) || errors.As(err, new(*apperr.Error)) {
		return err
	}
	return apperr.Internal(err)
}

func sortedPair(a, b string) []string {
	if a < b {
		return []string{a, b}
	}
	return []string{b, a}
}
