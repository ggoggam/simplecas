package db

import (
	"context"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// ---------------------------------------------------------------------------
// Scrubbing
//
// Stored content is read back now and then and checked against its hashes:
// every live xorb, and every live blob stored whole before chunking. A row's
// verified_at is when that last happened, or NULL if it never has; damaged_at
// is set while the last look at its bytes found them missing or wrong.
// ---------------------------------------------------------------------------

// ScrubTarget is stored content due a check.
type ScrubTarget struct {
	Hash string
	Size int64
	// Xorb is set for a xorb, and clear for a blob stored whole.
	Xorb bool
	// Verified is when the content was last checked before this claim, or
	// nil if it never was. RequeueScrub puts it back.
	Verified *time.Time
}

func (t ScrubTarget) table() string {
	if t.Xorb {
		return "xorbs"
	}
	return "blobs"
}

// ClaimScrub takes up to limit pieces of content that have gone intervalSecs
// without a check, those never checked first, then the longest unchecked. A
// claim sets verified_at to now, so other instances move on to other content;
// the caller reports how the check went with RecordScrub, or, if it could not
// make one, gives the claim back with RequeueScrub. A claim lost to a crash
// waits for the next interval.
//
// Content at refcount 0 is left out: GC may take it at any moment, and nobody
// reads it.
func (d *DB) ClaimScrub(ctx context.Context, intervalSecs int64, limit int) ([]ScrubTarget, error) {
	var claimed []ScrubTarget
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		var due []ScrubTarget
		for _, kind := range []struct {
			xorb  bool
			query string
		}{
			{true, `
				SELECT hash, size, verified_at FROM xorbs
				WHERE refcount > 0
				  AND (verified_at IS NULL OR verified_at < now() - make_interval(secs => $1))
				ORDER BY verified_at NULLS FIRST, hash
				LIMIT $2
				FOR UPDATE SKIP LOCKED`},
			{false, `
				SELECT hash, size, verified_at FROM blobs
				WHERE refcount > 0 AND NOT chunked
				  AND (verified_at IS NULL OR verified_at < now() - make_interval(secs => $1))
				ORDER BY verified_at NULLS FIRST, hash
				LIMIT $2
				FOR UPDATE SKIP LOCKED`},
		} {
			rows, err := tx.Query(ctx, kind.query, float64(intervalSecs), limit)
			if err != nil {
				return apperr.Internal(err)
			}
			for rows.Next() {
				t := ScrubTarget{Xorb: kind.xorb}
				if err := rows.Scan(&t.Hash, &t.Size, &t.Verified); err != nil {
					rows.Close()
					return apperr.Internal(err)
				}
				due = append(due, t)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return apperr.Internal(err)
			}
		}

		// The longest unchecked of either kind first.
		slices.SortStableFunc(due, func(a, b ScrubTarget) int {
			switch {
			case a.Verified == nil && b.Verified == nil:
				return 0
			case a.Verified == nil:
				return -1
			case b.Verified == nil:
				return 1
			}
			return a.Verified.Compare(*b.Verified)
		})
		claimed = due[:min(limit, len(due))]
		for _, xorb := range []bool{true, false} {
			var hashes []string
			for _, t := range claimed {
				if t.Xorb == xorb {
					hashes = append(hashes, t.Hash)
				}
			}
			if len(hashes) == 0 {
				continue
			}
			table := ScrubTarget{Xorb: xorb}.table()
			if _, err := tx.Exec(ctx, "UPDATE "+table+" SET verified_at = now() WHERE hash = ANY($1)", hashes); err != nil {
				return apperr.Internal(err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

// RecordScrub records how a check of t went. Sound content is marked
// checked, and any damage recorded earlier is cleared: the bytes were
// restored, or what looked like damage was not. Damaged content is marked so,
// and a damaged xorb is also marked for compaction, which rewrites it from
// sound copies of its chunks where it can.
func (d *DB) RecordScrub(ctx context.Context, t ScrubTarget, sound bool) error {
	if sound {
		_, err := d.pool.Exec(ctx, "UPDATE "+t.table()+" SET verified_at = now(), damaged_at = NULL WHERE hash = $1", t.Hash)
		return apperr.Internal(err)
	}
	if t.Xorb {
		// Marked for compaction on every failed scrub, not only the first:
		// a sound copy of a damaged chunk may have been stored since the
		// last try.
		_, err := d.pool.Exec(ctx, `
			UPDATE xorbs SET damaged_at = COALESCE(damaged_at, now()), released_at = COALESCE(released_at, now())
			WHERE hash = $1`, t.Hash)
		return apperr.Internal(err)
	}
	_, err := d.pool.Exec(ctx, "UPDATE blobs SET damaged_at = COALESCE(damaged_at, now()) WHERE hash = $1", t.Hash)
	return apperr.Internal(err)
}

// RequeueScrub gives back a claim on t whose check could not be made, so the
// next pass tries again.
func (d *DB) RequeueScrub(ctx context.Context, t ScrubTarget) error {
	_, err := d.pool.Exec(ctx, "UPDATE "+t.table()+" SET verified_at = $2 WHERE hash = $1", t.Hash, t.Verified)
	return apperr.Internal(err)
}

// MarkXorbDamaged records that a read found a xorb's bytes missing, or some
// chunk of it not matching its hash. Dedup stops reusing its chunks, and the
// first time it is found damaged it is marked for compaction to repair;
// reads of it after that leave the retries to the scrub.
func (d *DB) MarkXorbDamaged(ctx context.Context, hash string) error {
	_, err := d.pool.Exec(ctx, `
		UPDATE xorbs SET damaged_at = now(), released_at = COALESCE(released_at, now())
		WHERE hash = $1 AND damaged_at IS NULL`, hash)
	return apperr.Internal(err)
}

// ContentLive reports whether t still has a row with a reference. Content a
// check could not find in the backend is damaged only if so: otherwise GC
// took it, rightly, while it was being checked.
func (d *DB) ContentLive(ctx context.Context, t ScrubTarget) (bool, error) {
	var live bool
	err := d.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM "+t.table()+" WHERE hash = $1 AND refcount > 0)", t.Hash).Scan(&live)
	if err != nil {
		return false, apperr.Internal(err)
	}
	return live, nil
}

// Damage counts the live xorbs and whole-file blobs currently marked damaged,
// and the objects whose content uses one. Such an object may still read back
// whole: the damage may be in chunks it does not use, or in chunks that have
// sound copies elsewhere.
type Damage struct {
	Xorbs   int64
	Blobs   int64
	Objects int64
}

// CountDamage reports what is currently marked damaged.
func (d *DB) CountDamage(ctx context.Context) (Damage, error) {
	var dmg Damage
	err := d.pool.QueryRow(ctx, `
		SELECT
		    (SELECT COUNT(*) FROM xorbs WHERE damaged_at IS NOT NULL AND refcount > 0),
		    (SELECT COUNT(*) FROM blobs WHERE damaged_at IS NOT NULL AND refcount > 0),
		    (SELECT COUNT(*) FROM objects o WHERE o.blob_hash IN (
		        SELECT hash FROM blobs WHERE damaged_at IS NOT NULL
		        UNION
		        SELECT t.blob_hash FROM blob_terms t JOIN xorbs x ON x.hash = t.xorb_hash
		        WHERE x.damaged_at IS NOT NULL))`).
		Scan(&dmg.Xorbs, &dmg.Blobs, &dmg.Objects)
	if err != nil {
		return Damage{}, apperr.Internal(err)
	}
	return dmg, nil
}
