package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// releasedAt reads a xorb's compaction mark, nil when it is unmarked.
func releasedAt(t *testing.T, d *DB, hash string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := d.pool.QueryRow(t.Context(), "SELECT released_at FROM xorbs WHERE hash = $1", hash).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func unmark(t *testing.T, d *DB) {
	t.Helper()
	if _, err := d.pool.Exec(t.Context(), "UPDATE xorbs SET released_at = NULL"); err != nil {
		t.Fatal(err)
	}
}

// collect deletes key and sweeps its blob straight away.
func collect(t *testing.T, d *DB, nsID int64, key, blob string) {
	t.Helper()
	if _, err := d.DeleteObject(t.Context(), nsID, key); err != nil {
		t.Fatal(err)
	}
	stale(t, d, blob, 7200)
	if _, err := d.GCSweep(t.Context(), 3600, 100, nil); err != nil {
		t.Fatal(err)
	}
}

// A xorb that loses a blob but is still used by others may now hold dead
// chunks, and is marked for compaction; one that loses its last blob is left
// to the sweep, and one reused from zero is marked too.
func TestReleasingABlobMarksItsXorbsForCompaction(t *testing.T) {
	d := testDB(t)
	nsID := mustNamespace(t, d, "ns", nil)
	shared := NewXorb{Hash: hashOf("shared"), Size: 54, Chunks: tenByteChunks("a", "b", "c")}
	alone := NewXorb{Hash: hashOf("alone"), Size: 18, Chunks: tenByteChunks("z")}

	mustPutTerms(t, d, nsID, "one", hashOf("one"), []NewXorb{shared, alone},
		Term{Xorb: shared.Hash, Start: 0, End: 3, Size: 30}, Term{Xorb: alone.Hash, Start: 0, End: 1, Size: 10})
	mustPutTerms(t, d, nsID, "two", hashOf("two"), nil, Term{Xorb: shared.Hash, Start: 0, End: 1, Size: 10})
	unmark(t, d)

	collect(t, d, nsID, "one", hashOf("one"))
	if releasedAt(t, d, shared.Hash) == nil {
		t.Error("a xorb still used by another blob should be marked for compaction")
	}
	if releasedAt(t, d, alone.Hash) != nil {
		t.Error("a xorb nothing uses any more is the sweep's, not compaction's")
	}

	unmark(t, d)
	mustPutTerms(t, d, nsID, "three", hashOf("three"), nil, Term{Xorb: alone.Hash, Start: 0, End: 1, Size: 10})
	if releasedAt(t, d, alone.Hash) == nil {
		t.Error("a xorb reused from zero should be marked for compaction")
	}
}

// Compaction takes only xorbs marked long enough ago, unmarks what it takes,
// and returns only those still in use.
func TestClaimCompactionHonoursTheGracePeriod(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	old := NewXorb{Hash: hashOf("old"), Size: 18, Chunks: tenByteChunks("a")}
	fresh := NewXorb{Hash: hashOf("fresh"), Size: 18, Chunks: tenByteChunks("b")}
	mustPutTerms(t, d, nsID, "k", hashOf("k"), []NewXorb{old, fresh},
		Term{Xorb: old.Hash, End: 1, Size: 10}, Term{Xorb: fresh.Hash, End: 1, Size: 10})
	if _, err := d.pool.Exec(ctx, `
		UPDATE xorbs SET released_at = now() - CASE WHEN hash = $1 THEN interval '2 hours' ELSE interval '0' END`, old.Hash); err != nil {
		t.Fatal(err)
	}

	claimed, err := d.ClaimCompaction(ctx, 3600, 10)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(claimed) != fmt.Sprint([]string{old.Hash}) {
		t.Errorf("claimed %v, want only the xorb marked over an hour ago", claimed)
	}
	if releasedAt(t, d, old.Hash) != nil || releasedAt(t, d, fresh.Hash) == nil {
		t.Error("the claimed xorb should be unmarked, the other left marked")
	}

	if err := d.RequeueCompaction(ctx, old.Hash); err != nil {
		t.Fatal(err)
	}
	if releasedAt(t, d, old.Hash) == nil {
		t.Error("a requeued xorb should be marked again")
	}
}

// Moving a xorb's terms points each at the same chunks in the new xorb,
// hands the references over, and leaves the old xorb to the sweep.
func TestMoveTermsHandsEveryTermToTheNewXorb(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	from := NewXorb{Hash: hashOf("from"), Size: 90, Chunks: tenByteChunks("a", "b", "c", "d", "e")}
	mustPutTerms(t, d, nsID, "x", hashOf("x"), []NewXorb{from}, Term{Xorb: from.Hash, Start: 1, End: 2, Size: 10})
	mustPutTerms(t, d, nsID, "y", hashOf("y"), nil,
		Term{Xorb: from.Hash, Start: 3, End: 5, Size: 20}, Term{Xorb: from.Hash, Start: 1, End: 2, Size: 10})

	// Chunks a and c are dead; the new xorb holds b, d, e.
	to := NewXorb{Hash: hashOf("to"), Size: 54, Chunks: tenByteChunks("b", "d", "e")}
	moved, err := d.MoveTerms(ctx, from.Hash, to, []int32{-1, 0, -1, 1, 2}, allPresent{})
	if err != nil {
		t.Fatal(err)
	}
	if moved != 2 {
		t.Errorf("moved %d blobs, want 2", moved)
	}

	terms, err := d.BlobTerms(ctx, hashOf("y"), 0, 30, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []Term{{Pos: 0, Xorb: to.Hash, Start: 1, End: 3, Size: 20}, {Pos: 20, Xorb: to.Hash, Start: 0, End: 1, Size: 10}}
	if fmt.Sprint(terms) != fmt.Sprint(want) {
		t.Errorf("y's terms = %v, want %v", terms, want)
	}
	if n, _ := xorbRefcount(t, d, to.Hash); n != 2 {
		t.Errorf("new xorb refcount = %d, want 2", n)
	}
	if n, _ := xorbRefcount(t, d, from.Hash); n != 0 {
		t.Errorf("old xorb refcount = %d, want 0, for the sweep", n)
	}
	staleXorb(t, d, from.Hash, 7200)
	swept, err := d.GCSweepXorbs(ctx, 3600, 10, func(context.Context, string) error { return nil })
	if err != nil || swept != 1 {
		t.Errorf("swept %d xorbs (%v), want the old one", swept, err)
	}
}

// A move that the terms have outgrown since the new xorb was planned changes
// nothing: here a term uses a chunk the new xorb does not hold.
func TestMoveTermsRefusesTermsTheNewXorbDoesNotCover(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	from := NewXorb{Hash: hashOf("from"), Size: 54, Chunks: tenByteChunks("a", "b", "c")}
	mustPutTerms(t, d, nsID, "x", hashOf("x"), []NewXorb{from}, Term{Xorb: from.Hash, Start: 0, End: 2, Size: 20})

	to := NewXorb{Hash: hashOf("to"), Size: 18, Chunks: tenByteChunks("a")}
	if _, err := d.MoveTerms(ctx, from.Hash, to, []int32{0, -1, -1}, allPresent{}); !errors.Is(err, ErrStaleXorbs) {
		t.Fatalf("err = %v, want ErrStaleXorbs", err)
	}
	if n, _ := xorbRefcount(t, d, from.Hash); n != 1 {
		t.Errorf("old xorb refcount = %d, want it untouched at 1", n)
	}
	if _, ok := xorbRefcount(t, d, to.Hash); ok {
		t.Error("the new xorb's row should have been rolled back")
	}
}

// A damaged xorb is left out of dedup, and a claim that planned to reuse it
// before the damage was found is refused.
func TestDamagedXorbsAreNotReused(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	x := NewXorb{Hash: hashOf("x"), Size: 36, Chunks: tenByteChunks("a", "b")}
	term := Term{Xorb: x.Hash, Start: 0, End: 2, Size: 20}
	mustPutTerms(t, d, nsID, "k", hashOf("k"), []NewXorb{x}, term)

	if err := d.MarkXorbDamaged(ctx, x.Hash); err != nil {
		t.Fatal(err)
	}
	found, err := d.LocateChunks(ctx, []string{hashOf("a")})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Errorf("found %v in a damaged xorb", found)
	}
	if err := putTerms(t, d, nsID, "again", hashOf("again"), nil, []Term{term}, allPresent{}); !errors.Is(err, ErrStaleXorbs) {
		t.Errorf("reusing a damaged xorb: err = %v, want ErrStaleXorbs", err)
	}
	if releasedAt(t, d, x.Hash) == nil {
		t.Error("a damaged xorb should be marked for compaction to repair")
	}
}

// Compaction gives way to anyone holding a lock it needs, rather than hold
// up an upload or end up in a deadlock with one.
func TestMoveTermsGivesWayToAHeldLock(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	from := NewXorb{Hash: hashOf("from"), Size: 36, Chunks: tenByteChunks("a", "b")}
	mustPutTerms(t, d, nsID, "x", hashOf("x"), []NewXorb{from}, Term{Xorb: from.Hash, Start: 1, End: 2, Size: 10})

	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT 1 FROM blobs WHERE hash = $1 FOR UPDATE", hashOf("x")); err != nil {
		t.Fatal(err)
	}

	to := NewXorb{Hash: hashOf("to"), Size: 18, Chunks: tenByteChunks("b")}
	start := time.Now()
	if _, err := d.MoveTerms(ctx, from.Hash, to, []int32{-1, 0}, allPresent{}); !errors.Is(err, ErrStaleXorbs) {
		t.Fatalf("err = %v, want ErrStaleXorbs", err)
	}
	if waited := time.Since(start); waited > 10*CompactLockTimeout {
		t.Errorf("waited %v for the lock, want about %v", waited, CompactLockTimeout)
	}
}
