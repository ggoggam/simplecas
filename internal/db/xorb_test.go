package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

// chunks of 10 bytes each, named by seed, as a xorb stores them.
func tenByteChunks(seeds ...string) []XorbChunk {
	out := make([]XorbChunk, len(seeds))
	for i, s := range seeds {
		out[i] = XorbChunk{Hash: hashOf(s), Offset: int64(i) * 18, Length: 18, Size: 10}
	}
	return out
}

// putTerms stores key as a new blob made of terms, writing the rows of the
// xorbs in written, and returns the error AttachTerms gave.
func putTerms(t *testing.T, d *DB, nsID int64, key, blob string, written []NewXorb, terms []Term, store XorbBytes) error {
	t.Helper()
	var size int64
	for i := range terms {
		terms[i].Pos = size
		size += terms[i].Size
	}
	return d.InTx(t.Context(), func(tx pgx.Tx) error {
		claim, err := ClaimBlob(t.Context(), tx, blob, size, "")
		if err != nil {
			return err
		}
		if !claim.Fresh {
			return fmt.Errorf("blob %s already exists", blob)
		}
		if err := AttachTerms(t.Context(), tx, blob, written, terms, store); err != nil {
			return err
		}
		return UpsertObject(t.Context(), tx, nsID, key, blob, "", size, "application/octet-stream")
	})
}

func mustPutTerms(t *testing.T, d *DB, nsID int64, key, blob string, written []NewXorb, terms ...Term) {
	t.Helper()
	if err := putTerms(t, d, nsID, key, blob, written, terms, allPresent{}); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

// xorbRefcount reads a xorb's reference count, or ok=false if its row is gone.
func xorbRefcount(t *testing.T, d *DB, hash string) (int64, bool) {
	t.Helper()
	var n int64
	err := d.pool.QueryRow(t.Context(), "SELECT refcount FROM xorbs WHERE hash = $1", hash).Scan(&n)
	if notFound(err) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("read xorb refcount: %v", err)
	}
	return n, true
}

// staleXorb backdates a xorb's updated_at so it falls outside the grace period.
func staleXorb(t *testing.T, d *DB, hash string, seconds int) {
	t.Helper()
	_, err := d.pool.Exec(t.Context(),
		"UPDATE xorbs SET updated_at = now() - make_interval(secs => $2) WHERE hash = $1", hash, float64(seconds))
	if err != nil {
		t.Fatal(err)
	}
}

// A xorb's refcount counts the blobs with a term on it, each once however
// many terms it has there.
func TestAttachTermsCountsEachBlobOnce(t *testing.T) {
	d := testDB(t)
	nsID := mustNamespace(t, d, "ns", nil)
	x := NewXorb{Hash: hashOf("xorb"), Size: 72, Chunks: tenByteChunks("c0", "c1", "c2", "c3")}

	mustPutTerms(t, d, nsID, "a", hashOf("blob a"), []NewXorb{x},
		Term{Xorb: x.Hash, Start: 0, End: 4, Size: 40}, Term{Xorb: x.Hash, Start: 1, End: 2, Size: 10})
	mustPutTerms(t, d, nsID, "b", hashOf("blob b"), nil, Term{Xorb: x.Hash, Start: 2, End: 4, Size: 20})

	if n, _ := xorbRefcount(t, d, x.Hash); n != 2 {
		t.Errorf("xorb refcount = %d, want 2: two blobs use it", n)
	}
	var chunks int
	if err := d.pool.QueryRow(t.Context(), "SELECT count(*) FROM xorb_chunks WHERE xorb_hash = $1", x.Hash).Scan(&chunks); err != nil {
		t.Fatal(err)
	}
	if chunks != 4 {
		t.Errorf("%d chunk rows, want the xorb's 4 recorded once", chunks)
	}
}

type fakeBytes struct {
	present   bool
	discarded []string
}

func (f *fakeBytes) Present(context.Context, string) (bool, error) { return f.present, nil }
func (f *fakeBytes) Discard(_ context.Context, hash string) error {
	f.discarded = append(f.discarded, hash)
	return nil
}

// A claim that can no longer stand fails as stale, so the commit plans again:
// a xorb to reuse that was collected, one this commit wrote that is not in the
// backend, or bytes someone else left with no row.
func TestAttachTermsRefusesStaleXorbs(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	x := NewXorb{Hash: hashOf("xorb"), Size: 18, Chunks: tenByteChunks("c0")}
	term := Term{Xorb: x.Hash, Start: 0, End: 1, Size: 10}

	if err := putTerms(t, d, nsID, "gone", hashOf("b1"), nil, []Term{term}, allPresent{}); !errors.Is(err, ErrStaleXorbs) {
		t.Errorf("reusing a xorb with no row: err = %v, want ErrStaleXorbs", err)
	}
	if err := putTerms(t, d, nsID, "unwritten", hashOf("b2"), []NewXorb{x}, []Term{term}, &fakeBytes{present: false}); !errors.Is(err, ErrStaleXorbs) {
		t.Errorf("a written xorb not in the backend: err = %v, want ErrStaleXorbs", err)
	}
	existed := x
	existed.Existed = true
	store := &fakeBytes{present: true}
	if err := putTerms(t, d, nsID, "orphan", hashOf("b3"), []NewXorb{existed}, []Term{term}, store); !errors.Is(err, ErrStaleXorbs) {
		t.Errorf("bytes left with no row: err = %v, want ErrStaleXorbs", err)
	}
	if len(store.discarded) != 1 || store.discarded[0] != x.Hash {
		t.Errorf("discarded %v, want the untrusted bytes of %s", store.discarded, x.Hash)
	}

	// A xorb at zero is reused only once its bytes are confirmed.
	mustPutTerms(t, d, nsID, "k", hashOf("b4"), []NewXorb{x}, term)
	if _, err := d.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}
	staleBlob := hashOf("b4")
	stale(t, d, staleBlob, 7200)
	if _, err := d.GCSweep(ctx, 3600, 100, nil); err != nil {
		t.Fatal(err)
	}
	if n, ok := xorbRefcount(t, d, x.Hash); !ok || n != 0 {
		t.Fatalf("setup: xorb refcount = %d (present=%v), want a zero-ref row", n, ok)
	}
	if err := putTerms(t, d, nsID, "revive", hashOf("b5"), nil, []Term{term}, &fakeBytes{present: false}); !errors.Is(err, ErrStaleXorbs) {
		t.Errorf("reviving a xorb whose bytes are gone: err = %v, want ErrStaleXorbs", err)
	}
	mustPutTerms(t, d, nsID, "revive", hashOf("b5"), nil, term)
	if n, _ := xorbRefcount(t, d, x.Hash); n != 1 {
		t.Errorf("revived xorb refcount = %d, want 1", n)
	}
}

// Collecting a chunked blob deletes no bytes of its own: it drops the blob's
// references to its xorbs, and the xorb sweep collects those nothing else
// uses.
func TestGCSweepHandsAChunkedBlobsXorbsToTheXorbSweep(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	only := NewXorb{Hash: hashOf("only in a"), Size: 18, Chunks: tenByteChunks("o")}
	shared := NewXorb{Hash: hashOf("shared"), Size: 18, Chunks: tenByteChunks("s")}
	a := hashOf("blob a")

	mustPutTerms(t, d, nsID, "a", a, []NewXorb{only, shared},
		Term{Xorb: only.Hash, End: 1, Size: 10}, Term{Xorb: shared.Hash, End: 1, Size: 10})
	mustPutTerms(t, d, nsID, "b", hashOf("blob b"), nil, Term{Xorb: shared.Hash, End: 1, Size: 10})
	if _, err := d.DeleteObject(ctx, nsID, "a"); err != nil {
		t.Fatal(err)
	}
	stale(t, d, a, 7200)

	n, err := d.GCSweep(ctx, 3600, 100, func(context.Context, string) error {
		t.Error("a chunked blob has no bytes of its own to delete")
		return nil
	})
	if err != nil || n != 1 {
		t.Fatalf("swept %d blobs, %v; want 1", n, err)
	}
	if n, _ := xorbRefcount(t, d, only.Hash); n != 0 {
		t.Errorf("unshared xorb refcount = %d, want 0 once its only blob is gone", n)
	}
	if n, _ := xorbRefcount(t, d, shared.Hash); n != 1 {
		t.Errorf("shared xorb refcount = %d, want 1: blob b still uses it", n)
	}

	var deleted []string
	n, err = d.GCSweepXorbs(ctx, 0, 100, func(_ context.Context, hash string) error {
		deleted = append(deleted, hash)
		return nil
	})
	if err != nil || n != 1 {
		t.Fatalf("swept %d xorbs, %v; want 1", n, err)
	}
	if len(deleted) != 1 || deleted[0] != only.Hash {
		t.Errorf("deleted bytes for %v, want [%s]", deleted, only.Hash)
	}
	if _, ok := xorbRefcount(t, d, only.Hash); ok {
		t.Error("the swept xorb's row should be gone")
	}
	var chunks int
	if err := d.pool.QueryRow(ctx, "SELECT count(*) FROM xorb_chunks WHERE xorb_hash = $1", only.Hash).Scan(&chunks); err != nil || chunks != 0 {
		t.Errorf("%d chunk rows left for the swept xorb, %v; want none", chunks, err)
	}
	if _, ok := xorbRefcount(t, d, shared.Hash); !ok {
		t.Error("a xorb a live blob uses must survive the sweep")
	}
}

// As with blobs, the refcount is a cache: a xorb some term uses is never
// collected, whatever its count says; and one inside the grace period waits.
func TestGCSweepXorbsSparesUsedAndRecentXorbs(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	used := NewXorb{Hash: hashOf("used"), Size: 18, Chunks: tenByteChunks("u")}
	recent := NewXorb{Hash: hashOf("recent"), Size: 18, Chunks: tenByteChunks("r")}
	blob := hashOf("blob")

	mustPutTerms(t, d, nsID, "k", hashOf("user"), []NewXorb{used}, Term{Xorb: used.Hash, End: 1, Size: 10})
	if _, err := d.pool.Exec(ctx, "UPDATE xorbs SET refcount = 0 WHERE hash = $1", used.Hash); err != nil {
		t.Fatal(err)
	}
	staleXorb(t, d, used.Hash, 7200)
	mustPutTerms(t, d, nsID, "gone", blob, []NewXorb{recent}, Term{Xorb: recent.Hash, End: 1, Size: 10})
	if _, err := d.DeleteObject(ctx, nsID, "gone"); err != nil {
		t.Fatal(err)
	}
	stale(t, d, blob, 7200)
	if _, err := d.GCSweep(ctx, 3600, 100, nil); err != nil {
		t.Fatal(err)
	}

	n, err := d.GCSweepXorbs(ctx, 3600, 100, func(_ context.Context, hash string) error {
		t.Errorf("deleted %s: neither xorb may be collected", hash)
		return nil
	})
	if err != nil || n != 0 {
		t.Errorf("swept %d xorbs, %v; want none", n, err)
	}
}

func TestBlobTermsFindsTheTermsARangeOverlaps(t *testing.T) {
	d := testDB(t)
	nsID := mustNamespace(t, d, "ns", nil)
	x := NewXorb{Hash: hashOf("xorb"), Size: 72, Chunks: tenByteChunks("c0", "c1", "c2", "c3")}
	blob := hashOf("terms")
	mustPutTerms(t, d, nsID, "k", blob, []NewXorb{x},
		Term{Xorb: x.Hash, Start: 0, End: 1, Size: 10},
		Term{Xorb: x.Hash, Start: 3, End: 4, Size: 10},
		Term{Xorb: x.Hash, Start: 1, End: 3, Size: 20})
	at := func(pos ...int64) string { return fmt.Sprint(pos) }

	for _, tc := range []struct {
		name     string
		from, to int64
		limit    int
		want     string
	}{
		{"inside one term", 12, 18, 10, at(10)},
		{"straddles terms", 15, 25, 10, at(10, 20)},
		{"ends on a boundary", 10, 20, 10, at(10)},
		{"whole blob", 0, 40, 10, at(0, 10, 20)},
		{"limited", 0, 40, 2, at(0, 10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := d.BlobTerms(t.Context(), blob, tc.from, tc.to, tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			var pos []int64
			for _, term := range got {
				pos = append(pos, term.Pos)
			}
			if fmt.Sprint(pos) != tc.want {
				t.Errorf("terms at %v, want %s", pos, tc.want)
			}
		})
	}
}

// Dedup reuses only live xorbs, and a namespace's own runs are told apart
// from runs only others hold.
func TestLocateChunksAndTermsHeldInNamespace(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	mine := mustNamespace(t, d, "mine", nil)
	theirs := mustNamespace(t, d, "theirs", nil)
	live := NewXorb{Hash: hashOf("live"), Size: 54, Chunks: tenByteChunks("a", "b", "c")}
	dead := NewXorb{Hash: hashOf("dead"), Size: 18, Chunks: tenByteChunks("z")}

	mustPutTerms(t, d, mine, "k", hashOf("mine"), []NewXorb{live}, Term{Xorb: live.Hash, Start: 0, End: 2, Size: 20})
	mustPutTerms(t, d, theirs, "k", hashOf("theirs"), nil, Term{Xorb: live.Hash, Start: 0, End: 3, Size: 30})
	mustPutTerms(t, d, theirs, "gone", hashOf("gone"), []NewXorb{dead}, Term{Xorb: dead.Hash, End: 1, Size: 10})
	if _, err := d.DeleteObject(ctx, theirs, "gone"); err != nil {
		t.Fatal(err)
	}
	stale(t, d, hashOf("gone"), 7200)
	if _, err := d.GCSweep(ctx, 3600, 100, nil); err != nil {
		t.Fatal(err)
	}

	found, err := d.LocateChunks(ctx, []string{hashOf("b"), hashOf("z"), hashOf("nowhere")})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(found); got != fmt.Sprint(map[string][]ChunkLocation{hashOf("b"): {{Xorb: live.Hash, Index: 1}}}) {
		t.Errorf("found %s, want only b, in the live xorb", got)
	}

	held, err := d.TermsHeldInNamespace(ctx, mine, []Term{
		{Xorb: live.Hash, Start: 0, End: 2},
		{Xorb: live.Hash, Start: 1, End: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(held) != "[true false]" {
		t.Errorf("held = %v, want the first run (mine) but not the second (only theirs reach chunk 2)", held)
	}
}
