package cas

import (
	"bytes"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// compactNow is collectNow with compaction on at the default threshold.
func compactNow() config.GcConfig {
	gc := collectNow()
	gc.CompactBelowPercent = config.Default().GC.CompactBelowPercent
	return gc
}

// sparse stores a 4 MiB object and a second whose first keepMiB MiB are the
// same bytes, so it reuses that much of the first one's xorb, then deletes
// the first and collects its blob. It returns the second object's content
// and blob, and the xorb it now uses only part of.
func (f *fixture) sparse(t *testing.T, nsID int64, keepMiB int) (data []byte, blob, xorb string) {
	t.Helper()
	ctx := t.Context()
	first := pseudoRandom("sparse", 4<<20)
	if _, err := f.store.Commit(ctx, nsID, "first", "application/octet-stream", mustStage(t, f, first)); err != nil {
		t.Fatal(err)
	}
	xorbs := f.xorbsOf(t, hashOf(string(first)))
	if len(xorbs) != 1 {
		t.Fatalf("setup: the first object uses %d xorbs, want 1", len(xorbs))
	}
	data = append(bytes.Clone(first[:keepMiB<<20]), pseudoRandom("second", 1<<20)...)
	second := mustStage(t, f, data)
	if _, err := f.store.Commit(ctx, nsID, "second", "application/octet-stream", second); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.xorbsOf(t, second.Hash), xorbs[0]) {
		t.Fatal("setup: the second object should reuse the first one's xorb")
	}
	if _, err := f.db.DeleteObject(ctx, nsID, "first"); err != nil {
		t.Fatal(err)
	}
	f.store.sweepBlobs(ctx)
	return data, second.Hash, xorbs[0]
}

// xorbBytes sums the stored size of every xorb row.
func (f *fixture) xorbBytes(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := f.pool.QueryRow(t.Context(), "SELECT COALESCE(SUM(size), 0)::BIGINT FROM xorbs").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A xorb most of whose chunks no blob uses any more is rewritten with only
// the ones still in use; the old one is collected, and the object reads back
// whole from the new one.
func TestCompactionRewritesASparseXorb(t *testing.T) {
	f := newFixture(t, compactNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	data, blob, old := f.sparse(t, nsID, 1)
	before := f.xorbBytes(t)

	f.store.compactXorbs(ctx)
	f.store.sweepXorbs(ctx)

	if slices.Contains(f.xorbsOf(t, blob), old) {
		t.Fatal("the object's terms still point at the sparse xorb")
	}
	if _, ok := f.xorbRefcount(t, old); ok {
		t.Error("the sparse xorb should have been collected once nothing used it")
	}
	if ok, _ := f.bucket.Exists(ctx, storage.XorbPath(old)); ok {
		t.Error("the sparse xorb's bytes should be gone")
	}
	if after := f.xorbBytes(t); after > before-2<<20 {
		t.Errorf("xorbs hold %d bytes after compaction, %d before; want about 3 MiB less", after, before)
	}
	if n := f.driftedXorbs(t); n != 0 {
		t.Errorf("%d xorbs have a refcount that disagrees with their terms", n)
	}
	if got, err := f.readRange(t, blob, 0, int64(len(data))); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back %d bytes, %v; want the %d stored", len(got), err, len(data))
	}

	// The moved chunks are found where they are now, and reused from there.
	again := mustStage(t, f, data[:1<<20])
	p, err := f.store.plan(ctx, again, f.namespace(t, "other", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.xorbs) > 1 || len(p.xorbs) == 1 && len(p.xorbs[0].chunks) > 2 {
		t.Errorf("planned %d new xorbs, want the moved chunks reused", len(p.xorbs))
	}
}

// A xorb whose chunks are mostly still in use is left as it is, and not
// looked at again until it loses another blob.
func TestCompactionLeavesADenseXorb(t *testing.T) {
	f := newFixture(t, compactNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	_, blob, old := f.sparse(t, nsID, 3)

	f.store.compactXorbs(ctx)

	if !slices.Contains(f.xorbsOf(t, blob), old) {
		t.Error("a xorb mostly in use should not have been compacted")
	}
	var marked bool
	if err := f.pool.QueryRow(ctx, "SELECT released_at IS NOT NULL FROM xorbs WHERE hash = $1", old).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if marked {
		t.Error("a xorb compaction has looked at should be unmarked")
	}
}

// A read that looked a blob's terms up before compaction moved them still
// gets its bytes once the old xorb is gone, from the chunks' new home.
func TestReadsOfMovedTermsFindTheChunksInTheirNewXorb(t *testing.T) {
	f := newFixture(t, compactNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	data, blob, old := f.sparse(t, nsID, 1)

	terms, err := f.db.BlobTerms(ctx, blob, 0, 1, 1)
	if err != nil || len(terms) != 1 || terms[0].Xorb != old {
		t.Fatalf("setup: first term %v (%v), want one on the sparse xorb", terms, err)
	}
	chunks, err := f.db.XorbChunks(ctx, old, terms[0].Start, terms[0].End)
	if err != nil {
		t.Fatal(err)
	}
	run := make([]span, len(chunks))
	for i, c := range chunks {
		run[i] = span{XorbChunk: c, lo: 0, hi: int64(c.Size)}
	}

	f.store.compactXorbs(ctx)
	f.store.sweepXorbs(ctx)
	if ok, _ := f.bucket.Exists(ctx, storage.XorbPath(old)); ok {
		t.Fatal("setup: the old xorb should be gone")
	}

	got := f.store.fetchRun(ctx, old, run)
	if got.err != nil {
		t.Fatalf("fetch from the collected xorb: %v", got.err)
	}
	if !bytes.Equal(got.data, data[:terms[0].Size]) {
		t.Error("the run read from the new xorb differs from what was stored")
	}
}

// overlap stores a short object made of a few chunks from the start of the
// sparse object's shared run, followed by bytes of its own: a run that short
// is stored again, so those chunks then have two copies. It returns the
// index, in the sparse xorb, of one of them.
func (f *fixture) overlap(t *testing.T, nsID int64, data []byte, old string) int32 {
	t.Helper()
	cut := chunkAll(data, len(data))
	short := append(bytes.Clone(data[cut[2].Pos:cut[5].Pos]), pseudoRandom("short", 256<<10)...)
	staged := mustStage(t, f, short)
	for i := range 3 {
		if staged.Chunks[i].Hash != cut[2+i].Hash {
			t.Fatalf("setup: chunk %d of the short object is not chunk %d of the sparse one", i, 2+i)
		}
	}
	if _, err := f.store.Commit(t.Context(), nsID, "short", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.xorbsOf(t, staged.Hash), old) {
		t.Fatal("setup: a run of 3 chunks should have been stored again")
	}
	found, err := f.db.LocateChunks(t.Context(), []string{cut[3].Hash})
	if err != nil {
		t.Fatal(err)
	}
	for _, loc := range found[cut[3].Hash] {
		if loc.Xorb == old {
			return loc.Index
		}
	}
	t.Fatal("setup: the chunk should be in the sparse xorb")
	return 0
}

// A chunk that rotted is read from another copy of it, and the xorb it rotted
// in is marked damaged; compaction then rewrites that xorb from the sound
// copy, and the result reads back whole on its own.
func TestDamageIsReadAroundThenRepairedByCompaction(t *testing.T) {
	f := newFixture(t, compactNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	data, blob, old := f.sparse(t, nsID, 1)
	idx := f.overlap(t, nsID, data, old)

	chunks, err := f.db.XorbChunks(ctx, old, idx, idx+1)
	if err != nil {
		t.Fatal(err)
	}
	f.rewriteXorb(t, old, func(b []byte) []byte {
		b[chunks[0].Offset+chunkHeaderLen+7] ^= 0x01
		return b
	})

	if got, err := f.readRange(t, blob, 0, int64(len(data))); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes, %v; want the rotted chunk served from its other copy", len(got), err)
	}
	if damaged, _ := f.damage(t, "xorbs", old); !damaged {
		t.Fatal("the read should have marked the xorb damaged")
	}

	f.store.compactXorbs(ctx)
	f.store.sweepXorbs(ctx)

	xorbs := f.xorbsOf(t, blob)
	if slices.Contains(xorbs, old) {
		t.Fatal("the damaged xorb should have been rewritten")
	}
	for _, x := range xorbs {
		if damaged, _ := f.damage(t, "xorbs", x); damaged {
			t.Errorf("xorb %s is still marked damaged", x)
		}
		why, err := f.store.checkXorb(ctx, &pacer{}, db.ScrubTarget{Hash: x, Size: f.xorbSize(t, x), Xorb: true})
		if err != nil || why != "" {
			t.Errorf("xorb %s fails its check: %q, %v", x, why, err)
		}
	}
	if got, err := f.readRange(t, blob, 0, int64(len(data))); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back %d bytes, %v; want the %d stored", len(got), err, len(data))
	}
}

// A damaged xorb whose damage has no sound copy elsewhere cannot be
// repaired; compaction leaves it, rather than copy the damage.
func TestCompactionDoesNotCopyDamage(t *testing.T) {
	f := newFixture(t, compactNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	_, blob, old := f.sparse(t, nsID, 1)
	chunks, err := f.db.XorbChunks(ctx, old, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	f.rewriteXorb(t, old, func(b []byte) []byte {
		b[chunks[0].Offset+chunkHeaderLen+7] ^= 0x01
		return b
	})
	if err := f.db.MarkXorbDamaged(ctx, old); err != nil {
		t.Fatal(err)
	}

	f.store.compactXorbs(ctx)

	if !slices.Contains(f.xorbsOf(t, blob), old) {
		t.Error("a xorb with damage that has no sound copy should be left as it is")
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != 2 {
		t.Errorf("%d xorbs stored, want the two the objects use and no partial rewrite", n)
	}
	var marked bool
	if err := f.pool.QueryRow(ctx, "SELECT released_at IS NOT NULL FROM xorbs WHERE hash = $1", old).Scan(&marked); err != nil {
		t.Fatal(err)
	}
	if marked {
		t.Error("an unrepairable xorb should wait for its next scrub, not be retried every tick")
	}
}

func (f *fixture) xorbSize(t *testing.T, hash string) int64 {
	t.Helper()
	var n int64
	if err := f.pool.QueryRow(t.Context(), "SELECT size FROM xorbs WHERE hash = $1", hash).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Uploads that reuse a xorb's chunks, and deletes that release them, race
// compaction moving them: no upload fails, no refcount drifts, and every
// object reads back whole.
func TestCompactionRacesUploadsAndDeletes(t *testing.T) {
	f := newFixture(t, compactNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	data, _, old := f.sparse(t, nsID, 1)

	const writers, rounds = 4, 6
	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds+rounds)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				key := fmt.Sprintf("w%d-%d", w, r)
				body := append(bytes.Clone(data[:1<<20]), pseudoRandom(key, 64<<10)...)
				staged, err := f.store.Stage(ctx, bytes.NewReader(body))
				if err == nil {
					_, err = f.store.Commit(ctx, nsID, key, "application/octet-stream", staged)
				}
				if err == nil && r%2 == 1 {
					_, err = f.db.DeleteObject(ctx, nsID, key)
				}
				if err != nil {
					errs <- fmt.Errorf("%s: %w", key, err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range rounds {
			f.store.sweepBlobs(ctx)
			if err := f.db.RequeueCompaction(ctx, old); err != nil {
				errs <- err
			}
			f.store.compactXorbs(ctx)
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	f.store.sweepBlobs(ctx)
	f.store.compactXorbs(ctx)
	if n := f.driftedXorbs(t); n != 0 {
		t.Errorf("%d xorbs have a refcount that disagrees with their terms", n)
	}
	if n := f.driftedBlobs(t); n != 0 {
		t.Errorf("%d blobs have a refcount that disagrees with their objects", n)
	}
	list, err := f.db.ListObjects(ctx, nsID, "", 0, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range list.Objects {
		obj, err := f.db.GetObject(ctx, nsID, o.Key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := f.readRange(t, obj.BlobHash, 0, obj.Size)
		if err != nil || int64(len(got)) != obj.Size || !bytes.Equal(got[:1<<20], data[:1<<20]) {
			t.Errorf("%s read back %d bytes, %v; want its %d", o.Key, len(got), err, obj.Size)
		}
	}
}
