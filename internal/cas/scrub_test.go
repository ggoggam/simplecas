package cas

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/storage"
)

// scrubNow is a GC config that scrubs everything not checked in the last
// day, as fast as it can be read.
func scrubNow() config.GcConfig {
	gc := defaultGC()
	gc.ScrubIntervalSecs = 86400
	return gc
}

// scrubAll marks every piece of stored content unchecked and scrubs until
// nothing is left due.
func (f *fixture) scrubAll(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	for _, table := range []string{"xorbs", "blobs"} {
		if _, err := f.pool.Exec(ctx, "UPDATE "+table+" SET verified_at = NULL"); err != nil {
			t.Fatal(err)
		}
	}
	p := &pacer{}
	for i := 0; f.store.scrubPass(ctx, p) > 0; i++ {
		if i > 100 {
			t.Fatal("scrub never ran out of content to check")
		}
	}
}

// damage reads whether a row of table is marked damaged, and whether it has
// been checked at all.
func (f *fixture) damage(t *testing.T, table, hash string) (damaged, verified bool) {
	t.Helper()
	err := f.pool.QueryRow(t.Context(),
		"SELECT damaged_at IS NOT NULL, verified_at IS NOT NULL FROM "+table+" WHERE hash = $1", hash).
		Scan(&damaged, &verified)
	if err != nil {
		t.Fatal(err)
	}
	return damaged, verified
}

// Sound content passes its check, and the check is recorded.
func TestScrubPassesSoundContent(t *testing.T) {
	f := newFixture(t, scrubNow())
	nsID := f.namespace(t, "ns", nil)
	staged := mustStage(t, f, pseudoRandom("sound", 1<<20))
	if _, err := f.store.Commit(t.Context(), nsID, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	whole := f.putWholeFile(t, nsID, "old", "stored whole")

	f.scrubAll(t)

	xorb, _ := f.storedChunks(t, staged.Hash)
	for _, row := range []struct{ table, hash string }{{"xorbs", xorb}, {"blobs", whole}} {
		if damaged, verified := f.damage(t, row.table, row.hash); damaged || !verified {
			t.Errorf("%s %s: damaged=%v verified=%v, want checked and sound", row.table, row.hash, damaged, verified)
		}
	}
}

// A chunk that rots is found by the scrub, without anyone reading it; the
// xorb is marked damaged until a check finds it sound again.
func TestScrubFindsAChunkThatRotted(t *testing.T) {
	f := newFixture(t, scrubNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	staged := mustStage(t, f, pseudoRandom("rots", 1<<20))
	if _, err := f.store.Commit(ctx, nsID, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	xorb, stored := f.storedChunks(t, staged.Hash)
	pristine, err := f.bucket.ReadAll(ctx, storage.XorbPath(xorb))
	if err != nil {
		t.Fatal(err)
	}
	f.rewriteXorb(t, xorb, func(b []byte) []byte {
		b[stored[3].Offset+chunkHeaderLen+100] ^= 0x01
		return b
	})

	f.scrubAll(t)
	if damaged, _ := f.damage(t, "xorbs", xorb); !damaged {
		t.Fatal("the scrub should have marked the xorb damaged")
	}
	dmg, err := f.db.CountDamage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dmg.Xorbs != 1 || dmg.Objects != 1 {
		t.Errorf("damage = %+v, want the one xorb and the one object", dmg)
	}

	// Restored, say from a backup: the next check clears the mark.
	f.rewriteXorb(t, xorb, func([]byte) []byte { return pristine })
	f.scrubAll(t)
	if damaged, _ := f.damage(t, "xorbs", xorb); damaged {
		t.Error("a xorb found sound again should no longer be marked damaged")
	}
}

// Bytes missing from the backend under a live row are damage too.
func TestScrubFindsMissingBytes(t *testing.T) {
	f := newFixture(t, scrubNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	if _, err := f.store.Commit(ctx, nsID, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	whole := f.putWholeFile(t, nsID, "old", "stored whole")
	for _, key := range []string{storage.XorbPath(xorbABC), storage.BlobPath(whole)} {
		if err := f.bucket.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
	}

	f.scrubAll(t)

	for _, row := range []struct{ table, hash string }{{"xorbs", xorbABC}, {"blobs", whole}} {
		if damaged, _ := f.damage(t, row.table, row.hash); !damaged {
			t.Errorf("%s with no bytes should be marked damaged", row.table)
		}
	}
}

// A whole-file blob found damaged is repaired by uploading its content
// again: the commit rewrites it from the staged copy.
func TestReuploadRepairsADamagedWholeFileBlob(t *testing.T) {
	f := newFixture(t, scrubNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	whole := f.putWholeFile(t, nsID, "old", "stored whole")
	f.writeBlob(t, whole, "stored wholX")

	f.scrubAll(t)
	if damaged, _ := f.damage(t, "blobs", whole); !damaged {
		t.Fatal("the scrub should have marked the blob damaged")
	}

	if _, err := f.store.Commit(ctx, nsID, "again", "text/plain", f.stage(t, "stored whole")); err != nil {
		t.Fatal(err)
	}
	if damaged, _ := f.damage(t, "blobs", whole); damaged {
		t.Error("the re-upload should have repaired the blob")
	}
	if got, err := f.readRange(t, whole, 0, 12); err != nil || string(got) != "stored whole" {
		t.Errorf("read %q, %v; want the repaired bytes", got, err)
	}
}

// A check that cannot be made, here because the scrub is stopping, is not
// recorded either way, and the content stays due.
func TestScrubGivesBackWhatItCouldNotCheck(t *testing.T) {
	f := newFixture(t, scrubNow())
	nsID := f.namespace(t, "ns", nil)
	if _, err := f.store.Commit(t.Context(), nsID, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), "UPDATE xorbs SET verified_at = NULL"); err != nil {
		t.Fatal(err)
	}
	due, err := f.db.ClaimScrub(t.Context(), 86400, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("claimed %v (%v), want the one xorb", due, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	f.store.scrub(ctx, &pacer{}, due[0])

	if damaged, verified := f.damage(t, "xorbs", xorbABC); damaged || verified {
		t.Errorf("damaged=%v verified=%v, want it unmarked and never checked, as before the claim", damaged, verified)
	}
}

func TestRunScrubIsOffAtAZeroInterval(t *testing.T) {
	f := newFixture(t, defaultGC())
	done := make(chan struct{})
	go func() {
		f.store.RunScrub(t.Context())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunScrub should return at once when scrubbing is off")
	}
}

func TestPacerHoldsReadsToItsRate(t *testing.T) {
	p := &pacer{rate: 1000}
	start := time.Now()
	for range 3 {
		if err := p.wait(t.Context(), 100); err != nil {
			t.Fatal(err)
		}
	}
	// The first read starts at once; the next two wait 100 ms each.
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("three reads of 100 bytes at 1000 B/s took %v, want about 200ms", elapsed)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := p.wait(ctx, 1000); err == nil {
		t.Error("a wait past a cancelled context should fail")
	}

	r := &pacedReader{ctx: t.Context(), r: bytes.NewReader(make([]byte, 3*pacedBlock)), p: &pacer{}}
	if n, _ := r.Read(make([]byte, 2*pacedBlock)); n != pacedBlock {
		t.Errorf("read %d bytes at once, want at most %d", n, pacedBlock)
	}
}
