package cas

import (
	"context"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/storage"
)

// collectNow is a GC config with no grace at all, so a sweep in a test sees
// everything the moment it is written.
func collectNow() config.GcConfig {
	return config.GcConfig{IntervalSecs: 60, GraceSecs: 0, MultipartExpirySecs: 0}
}

func TestSweepBlobsCollectsAndKeeps(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if _, err := f.store.Commit(ctx, nsID, "gone", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "kept", "text/plain", f.stage(t, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DeleteObject(ctx, nsID, "gone"); err != nil {
		t.Fatal(err)
	}

	f.store.sweepBlobs(ctx)

	// The unreferenced blob loses both its row and its bytes.
	if _, ok := f.refcount(t, hashABC); ok {
		t.Error("the unreferenced blob's row should be gone")
	}
	if ok, _ := f.bucket.Exists(ctx, storage.BlobPath(hashABC)); ok {
		t.Error("the unreferenced blob's bytes should be gone")
	}
	// The referenced one is untouched.
	if n, _ := f.refcount(t, hashEmpty); n != 1 {
		t.Errorf("referenced blob refcount = %d, want 1", n)
	}
	if ok, _ := f.bucket.Exists(ctx, storage.BlobPath(hashEmpty)); !ok {
		t.Error("a referenced blob's bytes must survive the sweep")
	}
}

// Bytes already missing must not wedge the sweep: the row still has to go, or
// the blob would be retried forever.
func TestSweepBlobsToleratesMissingBytes(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if _, err := f.store.Commit(ctx, nsID, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}
	// Something else removed the bytes out from under us.
	if err := f.bucket.Delete(ctx, storage.BlobPath(hashABC)); err != nil {
		t.Fatal(err)
	}

	f.store.sweepBlobs(ctx)

	if _, ok := f.refcount(t, hashABC); ok {
		t.Error("the row must be collected even when the bytes were already gone")
	}
}

func TestSweepStagingRemovesOrphansAndSparesLiveParts(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	// An orphan: staged, then never committed.
	orphan := f.stage(t, "orphaned bytes")

	// A live multipart part, which the sweeper must leave alone however old it
	// looks — only the multipart expiry sweep may reclaim it.
	uploadID, err := f.db.CreateMultipart(ctx, nsID, "slow", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	part := f.stage(t, "part bytes")
	if _, err := f.db.PutPart(ctx, uploadID, 1, part.StagingKey, part.Size, part.Hash, 0); err != nil {
		t.Fatal(err)
	}

	f.store.sweepStaging(ctx)

	if ok, _ := f.bucket.Exists(ctx, orphan.StagingKey); ok {
		t.Error("an orphaned staging file should have been collected")
	}
	if ok, _ := f.bucket.Exists(ctx, part.StagingKey); !ok {
		t.Error("a staging file still referenced by a live part must be spared")
	}
}

// A staging file inside the grace period is left alone, so a commit racing the
// sweeper cannot lose its bytes.
func TestSweepStagingHonoursTheGracePeriod(t *testing.T) {
	f := newFixture(t, config.GcConfig{IntervalSecs: 60, GraceSecs: 3600, MultipartExpirySecs: 86400})
	ctx := t.Context()

	fresh := f.stage(t, "just written")
	f.store.sweepStaging(ctx)

	if ok, _ := f.bucket.Exists(ctx, fresh.StagingKey); !ok {
		t.Error("a staging file inside the grace period must not be collected")
	}
}

func TestSweepMultipartReclaimsAbandonedParts(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	uploadID, err := f.db.CreateMultipart(ctx, nsID, "abandoned", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	part := f.stage(t, "abandoned part")
	if _, err := f.db.PutPart(ctx, uploadID, 1, part.StagingKey, part.Size, part.Hash, 0); err != nil {
		t.Fatal(err)
	}

	// With a zero expiry the upload is stale immediately.
	f.store.sweepMultipart(ctx)

	if _, err := f.db.GetMultipart(ctx, nsID, "abandoned", uploadID); err == nil {
		t.Error("the abandoned upload record should be gone")
	}
	if ok, _ := f.bucket.Exists(ctx, part.StagingKey); ok {
		t.Error("the abandoned upload's part bytes should be reclaimed")
	}
}

// The sweeps run in sequence, and each has to survive the others' leftovers.
func TestRunGCStopsOnContextCancel(t *testing.T) {
	f := newFixture(t, config.GcConfig{IntervalSecs: 1, GraceSecs: 0, MultipartExpirySecs: 0})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		f.store.RunGC(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunGC did not return after its context was cancelled")
	}
}

// A full pass with nothing to do must be quiet and harmless.
func TestGCPassOnAnEmptyStore(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()

	f.store.sweepBlobs(ctx)
	f.store.sweepStaging(ctx)
	f.store.sweepMultipart(ctx)

	if n := f.countUnder(t, ""); n != 0 {
		t.Errorf("an empty store gained %d objects during a GC pass", n)
	}
}
