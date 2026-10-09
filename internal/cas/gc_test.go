package cas

import (
	"context"
	"testing"
	"time"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
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

func TestSweepSessionsRemovesExpiredOnes(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	user, err := f.db.ResolveUser(ctx, "https://idp.test", "sub-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for i, expires := range []time.Time{time.Now().Add(-time.Minute), time.Now().Add(time.Hour)} {
		_, err := f.db.CreateSession(ctx, db.NewSession{
			TokenHash: []byte{byte(i)}, UserID: user.ID, ExpiresAt: expires,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	f.store.sweepSessions(ctx)

	var total, live int
	err = f.pool.QueryRow(ctx,
		"SELECT count(*), count(*) FILTER (WHERE expires_at > now()) FROM sessions").Scan(&total, &live)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || live != 1 {
		t.Errorf("%d sessions left (%d live), want only the live one", total, live)
	}
}

// writeBlob puts bytes at hash's blob path directly, the way a commit that
// copied them into place and then failed to commit leaves them.
func (f *fixture) writeBlob(t *testing.T, hash, content string) {
	t.Helper()
	if err := f.bucket.WriteAll(t.Context(), storage.BlobPath(hash), []byte(content), nil); err != nil {
		t.Fatal(err)
	}
}

func TestSweepOrphanBlobsReclaimsBytesWithNoRow(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	// The orphan: bytes in place, no row.
	f.writeBlob(t, hashABC, "abc")
	// A live blob, and one at refcount 0 that GCSweep has not taken yet. Both
	// have rows, so neither is the orphan sweep's business.
	if _, err := f.store.Commit(ctx, nsID, "kept", "text/plain", f.stage(t, "")); err != nil {
		t.Fatal(err)
	}
	unreferenced := f.stage(t, "unreferenced")
	if _, err := f.store.Commit(ctx, nsID, "gone", "text/plain", unreferenced); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DeleteObject(ctx, nsID, "gone"); err != nil {
		t.Fatal(err)
	}
	// Something under blobs/ that is not a blob at all.
	if err := f.bucket.WriteAll(ctx, "blobs/README", []byte("not a blob"), nil); err != nil {
		t.Fatal(err)
	}

	f.store.sweepOrphanBlobs(ctx)

	if ok, _ := f.bucket.Exists(ctx, storage.BlobPath(hashABC)); ok {
		t.Error("bytes no row accounts for should have been reclaimed")
	}
	for _, key := range []string{storage.BlobPath(hashEmpty), storage.BlobPath(unreferenced.Hash), "blobs/README"} {
		if ok, _ := f.bucket.Exists(ctx, key); !ok {
			t.Errorf("%s must survive the orphan sweep", key)
		}
	}
	if _, ok := f.refcount(t, hashABC); ok {
		t.Error("the orphan sweep must not leave a blob row behind")
	}
}

// Fresh bytes with no row are most likely a commit about to succeed; the grace
// period spares them the lock.
func TestSweepOrphanBlobsHonoursTheGracePeriod(t *testing.T) {
	f := newFixture(t, config.GcConfig{IntervalSecs: 60, GraceSecs: 3600, MultipartExpirySecs: 86400})
	ctx := t.Context()

	f.writeBlob(t, hashABC, "abc")
	f.store.sweepOrphanBlobs(ctx)

	if ok, _ := f.bucket.Exists(ctx, storage.BlobPath(hashABC)); !ok {
		t.Error("bytes inside the grace period must not be reclaimed")
	}
}

// Once an orphan is reclaimed, the same content uploaded again must come back
// whole: the claim sees no row and writes the bytes afresh.
func TestReuploadAfterOrphanSweepRewritesTheBytes(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	f.writeBlob(t, hashABC, "abc")
	f.store.sweepOrphanBlobs(ctx)

	if _, err := f.store.Commit(ctx, nsID, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	got, err := f.bucket.ReadAll(ctx, storage.BlobPath(hashABC))
	if err != nil || string(got) != "abc" {
		t.Errorf("blob bytes = %q, %v; want the re-upload's bytes in place", got, err)
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
	f.store.sweepSessions(ctx)
	f.store.sweepOrphanBlobs(ctx)

	if n := f.countUnder(t, ""); n != 0 {
		t.Errorf("an empty store gained %d objects during a GC pass", n)
	}
}
