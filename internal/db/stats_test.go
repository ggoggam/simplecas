package db

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestStats(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	a := mustNamespace(t, d, "ns-a", nil)
	b := mustNamespace(t, d, "ns-b", nil)

	shared := hashOf("shared")
	unique := hashOf("unique")
	// Two objects share one blob; a third has its own.
	putObject(t, d, a, "one", shared, 1000)
	putObject(t, d, b, "two", shared, 1000)
	putObject(t, d, a, "three", unique, 500)

	s, err := d.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.NamespaceCount != 2 {
		t.Errorf("namespace_count = %d, want 2", s.NamespaceCount)
	}
	if s.ObjectCount != 3 {
		t.Errorf("object_count = %d, want 3", s.ObjectCount)
	}
	if s.LogicalBytes != 2500 {
		t.Errorf("logical_bytes = %d, want 2500 (the sum over objects)", s.LogicalBytes)
	}
	// Dedup: two blobs are physically stored, not three objects' worth.
	if s.BlobCount != 2 {
		t.Errorf("blob_count = %d, want 2", s.BlobCount)
	}
	if s.PhysicalBytes != 1500 {
		t.Errorf("physical_bytes = %d, want 1500", s.PhysicalBytes)
	}
}

// A blob at refcount 0 is awaiting collection and must not be billed as stored.
func TestStatsExcludesUnreferencedBlobs(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("orphan")

	putObject(t, d, nsID, "k", hash, 700)
	if _, err := d.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}

	s, err := d.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.BlobCount != 0 || s.PhysicalBytes != 0 {
		t.Errorf("blob_count=%d physical_bytes=%d, want both 0", s.BlobCount, s.PhysicalBytes)
	}
}

// Under global dedup a shared blob counts toward each tenant's footprint, so
// the per-tenant figures can sum to more than the global one.
func TestStatsForTenants(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	one, err := d.CreateTenant(ctx, "one", mustUser(t, d, "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := d.CreateTenant(ctx, "two", mustUser(t, d, "b@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	nsOne := mustNamespace(t, d, "ns-one", &one)
	nsTwo := mustNamespace(t, d, "ns-two", &two)
	mustNamespace(t, d, "ns-unowned", nil)

	shared := hashOf("shared")
	putObject(t, d, nsOne, "a", shared, 1000)
	putObject(t, d, nsTwo, "b", shared, 1000)
	putObject(t, d, nsOne, "c", hashOf("only-one"), 200)

	s, err := d.StatsForTenants(ctx, []int64{one})
	if err != nil {
		t.Fatal(err)
	}
	if s.NamespaceCount != 1 {
		t.Errorf("namespace_count = %d, want 1 — the unowned namespace must not count", s.NamespaceCount)
	}
	if s.ObjectCount != 2 || s.LogicalBytes != 1200 {
		t.Errorf("objects=%d logical=%d, want 2 and 1200", s.ObjectCount, s.LogicalBytes)
	}
	// The shared blob is attributed to this tenant too, and counted once.
	if s.BlobCount != 2 || s.PhysicalBytes != 1200 {
		t.Errorf("blobs=%d physical=%d, want 2 and 1200", s.BlobCount, s.PhysicalBytes)
	}

	other, err := d.StatsForTenants(ctx, []int64{two})
	if err != nil {
		t.Fatal(err)
	}
	if other.PhysicalBytes != 1000 {
		t.Errorf("tenant two physical = %d, want 1000", other.PhysicalBytes)
	}

	// Summing the tenants exceeds the global figure — that is the documented
	// meaning of the per-tenant number, not a bug.
	global, err := d.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.PhysicalBytes+other.PhysicalBytes <= global.PhysicalBytes {
		t.Errorf("expected per-tenant footprints to overlap; per-tenant sum=%d global=%d",
			s.PhysicalBytes+other.PhysicalBytes, global.PhysicalBytes)
	}

	// A caller in no tenant sees nothing at all.
	none, err := d.StatsForTenants(ctx, []int64{})
	if err != nil {
		t.Fatal(err)
	}
	if none != (Stats{}) {
		t.Errorf("a caller with no tenants saw %+v, want zero", none)
	}
}

// ---------------------------------------------------------------------------
// Garbage collection
// ---------------------------------------------------------------------------

// stale backdates a blob's updated_at so it falls outside the grace period.
func stale(t *testing.T, d *DB, hash string, seconds int) {
	t.Helper()
	_, err := d.pool.Exec(t.Context(),
		"UPDATE blobs SET updated_at = now() - make_interval(secs => $2) WHERE hash = $1",
		hash, float64(seconds))
	if err != nil {
		t.Fatal(err)
	}
}

func TestGCSweepCollectsUnreferencedBlobs(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	dropped := hashOf("dropped")
	kept := hashOf("kept")
	putObject(t, d, nsID, "gone", dropped, 10)
	putObject(t, d, nsID, "here", kept, 10)
	wholeFile(t, d, dropped)
	if _, err := d.DeleteObject(ctx, nsID, "gone"); err != nil {
		t.Fatal(err)
	}
	stale(t, d, dropped, 7200)

	var deleted []string
	n, err := d.GCSweep(ctx, 3600, 100, func(_ context.Context, hash string) error {
		deleted = append(deleted, hash)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("swept %d blobs, want 1", n)
	}
	if len(deleted) != 1 || deleted[0] != dropped {
		t.Errorf("deleted bytes for %v, want [%s]", deleted, dropped)
	}
	if _, ok := refcount(t, d, dropped); ok {
		t.Error("the swept blob's row should be gone")
	}
	// A referenced blob is untouchable regardless of age.
	if _, ok := refcount(t, d, kept); !ok {
		t.Error("a referenced blob must survive the sweep")
	}
}

// The grace period is what lets a blob be re-referenced (an overwrite, a
// dedup link) before its bytes are discarded.
func TestGCSweepHonoursTheGracePeriod(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("recent")

	putObject(t, d, nsID, "k", hash, 10)
	if _, err := d.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}

	n, err := d.GCSweep(ctx, 3600, 100, func(context.Context, string) error {
		t.Error("nothing should be deleted inside the grace period")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("swept %d blobs, want 0", n)
	}
	if _, ok := refcount(t, d, hash); !ok {
		t.Error("the blob row should still be there")
	}
}

// A blob re-referenced before the sweep gets a fresh refcount, so the sweep
// must skip it even though it was once at zero.
func TestGCSweepSkipsRelinkedBlobs(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("relinked")

	putObject(t, d, nsID, "k", hash, 10)
	if _, err := d.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}
	stale(t, d, hash, 7200)

	// A re-upload of the same content claims it back before GC runs.
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		_, err := ClaimBlob(ctx, tx, hash, 10, "")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := d.GCSweep(ctx, 3600, 100, func(context.Context, string) error {
		t.Error("a re-referenced blob must not be collected")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("swept %d blobs, want 0", n)
	}
}

// If the bytes cannot be deleted, the metadata row has to stay so the blob is
// retried — dropping the row would leave the bytes stranded forever.
func TestGCSweepKeepsTheRowWhenByteDeletionFails(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("stuck")

	putObject(t, d, nsID, "k", hash, 10)
	wholeFile(t, d, hash)
	if _, err := d.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}
	stale(t, d, hash, 7200)

	boom := errors.New("backend unavailable")
	n, err := d.GCSweep(ctx, 3600, 100, func(context.Context, string) error {
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the backend failure surfaced", err)
	}
	if n != 0 {
		t.Errorf("swept %d, want 0", n)
	}
	if _, ok := refcount(t, d, hash); !ok {
		t.Error("the row must survive so the blob is retried next pass")
	}
}

func TestGCSweepRespectsTheLimit(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	for _, seed := range []string{"g1", "g2", "g3", "g4"} {
		h := hashOf(seed)
		putObject(t, d, nsID, seed, h, 10)
		if _, err := d.DeleteObject(ctx, nsID, seed); err != nil {
			t.Fatal(err)
		}
		stale(t, d, h, 7200)
	}

	n, err := d.GCSweep(ctx, 3600, 2, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("swept %d, want the limit of 2", n)
	}

	// The rest are picked up on the next pass.
	n, err = d.GCSweep(ctx, 3600, 100, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("second pass swept %d, want the remaining 2", n)
	}
}

// sweepAll runs a pass with no grace period, recording whose bytes it deleted.
func sweepAll(t *testing.T, d *DB, deleteBytes func(hash string) error) (int64, []string, error) {
	t.Helper()
	var deleted []string
	n, err := d.GCSweep(t.Context(), 0, 100, func(_ context.Context, hash string) error {
		deleted = append(deleted, hash)
		return deleteBytes(hash)
	})
	return n, deleted, err
}

// The refcount is a cache of how many objects point at a blob. If it drifts low,
// the sweep must believe the objects table: deleting the bytes would lose live
// data, and the row delete would only fail on the foreign key afterwards. The
// drifted blob must not stall the pass either — a genuinely unreferenced blob
// in the same pass is still reclaimed.
func TestGCSweepIgnoresADriftedRefcount(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	drifted := hashOf("drifted")
	garbage := hashOf("garbage")
	putObject(t, d, nsID, "live", drifted, 10)
	putObject(t, d, nsID, "gone", garbage, 10)
	wholeFile(t, d, drifted)
	wholeFile(t, d, garbage)
	if _, err := d.DeleteObject(ctx, nsID, "gone"); err != nil {
		t.Fatal(err)
	}
	// The drift: "live" still points at the blob, but its count says nobody does.
	if _, err := d.pool.Exec(ctx, "UPDATE blobs SET refcount = 0 WHERE hash = $1", drifted); err != nil {
		t.Fatal(err)
	}
	// Make the drifted blob the oldest candidate, so a sweep that picked it
	// would hit it first.
	stale(t, d, drifted, 7200)
	stale(t, d, garbage, 3600)

	n, deleted, err := sweepAll(t, d, func(string) error { return nil })
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Errorf("swept %d blobs, want 1", n)
	}
	if len(deleted) != 1 || deleted[0] != garbage {
		t.Errorf("deleted bytes for %v, want only [%s]", deleted, garbage)
	}
	if _, ok := refcount(t, d, drifted); !ok {
		t.Error("a blob an object still references must survive, whatever its refcount says")
	}
	if _, ok := refcount(t, d, garbage); ok {
		t.Error("the unreferenced blob should have been collected in the same pass")
	}
}

// One blob that cannot be deleted must not stall the pass: it is skipped for
// the rest of the pass and kept for the next, and the others are still swept.
func TestGCSweepCarriesOnPastAFailingBlob(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	bad := hashOf("bad")
	good := []string{hashOf("good1"), hashOf("good2")}
	for i, h := range append([]string{bad}, good...) {
		putObject(t, d, nsID, h, h, 10)
		wholeFile(t, d, h)
		if _, err := d.DeleteObject(ctx, nsID, h); err != nil {
			t.Fatal(err)
		}
		// The bad blob is the oldest, so it is the first candidate taken.
		stale(t, d, h, 7200-i)
	}

	boom := errors.New("backend refused")
	var badAttempts int
	n, deleted, err := sweepAll(t, d, func(hash string) error {
		if hash == bad {
			badAttempts++
			return boom
		}
		return nil
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the per-blob failure reported", err)
	}
	if n != 2 {
		t.Errorf("swept %d blobs, want the 2 that could be deleted", n)
	}
	if badAttempts != 1 {
		t.Errorf("the failing blob was attempted %d times in one pass, want 1", badAttempts)
	}
	if len(deleted) != 3 {
		t.Errorf("deleteBytes ran for %v, want each blob once", deleted)
	}
	if _, ok := refcount(t, d, bad); !ok {
		t.Error("the failing blob's row must survive so it is retried next pass")
	}
	for _, h := range good {
		if _, ok := refcount(t, d, h); ok {
			t.Errorf("blob %s should have been collected despite the earlier failure", h)
		}
	}

	// Next pass the backend recovers and the straggler goes too.
	n, _, err = sweepAll(t, d, func(string) error { return nil })
	if err != nil || n != 1 {
		t.Errorf("retry pass swept %d (err %v), want 1", n, err)
	}
}

func TestUnknownBlobsSetsAsideTheOnesWithRows(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	known, unreferenced, unknown := hashOf("known"), hashOf("unreferenced"), hashOf("unknown")
	putObject(t, d, nsID, "k", known, 10)
	putObject(t, d, nsID, "gone", unreferenced, 10)
	if _, err := d.DeleteObject(ctx, nsID, "gone"); err != nil {
		t.Fatal(err)
	}

	got, err := d.UnknownBlobs(ctx, []string{known, unreferenced, unknown})
	if err != nil {
		t.Fatal(err)
	}
	// A row at refcount 0 is still the table's to manage: GCSweep takes it.
	if !slices.Equal(got, []string{unknown}) {
		t.Errorf("unknown = %v, want [%s]", got, unknown)
	}
}

func TestReclaimOrphanBlobDeletesBytesWithNoRow(t *testing.T) {
	d := testDB(t)
	hash := hashOf("orphan")

	var deleted []string
	reclaimed, err := d.ReclaimOrphanBlob(t.Context(), hash, func(_ context.Context, h string) error {
		deleted = append(deleted, h)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reclaimed || !slices.Equal(deleted, []string{hash}) {
		t.Errorf("reclaimed = %v, deleted %v; want the orphan's bytes deleted", reclaimed, deleted)
	}
	// The row that held the claim is never committed.
	if _, ok := refcount(t, d, hash); ok {
		t.Error("reclaiming an orphan must not leave a blob row behind")
	}
}

func TestReclaimOrphanBlobLeavesBlobsWithRowsAlone(t *testing.T) {
	d := testDB(t)
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("committed")
	putObject(t, d, nsID, "k", hash, 10)

	reclaimed, err := d.ReclaimOrphanBlob(t.Context(), hash, func(context.Context, string) error {
		t.Error("the bytes of a blob with a row must not be deleted")
		return nil
	})
	if err != nil || reclaimed {
		t.Errorf("reclaimed = %v, err = %v; want neither", reclaimed, err)
	}
}

func TestReclaimOrphanBlobKeepsAFailedDeleteForNextPass(t *testing.T) {
	d := testDB(t)
	boom := errors.New("backend unavailable")

	reclaimed, err := d.ReclaimOrphanBlob(t.Context(), hashOf("stuck"), func(context.Context, string) error {
		return boom
	})
	if !errors.Is(err, boom) || reclaimed {
		t.Errorf("reclaimed = %v, err = %v; want the backend failure surfaced", reclaimed, err)
	}
}

// openClaim starts a commit that has claimed hash and copied its bytes but not
// yet committed, which is exactly what an orphan looks like from outside. The
// claim's transaction stays open until end is called with commit or rollback.
func openClaim(t *testing.T, d *DB, hash string) (end func(commit bool)) {
	t.Helper()
	ctx := t.Context()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimBlob(ctx, tx, hash, 10, ""); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	ended := false
	t.Cleanup(func() {
		if !ended {
			_ = tx.Rollback(ctx)
		}
	})
	return func(commit bool) {
		ended = true
		if commit {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			return
		}
		_ = tx.Rollback(ctx)
	}
}

// withOrphanLockTimeout shortens how long the sweep waits on a claim, so a
// test that has to see it give up does not take seconds.
func withOrphanLockTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	prev := OrphanLockTimeout
	OrphanLockTimeout = timeout
	t.Cleanup(func() { OrphanLockTimeout = prev })
}

// The case the claim exists for: a commit that has copied its bytes but not
// committed must not lose them to the sweep.
func TestReclaimOrphanBlobSkipsAClaimInFlight(t *testing.T) {
	d := testDB(t)
	withOrphanLockTimeout(t, 200*time.Millisecond)
	hash := hashOf("in flight")

	end := openClaim(t, d, hash)
	reclaimed, err := d.ReclaimOrphanBlob(t.Context(), hash, func(context.Context, string) error {
		t.Error("the bytes of an uncommitted claim must not be deleted")
		return nil
	})
	if err != nil || reclaimed {
		t.Errorf("reclaimed = %v, err = %v; want the blob skipped for this pass", reclaimed, err)
	}

	end(true)
	if n, ok := refcount(t, d, hash); !ok || n != 1 {
		t.Errorf("refcount = %d (row %v), want the claim committed at 1", n, ok)
	}
}

// A claim that commits while the sweep waits on it wins: the sweep then finds
// the row and leaves the bytes alone.
func TestReclaimOrphanBlobDefersToAClaimThatCommits(t *testing.T) {
	d := testDB(t)
	hash := hashOf("commits")

	end := openClaim(t, d, hash)
	result := make(chan bool)
	go func() {
		reclaimed, _ := d.ReclaimOrphanBlob(t.Context(), hash, func(context.Context, string) error {
			return errors.New("the bytes of a committed claim must not be deleted")
		})
		result <- reclaimed
	}()

	time.Sleep(100 * time.Millisecond)
	end(true)
	if <-result {
		t.Error("the sweep reclaimed a blob whose claim committed")
	}
}

// A claim that rolls back while the sweep waits on it leaves real orphans, and
// the sweep goes on to reclaim them.
func TestReclaimOrphanBlobReclaimsAfterAClaimRollsBack(t *testing.T) {
	d := testDB(t)
	hash := hashOf("rolls back")

	end := openClaim(t, d, hash)
	result := make(chan bool)
	go func() {
		reclaimed, err := d.ReclaimOrphanBlob(t.Context(), hash, func(context.Context, string) error { return nil })
		if err != nil {
			t.Error(err)
		}
		result <- reclaimed
	}()

	time.Sleep(100 * time.Millisecond)
	end(false)
	if !<-result {
		t.Error("the bytes a rolled-back claim left behind should be reclaimed")
	}
}

// A claim that arrives while the sweep is deleting waits for it, and then sees
// a fresh row, so it rewrites the bytes the sweep just took.
func TestReclaimOrphanBlobHoldsOffANewClaim(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	hash := hashOf("raced")

	type claim struct {
		needsBytes bool
		err        error
	}
	claimed := make(chan claim, 1)
	var (
		c     claim
		early bool
	)
	reclaimed, err := d.ReclaimOrphanBlob(ctx, hash, func(context.Context, string) error {
		go func() {
			var c claim
			c.err = d.InTx(ctx, func(tx pgx.Tx) error {
				claim, err := ClaimBlob(ctx, tx, hash, 10, "")
				c.needsBytes = claim.NeedsBytes()
				return err
			})
			claimed <- c
		}()
		select {
		case c = <-claimed:
			early = true
		case <-time.After(200 * time.Millisecond):
		}
		return nil
	})
	if early {
		t.Fatal("a claim went through while the sweep was deleting the bytes")
	}
	if err != nil || !reclaimed {
		t.Fatalf("reclaimed = %v, err = %v; want the orphan reclaimed", reclaimed, err)
	}

	c = <-claimed
	if c.err != nil {
		t.Fatal(c.err)
	}
	if !c.needsBytes {
		t.Error("a claim after the delete must be told to write the bytes again")
	}
}
