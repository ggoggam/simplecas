package db

import (
	"context"
	"errors"
	"testing"

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

	one, err := d.CreateTenant(ctx, "one", "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	two, err := d.CreateTenant(ctx, "two", "b@example.com")
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

	// The dedup link path claims it back before GC runs.
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		_, ok, err := ClaimExistingBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if !ok {
			t.Fatal("expected the blob to still be claimable")
		}
		return nil
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
