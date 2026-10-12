package cas

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

func limitsWith(fn func(*config.LimitsConfig)) config.LimitsConfig {
	limits := config.Default().Limits
	fn(&limits)
	return limits
}

func isKind(err error, kind apperr.Kind) bool {
	var e *apperr.Error
	return errors.As(err, &e) && e.Kind == kind
}

// usage sums what a team is charged for, straight from the rows.
func (f *fixture) usage(t *testing.T, tenantID int64) int64 {
	t.Helper()
	var n int64
	err := f.pool.QueryRow(t.Context(), `
		SELECT COALESCE(SUM(o.size), 0) FROM objects o
		JOIN namespaces n ON n.id = o.namespace_id WHERE n.tenant_id = $1`, tenantID).Scan(&n)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	return n
}

func (f *fixture) tenant(t *testing.T, name string) int64 {
	t.Helper()
	owner, err := f.db.ResolveUser(t.Context(), "https://issuer.test", name, name+"@example.com", "")
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}
	id, err := f.db.CreateTenant(t.Context(), name, owner.ID)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return id
}

func (f *fixture) multipart(t *testing.T, nsID int64, key string) db.MultipartUpload {
	t.Helper()
	id, err := f.db.CreateMultipart(t.Context(), nsID, key, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := f.db.GetMultipart(t.Context(), nsID, key, id)
	if err != nil {
		t.Fatal(err)
	}
	return upload
}

// unreadable fails the test if anything reads it: a body declared over a limit
// must be refused without being read.
type unreadable struct{ t *testing.T }

func (u unreadable) Read([]byte) (int, error) {
	u.t.Error("the body was read although its declared size was already refused")
	return 0, errors.New("unreadable")
}

// ---------------------------------------------------------------------------
// Size limits
// ---------------------------------------------------------------------------

func TestPutEnforcesTheObjectSizeLimit(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.MaxObjectBytes = 4 }))
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if _, size, err := f.store.Put(ctx, nsID, "fits", "text/plain", strings.NewReader("abcd"), -1); err != nil || size != 4 {
		t.Fatalf("a body at the limit: size %d, err %v", size, err)
	}

	// Undeclared: refused once the stream passes the limit.
	_, _, err := f.store.Put(ctx, nsID, "long", "text/plain", strings.NewReader("abcde"), -1)
	if !isKind(err, apperr.KindEntityTooLarge) {
		t.Fatalf("undeclared oversize body: err = %v, want EntityTooLarge", err)
	}
	// Declared: refused before reading.
	_, _, err = f.store.Put(ctx, nsID, "declared", "text/plain", unreadable{t}, 5)
	if !isKind(err, apperr.KindEntityTooLarge) {
		t.Fatalf("declared oversize body: err = %v, want EntityTooLarge", err)
	}

	if _, err := f.db.GetObject(ctx, nsID, "long"); !errors.Is(err, apperr.ErrNoSuchKey) {
		t.Errorf("a refused upload must not create an object, got %v", err)
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files left behind by refused uploads", n)
	}
}

func TestPutPartEnforcesThePartSizeLimit(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.MaxPartBytes = 2 }))
	ctx := t.Context()
	upload := f.multipart(t, f.namespace(t, "ns", nil), "big")

	if _, err := f.store.PutPart(ctx, upload, 1, strings.NewReader("ab"), -1); err != nil {
		t.Fatalf("a part at the limit: %v", err)
	}
	if _, err := f.store.PutPart(ctx, upload, 2, strings.NewReader("abc"), -1); !isKind(err, apperr.KindEntityTooLarge) {
		t.Fatalf("undeclared oversize part: err = %v, want EntityTooLarge", err)
	}
	if _, err := f.store.PutPart(ctx, upload, 2, unreadable{t}, 3); !isKind(err, apperr.KindEntityTooLarge) {
		t.Fatalf("declared oversize part: err = %v, want EntityTooLarge", err)
	}

	parts, err := f.db.ListParts(ctx, upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 {
		t.Errorf("%d parts recorded, want only the one within the limit", len(parts))
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 1 {
		t.Errorf("%d staging files, want 1 (the accepted part)", n)
	}
}

// Parts can each be within the part limit and still add up past the object
// limit. Completion must refuse that before assembling anything.
func TestCompleteMultipartEnforcesTheObjectSizeLimit(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) {
		l.MaxObjectBytes = 5
		l.MaxPartBytes = 3
	}))
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	upload := f.multipart(t, nsID, "big")

	for i, body := range []string{"abc", "def"} {
		if _, err := f.store.PutPart(ctx, upload, int32(i+1), strings.NewReader(body), -1); err != nil {
			t.Fatal(err)
		}
	}
	parts, err := f.db.ListParts(ctx, upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CompleteMultipart(ctx, upload, parts); !isKind(err, apperr.KindEntityTooLarge) {
		t.Fatalf("err = %v, want EntityTooLarge", err)
	}
	if _, err := f.db.GetObject(ctx, nsID, "big"); !errors.Is(err, apperr.ErrNoSuchKey) {
		t.Errorf("a refused completion must not create the object, got %v", err)
	}
	// Only the two parts: nothing was assembled.
	if n := f.countUnder(t, storage.StagingPrefix); n != 2 {
		t.Errorf("%d staging files, want the 2 parts", n)
	}
}

// ---------------------------------------------------------------------------
// Quotas
// ---------------------------------------------------------------------------

// Dedup is global, but a team pays for everything it stores in full: what
// another team holds must not make this team's usage any cheaper, or usage
// would reveal it.
func TestQuotaChargesSharedContentInFull(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 5 }))
	ctx := t.Context()
	a, b := f.tenant(t, "a"), f.tenant(t, "b")
	nsA, nsB := f.namespace(t, "ns-a", &a), f.namespace(t, "ns-b", &b)

	if _, _, err := f.store.Put(ctx, nsA, "x", "text/plain", strings.NewReader("abc"), -1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.Put(ctx, nsB, "x", "text/plain", strings.NewReader("abc"), -1); err != nil {
		t.Fatalf("team b's first 3 bytes: %v", err)
	}
	// 3 + 3 > 5, though the second 3 are a dedup hit on b's own content.
	_, _, err := f.store.Put(ctx, nsB, "y", "text/plain", strings.NewReader("abc"), -1)
	if !isKind(err, apperr.KindQuotaExceeded) {
		t.Fatalf("err = %v, want QuotaExceeded", err)
	}
	if got := f.usage(t, b); got != 3 {
		t.Errorf("team b usage = %d, want 3", got)
	}
	if n := f.driftedBlobs(t); n != 0 {
		t.Errorf("%d blobs with drifted refcounts after a refused write", n)
	}
}

// A refusal must come before the bytes are promoted: once the transaction
// rolls back, promoted bytes have no blob row and nothing would collect them.
func TestQuotaRefusesNewContentBeforePromotingIt(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 5 }))
	ctx := t.Context()
	team := f.tenant(t, "team")
	nsID := f.namespace(t, "ns", &team)

	if _, _, err := f.store.Put(ctx, nsID, "a", "text/plain", strings.NewReader("abc"), -1); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.store.Put(ctx, nsID, "b", "text/plain", strings.NewReader("xyz"), -1)
	if !isKind(err, apperr.KindQuotaExceeded) {
		t.Fatalf("err = %v, want QuotaExceeded", err)
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != 1 {
		t.Errorf("%d xorbs, want 1: refused content must not reach xorbs/", n)
	}
}

// Overwriting a key replaces its bytes rather than adding to them.
func TestQuotaChargesAnOverwriteTheDifference(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 5 }))
	ctx := t.Context()
	team := f.tenant(t, "team")
	nsID := f.namespace(t, "ns", &team)

	for _, body := range []string{"abcd", "efgh", "ijklm"} {
		if _, _, err := f.store.Put(ctx, nsID, "k", "text/plain", strings.NewReader(body), -1); err != nil {
			t.Fatalf("overwrite with %q: %v", body, err)
		}
	}
	if got := f.usage(t, team); got != 5 {
		t.Errorf("usage = %d, want 5", got)
	}
}

// Copy and link move no bytes, but the object they create is charged.
func TestQuotaAppliesToCopyAndLink(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 5 }))
	ctx := t.Context()
	team := f.tenant(t, "team")
	nsID := f.namespace(t, "ns", &team)

	if _, _, err := f.store.Put(ctx, nsID, "a", "text/plain", strings.NewReader("abc"), -1); err != nil {
		t.Fatal(err)
	}
	src, err := f.db.GetObject(ctx, nsID, "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CopyObject(ctx, src, nsID, "copy"); !isKind(err, apperr.KindQuotaExceeded) {
		t.Errorf("copy: err = %v, want QuotaExceeded", err)
	}
	if _, _, _, err := f.store.LinkBlob(ctx, nsID, "link", hashABC, "text/plain", &team); !isKind(err, apperr.KindQuotaExceeded) {
		t.Errorf("link: err = %v, want QuotaExceeded", err)
	}
	if got := f.usage(t, team); got != 3 {
		t.Errorf("usage = %d, want 3", got)
	}
	if n, _ := f.refcount(t, hashABC); n != 1 {
		t.Errorf("refcount = %d, want 1: refused copy and link must not keep a reference", n)
	}
}

// Parts of unfinished uploads count, or a team could park unbounded bytes in
// uploads it never completes. Re-uploading a part replaces it, and completing
// an upload converts its parts into the object without counting both.
func TestQuotaCountsMultipartParts(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 5 }))
	ctx := t.Context()
	team := f.tenant(t, "team")
	nsID := f.namespace(t, "ns", &team)
	upload := f.multipart(t, nsID, "big")

	if _, err := f.store.PutPart(ctx, upload, 1, strings.NewReader("abc"), -1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PutPart(ctx, upload, 2, strings.NewReader("def"), -1); !isKind(err, apperr.KindQuotaExceeded) {
		t.Fatalf("a part past the quota: err = %v, want QuotaExceeded", err)
	}
	// Part 1 again: 3 bytes replacing 3, not 6.
	if _, err := f.store.PutPart(ctx, upload, 1, strings.NewReader("ghi"), -1); err != nil {
		t.Fatalf("re-uploading a part: %v", err)
	}
	if _, err := f.store.PutPart(ctx, upload, 2, strings.NewReader("jk"), -1); err != nil {
		t.Fatalf("a part that fits: %v", err)
	}

	parts, err := f.db.ListParts(ctx, upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 5 bytes of parts become 5 bytes of object: at the quota, not 10 over.
	if _, err := f.store.CompleteMultipart(ctx, upload, parts); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got := f.usage(t, team); got != 5 {
		t.Errorf("usage = %d, want 5", got)
	}
}

func TestQuotaIgnoresUnownedNamespaces(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 1 }))
	nsID := f.namespace(t, "ns", nil)
	if _, _, err := f.store.Put(t.Context(), nsID, "k", "text/plain", strings.NewReader("abc"), -1); err != nil {
		t.Fatalf("an unowned namespace has no quota: %v", err)
	}
}

// Writers racing past the unlocked early check must still be held to the
// quota by the locked one.
func TestQuotaHoldsUnderConcurrentWriters(t *testing.T) {
	const quota, writers, size = 10, 8, 3
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = quota }))
	ctx := t.Context()
	team := f.tenant(t, "team")
	nsID := f.namespace(t, "ns", &team)

	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Go(func() {
			body := fmt.Sprintf("%03d", i)
			_, _, errs[i] = f.store.Put(ctx, nsID, "k"+body, "text/plain", strings.NewReader(body), -1)
		})
	}
	wg.Wait()

	accepted := 0
	for _, err := range errs {
		switch {
		case err == nil:
			accepted++
		case !isKind(err, apperr.KindQuotaExceeded):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if accepted != quota/size {
		t.Errorf("%d writes accepted, want %d", accepted, quota/size)
	}
	if got := f.usage(t, team); got > quota {
		t.Errorf("usage = %d, over the %d-byte quota", got, quota)
	}
	if n := f.driftedBlobs(t); n != 0 {
		t.Errorf("%d blobs with drifted refcounts", n)
	}
}

// Parts staged for one upload count against every other write in the team,
// not only against that upload's own completion.
func TestQuotaCountsStagedPartsAgainstOtherWrites(t *testing.T) {
	f := newFixtureWithLimits(t, defaultGC(), limitsWith(func(l *config.LimitsConfig) { l.TenantQuotaBytes = 5 }))
	ctx := t.Context()
	team := f.tenant(t, "team")
	nsID := f.namespace(t, "ns", &team)
	upload := f.multipart(t, nsID, "big")
	if _, err := f.store.PutPart(ctx, upload, 1, strings.NewReader("abcd"), -1); err != nil {
		t.Fatal(err)
	}
	// 4 bytes of parts + 2 bytes of object > 5.
	if _, _, err := f.store.Put(ctx, nsID, "other", "text/plain", strings.NewReader("ab"), -1); !isKind(err, apperr.KindQuotaExceeded) {
		t.Errorf("err = %v, want QuotaExceeded: staged parts must count", err)
	}
}

// A body that stops arriving fails with the router's stall deadline; that is
// the client's doing, and is reported as RequestTimeout rather than a 500.
func TestStageReportsAStalledBodyAsATimeout(t *testing.T) {
	f := newFixture(t, defaultGC())
	_, err := f.store.Stage(t.Context(), stalled{})
	if !errors.Is(err, apperr.ErrRequestTimeout) {
		t.Fatalf("err = %v, want RequestTimeout", err)
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files left behind", n)
	}
}

type stalled struct{}

func (stalled) Read([]byte) (int, error) {
	return 0, fmt.Errorf("read tcp: %w", os.ErrDeadlineExceeded)
}
