package cas

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// Published BLAKE3 digests, which are also what the PWA's hash-wasm produces —
// so these pin the ETag contract the client-side dedup path depends on.
const (
	hashEmpty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	hashABC   = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
)

// fixture is a Store wired to a scratch database and a scratch fs bucket, plus
// a raw pool for the assertions that need to look behind the abstraction.
type fixture struct {
	store  *Store
	db     *db.DB
	bucket *storage.Bucket
	pool   *pgxpool.Pool
}

func newFixture(t *testing.T, gc config.GcConfig) *fixture {
	t.Helper()
	ctx := t.Context()
	dsn := testdb.URL(t)

	database, err := db.Connect(ctx, dsn, 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)

	// A raw pool for the assertions that need to look behind the abstraction.
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("raw pool: %v", err)
	}
	t.Cleanup(pool.Close)

	bucket, err := storage.Open(ctx, config.StorageConfig{Backend: "fs", Root: t.TempDir()})
	if err != nil {
		t.Fatalf("open bucket: %v", err)
	}
	t.Cleanup(func() { _ = bucket.Close() })

	return &fixture{
		store:  New(database, bucket, gc, slog.New(slog.DiscardHandler)),
		db:     database,
		bucket: bucket,
		pool:   pool,
	}
}

func defaultGC() config.GcConfig {
	return config.GcConfig{IntervalSecs: 60, GraceSecs: 300, MultipartExpirySecs: 86400}
}

func (f *fixture) namespace(t *testing.T, name string, tenantID *int64) int64 {
	t.Helper()
	if err := f.db.CreateNamespace(t.Context(), name, tenantID); err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	ns, err := f.db.GetNamespace(t.Context(), name)
	if err != nil {
		t.Fatalf("get namespace: %v", err)
	}
	return ns.ID
}

func (f *fixture) refcount(t *testing.T, hash string) (int64, bool) {
	t.Helper()
	var n int64
	err := f.pool.QueryRow(t.Context(), "SELECT refcount FROM blobs WHERE hash = $1", hash).Scan(&n)
	if err != nil {
		return 0, false
	}
	return n, true
}

// countUnder reports how many objects exist under a key prefix, which is how
// the tests check that dedup really stored the bytes only once.
func (f *fixture) countUnder(t *testing.T, prefix string) int {
	t.Helper()
	var n int
	it := f.bucket.List(&blob.ListOptions{Prefix: prefix})
	for {
		obj, err := it.Next(t.Context())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("list %s: %v", prefix, err)
		}
		if !obj.IsDir {
			n++
		}
	}
	return n
}

func (f *fixture) stage(t *testing.T, body string) StagedBlob {
	t.Helper()
	staged, err := f.store.Stage(t.Context(), strings.NewReader(body))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	return staged
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

func TestStageHashesWhileStreaming(t *testing.T) {
	f := newFixture(t, defaultGC())

	tests := []struct {
		name string
		body string
		hash string
		size int64
	}{
		{"empty body", "", hashEmpty, 0},
		{"known vector", "abc", hashABC, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			staged := f.stage(t, tc.body)
			if staged.Hash != tc.hash {
				t.Errorf("hash = %s, want %s", staged.Hash, tc.hash)
			}
			if staged.Size != tc.size {
				t.Errorf("size = %d, want %d", staged.Size, tc.size)
			}
			if !strings.HasPrefix(staged.StagingKey, storage.StagingPrefix) {
				t.Errorf("staging key %q is outside the staging prefix", staged.StagingKey)
			}
			// The bytes really landed.
			got, err := f.bucket.ReadAll(t.Context(), staged.StagingKey)
			if err != nil {
				t.Fatalf("read staged bytes: %v", err)
			}
			if string(got) != tc.body {
				t.Errorf("staged content = %q, want %q", got, tc.body)
			}
		})
	}
}

// A client that hangs up mid-body is a bad request, not a server fault, and it
// must not leave a staging file behind.
func TestStageDiscardsStagingOnBodyFailure(t *testing.T) {
	f := newFixture(t, defaultGC())

	body := io.MultiReader(
		strings.NewReader("partial"),
		&failingReader{err: errors.New("connection reset")},
	)
	_, err := f.store.Stage(t.Context(), body)
	if err == nil {
		t.Fatal("expected the staging attempt to fail")
	}
	if got := apperr.From(err).Status(); got != 400 {
		t.Errorf("status = %d, want 400 for a client body failure", got)
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files left behind, want none", n)
	}
}

type failingReader struct{ err error }

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

func TestCommitPublishesAndCleansUp(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	staged := f.stage(t, "abc")
	etag, err := f.store.Commit(ctx, nsID, "k", "text/plain", staged)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if etag != hashABC {
		t.Errorf("etag = %s, want the content hash %s", etag, hashABC)
	}

	// The bytes live at their content-addressed home.
	got, err := f.bucket.ReadAll(ctx, storage.BlobPath(hashABC))
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if string(got) != "abc" {
		t.Errorf("blob content = %q", got)
	}
	// Staging is cleared on the happy path.
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files remain, want none", n)
	}

	obj, err := f.db.GetObject(ctx, nsID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if obj.BlobHash != hashABC || obj.Size != 3 || obj.ContentType != "text/plain" {
		t.Errorf("object = %+v", obj)
	}
	if n, _ := f.refcount(t, hashABC); n != 1 {
		t.Errorf("refcount = %d, want 1", n)
	}
}

// The heart of dedup: uploading identical content a second time adds a
// reference and stores no additional bytes.
func TestCommitDedupStoresBytesOnce(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	a := f.namespace(t, "ns-a", nil)
	b := f.namespace(t, "ns-b", nil)

	if _, err := f.store.Commit(ctx, a, "first", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, b, "second", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	if n := f.countUnder(t, "blobs/"); n != 1 {
		t.Errorf("%d stored blobs, want exactly 1 — the duplicate must cost no bytes", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files remain, want none", n)
	}
}

func TestCommitOverwriteReleasesTheOldBlob(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if _, err := f.store.Commit(ctx, nsID, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "k", "text/plain", f.stage(t, "")); err != nil {
		t.Fatal(err)
	}

	if n, _ := f.refcount(t, hashABC); n != 0 {
		t.Errorf("old blob refcount = %d, want 0", n)
	}
	if n, _ := f.refcount(t, hashEmpty); n != 1 {
		t.Errorf("new blob refcount = %d, want 1", n)
	}
	// The old bytes stay until GC's grace period expires, so a re-upload or a
	// dedup link can still reuse them.
	if ok, _ := f.bucket.Exists(ctx, storage.BlobPath(hashABC)); !ok {
		t.Error("the superseded blob's bytes should survive until GC collects them")
	}
}

// ---------------------------------------------------------------------------
// Copy and link
// ---------------------------------------------------------------------------

func TestCopyObjectMovesNoBytes(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	src := f.namespace(t, "src", nil)
	dst := f.namespace(t, "dst", nil)

	if _, err := f.store.Commit(ctx, src, "orig", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	meta, err := f.db.GetObject(ctx, src, "orig")
	if err != nil {
		t.Fatal(err)
	}

	etag, err := f.store.CopyObject(ctx, meta, dst, "copy")
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if etag != hashABC {
		t.Errorf("etag = %s, want %s", etag, hashABC)
	}
	if n := f.countUnder(t, "blobs/"); n != 1 {
		t.Errorf("%d stored blobs, want 1 — a copy must not duplicate bytes", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}

	copied, err := f.db.GetObject(ctx, dst, "copy")
	if err != nil {
		t.Fatal(err)
	}
	if copied.ContentType != "text/plain" || copied.Size != 3 {
		t.Errorf("copy metadata = %+v, want the source's", copied)
	}
}

// If GC collected the source blob between reading the object and claiming it,
// there are no bytes to honour the copy with.
func TestCopyObjectFailsWhenTheBlobIsGone(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	dst := f.namespace(t, "dst", nil)

	phantom := db.ObjectMeta{
		Key:         "orig",
		BlobHash:    hashABC,
		Size:        3,
		ContentType: "text/plain",
	}
	_, err := f.store.CopyObject(ctx, phantom, dst, "copy")
	if !errors.Is(err, apperr.ErrNoSuchKey) {
		t.Fatalf("err = %v, want ErrNoSuchKey", err)
	}
	// The speculative claim must not have left a blob row behind.
	if _, ok := f.refcount(t, hashABC); ok {
		t.Error("a failed copy left a blob row with no bytes behind it")
	}
}

func TestLinkBlob(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	// Miss: nothing stored yet, so the client must upload for real.
	_, linked, err := f.store.LinkBlob(ctx, nsID, "k", hashABC, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if linked {
		t.Fatal("linking absent content should report linked=false")
	}

	if _, err := f.store.Commit(ctx, nsID, "orig", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	// Hit: zero bytes transferred, and the size comes from the store.
	size, linked, err := f.store.LinkBlob(ctx, nsID, "k", hashABC, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("stored content should link")
	}
	if size != 3 {
		t.Errorf("size = %d, want the stored 3", size)
	}
	if n := f.countUnder(t, "blobs/"); n != 1 {
		t.Errorf("%d stored blobs, want 1", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
}

// The link endpoint must not confirm the existence of another tenant's content.
func TestLinkBlobIsTenantScoped(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()

	mine, err := f.db.CreateTenant(ctx, "mine", "me@example.com")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := f.db.CreateTenant(ctx, "theirs", "them@example.com")
	if err != nil {
		t.Fatal(err)
	}
	theirNS := f.namespace(t, "theirs-ns", &theirs)
	myNS := f.namespace(t, "mine-ns", &mine)

	// Their content is stored, but my tenant has never seen it.
	if _, err := f.store.Commit(ctx, theirNS, "secret", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	_, linked, err := f.store.LinkBlob(ctx, myNS, "guess", hashABC, "text/plain", &mine)
	if err != nil {
		t.Fatal(err)
	}
	if linked {
		t.Fatal("linking another tenant's content must be declined")
	}
	// Declining must not have taken a reference either.
	if n, _ := f.refcount(t, hashABC); n != 1 {
		t.Errorf("refcount = %d, want 1 — the declined link must not claim", n)
	}

	// The owning tenant links fine.
	_, linked, err = f.store.LinkBlob(ctx, theirNS, "again", hashABC, "text/plain", &theirs)
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Error("the owning tenant should be able to link its own content")
	}
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

// The assembled object must hash as the concatenation, in the order given, so
// it dedups against a whole-file upload of the same content.
func TestCompleteMultipartConcatenatesInOrder(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	uploadID, err := f.db.CreateMultipart(ctx, nsID, "assembled", "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := f.db.GetMultipart(ctx, nsID, "assembled", uploadID)
	if err != nil {
		t.Fatal(err)
	}

	// "a" + "b" + "c" must hash as "abc".
	var parts []db.PartMeta
	for i, body := range []string{"a", "b", "c"} {
		staged := f.stage(t, body)
		replaced, err := f.db.PutPart(ctx, uploadID, int32(i+1), staged.StagingKey, staged.Size, staged.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if replaced != "" {
			t.Errorf("unexpected replacement %q", replaced)
		}
		parts = append(parts, db.PartMeta{
			PartNumber: int32(i + 1),
			StagingKey: staged.StagingKey,
			Size:       staged.Size,
			ETag:       staged.Hash,
		})
	}

	etag, err := f.store.CompleteMultipart(ctx, upload, parts)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if etag != hashABC {
		t.Errorf("etag = %s, want the hash of the whole object %s", etag, hashABC)
	}

	got, err := f.bucket.ReadAll(ctx, storage.BlobPath(hashABC))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Errorf("assembled content = %q, want abc", got)
	}
	obj, err := f.db.GetObject(ctx, nsID, "assembled")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 3 {
		t.Errorf("size = %d, want 3", obj.Size)
	}

	// The parts and the assembly scratch file are all cleaned up.
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files remain after completion, want none", n)
	}
	if _, err := f.db.GetMultipart(ctx, nsID, "assembled", uploadID); !errors.Is(err, apperr.ErrNoSuchUpload) {
		t.Errorf("the upload record should be gone, got %v", err)
	}
}

// A multipart-assembled object and a whole-file upload of the same bytes are
// the same blob — dedup does not care how the content arrived.
func TestMultipartDedupsAgainstWholeFileUpload(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if _, err := f.store.Commit(ctx, nsID, "whole", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	uploadID, err := f.db.CreateMultipart(ctx, nsID, "in-parts", "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := f.db.GetMultipart(ctx, nsID, "in-parts", uploadID)
	if err != nil {
		t.Fatal(err)
	}
	var parts []db.PartMeta
	for i, body := range []string{"ab", "c"} {
		staged := f.stage(t, body)
		if _, err := f.db.PutPart(ctx, uploadID, int32(i+1), staged.StagingKey, staged.Size, staged.Hash); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, db.PartMeta{
			PartNumber: int32(i + 1), StagingKey: staged.StagingKey,
			Size: staged.Size, ETag: staged.Hash,
		})
	}
	if _, err := f.store.CompleteMultipart(ctx, upload, parts); err != nil {
		t.Fatal(err)
	}

	if n := f.countUnder(t, "blobs/"); n != 1 {
		t.Errorf("%d stored blobs, want 1", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
}
