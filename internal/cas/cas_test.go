package cas

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeebo/blake3"
	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testblob"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// Published BLAKE3 digests, which are also what the PWA's hash-wasm produces —
// so these pin the content addresses the client-side dedup path depends on.
const (
	hashEmpty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	hashABC   = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
)

// md5ABC is the MD5 of "abc", the ETag S3 gives it.
const md5ABC = "900150983cd24fb0d6963f7d28e17f72"

// multipartETag is the ETag S3 gives a multipart upload of these parts: the
// MD5 of the parts' MD5s, then "-" and the part count.
func multipartETag(parts ...string) string {
	all := md5.New()
	for _, p := range parts {
		sum := md5.Sum([]byte(p))
		all.Write(sum[:])
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(all.Sum(nil)), len(parts))
}

// fixture is a Store wired to a scratch database and a scratch bucket
// (testblob), plus a raw pool for the assertions that need to look behind the
// abstraction.
type fixture struct {
	store  *Store
	db     *db.DB
	bucket *storage.Bucket
	pool   *pgxpool.Pool
}

func newFixture(t *testing.T, gc config.GcConfig) *fixture {
	t.Helper()
	return newFixtureWithLimits(t, gc, config.Default().Limits)
}

func newFixtureWithLimits(t *testing.T, gc config.GcConfig, limits config.LimitsConfig) *fixture {
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

	bucket := testblob.Open(t)

	return &fixture{
		store:  New(database, bucket, gc, limits, slog.New(slog.DiscardHandler)),
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

// driftedBlobs counts blobs whose refcount disagrees with the number of objects
// actually pointing at them. Every write path must keep this at zero.
func (f *fixture) driftedBlobs(t *testing.T) int {
	t.Helper()
	var n int
	err := f.pool.QueryRow(t.Context(), `
		SELECT COUNT(*) FROM blobs b
		WHERE b.refcount <> (SELECT COUNT(*) FROM objects o WHERE o.blob_hash = b.hash)`).Scan(&n)
	if err != nil {
		t.Fatalf("count drifted blobs: %v", err)
	}
	return n
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

// hashOf is the BLAKE3 address of content.
func hashOf(content string) string {
	sum := blake3.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// putWholeFile stores content as key the way it was stored before chunking:
// one file under blobs/ and a blob row with no terms. It returns the hash.
func (f *fixture) putWholeFile(t *testing.T, nsID int64, key, content string) string {
	t.Helper()
	ctx := t.Context()
	hash := hashOf(content)
	sum := md5.Sum([]byte(content))
	if err := f.bucket.WriteAll(ctx, storage.BlobPath(hash), []byte(content), nil); err != nil {
		t.Fatal(err)
	}
	_, err := f.pool.Exec(ctx, `
		INSERT INTO blobs (hash, size, refcount, md5, chunked) VALUES ($1, $2, 1, $3, false)
		ON CONFLICT (hash) DO UPDATE SET refcount = blobs.refcount + 1`,
		hash, len(content), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.pool.Exec(ctx, `
		INSERT INTO objects (namespace_id, key, blob_hash, etag, size, content_type)
		VALUES ($1, $2, $3, $4, $5, 'text/plain')`,
		nsID, key, hash, hex.EncodeToString(sum[:]), len(content))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

// xorbABC is the xorb "abc" is stored in: content that short is one chunk,
// and a one-chunk xorb is named by that chunk's hash.
var xorbABC = chunkHash([]byte("abc"))

// xorbRefcount reads a xorb's reference count, or ok=false if its row is gone.
func (f *fixture) xorbRefcount(t *testing.T, hash string) (int64, bool) {
	t.Helper()
	var n int64
	err := f.pool.QueryRow(t.Context(), "SELECT refcount FROM xorbs WHERE hash = $1", hash).Scan(&n)
	if err != nil {
		return 0, false
	}
	return n, true
}

// xorbsOf lists the xorbs a blob's terms use.
func (f *fixture) xorbsOf(t *testing.T, blob string) []string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), "SELECT DISTINCT xorb_hash FROM blob_terms WHERE blob_hash = $1 ORDER BY 1", blob)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return hashes
}

// blobChunks lists the chunk hashes a blob's terms hold, in order.
func (f *fixture) blobChunks(t *testing.T, blob string) []string {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `
		SELECT xc.chunk_hash FROM blob_terms t
		JOIN xorb_chunks xc ON xc.xorb_hash = t.xorb_hash AND xc.idx >= t.chunk_start AND xc.idx < t.chunk_end
		WHERE t.blob_hash = $1 ORDER BY t.pos, xc.idx`, blob)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return hashes
}

// driftedXorbs counts xorbs whose refcount disagrees with the number of blobs
// whose terms use them. Every write path and sweep must keep this at zero.
func (f *fixture) driftedXorbs(t *testing.T) int {
	t.Helper()
	var n int
	err := f.pool.QueryRow(t.Context(), `
		SELECT COUNT(*) FROM xorbs x
		WHERE x.refcount <> (SELECT COUNT(DISTINCT blob_hash) FROM blob_terms bt WHERE bt.xorb_hash = x.hash)`).Scan(&n)
	if err != nil {
		t.Fatalf("count drifted xorbs: %v", err)
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
	if etag != md5ABC {
		t.Errorf("etag = %s, want the content MD5 %s", etag, md5ABC)
	}

	// The bytes live in a xorb at its content-addressed home.
	if got := f.xorbsOf(t, hashABC); len(got) != 1 || got[0] != xorbABC {
		t.Errorf("xorbs = %v, want [%s]", got, xorbABC)
	}
	if ok, _ := f.bucket.Exists(ctx, storage.XorbPath(xorbABC)); !ok {
		t.Error("the xorb is not in the backend")
	}
	got, err := f.readRange(t, hashABC, 0, 3)
	if err != nil || string(got) != "abc" {
		t.Errorf("read back %q, %v; want abc", got, err)
	}
	// Staging is cleared on the happy path.
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files remain, want none", n)
	}

	obj, err := f.db.GetObject(ctx, nsID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if obj.BlobHash != hashABC || obj.ETag() != md5ABC || obj.Size != 3 || obj.ContentType != "text/plain" {
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

	if n := f.countUnder(t, storage.XorbPrefix); n != 1 {
		t.Errorf("%d stored xorbs, want exactly 1 — the duplicate must cost no bytes", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files remain, want none", n)
	}
}

// Dedup is global, so skipping the write for any stored blob would make an
// upload of content another tenant holds come back faster than one of new
// content. The bytes are written for any content new to the namespace, as a
// decoy deleted after the commit; only a namespace's own duplicates skip it.
func TestCommitWritesBytesForContentNewToTheNamespace(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	mine := f.namespace(t, "mine", nil)
	theirs := f.namespace(t, "theirs", nil)

	if _, err := f.store.Commit(ctx, theirs, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	// A duplicate inside the namespace that holds the content writes nothing.
	again := f.stage(t, "abc")
	p, err := f.store.plan(ctx, again, theirs)
	if err != nil {
		t.Fatal(err)
	}
	if p.writes() {
		t.Error("a duplicate within the namespace plans writes")
	}
	if _, err := f.store.Commit(ctx, theirs, "again", "text/plain", again); err != nil {
		t.Fatal(err)
	}

	// The same content in another namespace is written as if it were new.
	staged := f.stage(t, "abc")
	p, err = f.store.plan(ctx, staged, mine)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.xorbs) != 0 || len(p.decoys) != 1 || len(p.decoys[0]) != len(staged.Chunks) {
		t.Fatalf("plan = %d new xorbs and decoys %v, want every chunk written as a decoy", len(p.xorbs), p.decoys)
	}
	w, err := f.store.carryOut(ctx, staged, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.decoys) != 1 {
		t.Fatalf("wrote %d decoys, want 1", len(w.decoys))
	}
	if attrs, err := f.bucket.Attributes(ctx, w.decoys[0]); err != nil || attrs.Size < 3 {
		t.Errorf("decoy = %+v, %v; want the content's bytes written", attrs, err)
	}
	f.store.discardDecoys(ctx, w.decoys)

	if _, err := f.store.Commit(ctx, mine, "k", "text/plain", staged); err != nil {
		t.Fatal(err)
	}
	if n := f.countUnder(t, storage.StagingPrefix); n != 0 {
		t.Errorf("%d staging files remain, want the decoy gone with the rest", n)
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != 1 {
		t.Errorf("%d xorbs, want 1 — still one shared copy", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 3 {
		t.Errorf("refcount = %d, want 3 — still one shared blob", n)
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
	if ok, _ := f.bucket.Exists(ctx, storage.XorbPath(xorbABC)); !ok {
		t.Error("the superseded blob's bytes should survive until GC collects them")
	}
}

// GC deletes a whole-file blob's bytes before its transaction commits the
// row's removal, so a crash or failed commit in between leaves a zero-ref row
// with no bytes. The next upload of that content revives the row, and must put
// the bytes back rather than trust that a row means they are there. (Chunked
// blobs have no such window: their sweep deletes no bytes.)
func TestCommitRestoresBytesAfterAnInterruptedSweep(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	f.putWholeFile(t, nsID, "k", "abc")
	if _, err := f.db.DeleteObject(ctx, nsID, "k"); err != nil {
		t.Fatal(err)
	}

	// The sweep gets as far as deleting the bytes, then its commit fails.
	crash := errors.New("crashed before commit")
	_, err := f.db.GCSweep(ctx, 0, 100, func(ctx context.Context, hash string) error {
		if err := f.store.deleteIfPresent(ctx, storage.BlobPath(hash)); err != nil {
			return err
		}
		return crash
	})
	if !errors.Is(err, crash) {
		t.Fatalf("sweep err = %v, want the injected crash", err)
	}
	if n, ok := f.refcount(t, hashABC); !ok || n != 0 {
		t.Fatalf("refcount = %d (present=%v), want a surviving zero-ref row", n, ok)
	}
	if ok, _ := f.bucket.Exists(ctx, storage.BlobPath(hashABC)); ok {
		t.Fatal("setup: the interrupted sweep should have removed the bytes")
	}

	// The link fast path has no bytes to offer and must send the client to
	// a real upload instead of linking to nothing.
	_, _, linked, err := f.store.LinkBlob(ctx, nsID, "linked", hashABC, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if linked {
		t.Error("linking a zero-ref blob whose bytes may be gone must be declined")
	}

	// A copy from a stale read of the old object has nothing to copy either.
	stale := db.ObjectMeta{Key: "k", BlobHash: hashABC, Size: 3, ContentType: "text/plain"}
	if _, err := f.store.CopyObject(ctx, stale, nsID, "copied"); !errors.Is(err, apperr.ErrNoSuchKey) {
		t.Errorf("copy err = %v, want ErrNoSuchKey", err)
	}

	// The re-upload revives the row and writes the bytes back.
	if _, err := f.store.Commit(ctx, nsID, "again", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	got, err := f.bucket.ReadAll(ctx, storage.BlobPath(hashABC))
	if err != nil {
		t.Fatalf("the re-uploaded object has no bytes behind it: %v", err)
	}
	if string(got) != "abc" {
		t.Errorf("blob content = %q, want %q", got, "abc")
	}
	if n, _ := f.refcount(t, hashABC); n != 1 {
		t.Errorf("refcount = %d, want 1", n)
	}
	if n := f.driftedBlobs(t); n != 0 {
		t.Errorf("%d blobs have a refcount that disagrees with their objects", n)
	}
}

// Concurrent PUTs of different content to the same new key: exactly one wins,
// and every loser's reference must be released. SELECT ... FOR UPDATE locks
// nothing on a key that does not exist yet, so without the key lock in
// UpsertObject each writer saw no previous object and the overwritten blobs
// kept a reference forever.
func TestCommitConcurrentPutsToANewKeyReleaseTheLosers(t *testing.T) {
	f := newFixture(t, collectNow())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	const writers, rounds = 8, 5
	for round := range rounds {
		key := fmt.Sprintf("contended-%d", round)

		staged := make([]StagedBlob, writers)
		for i := range staged {
			staged[i] = f.stage(t, fmt.Sprintf("round %d writer %d", round, i))
		}

		// Release every writer at once so their transactions overlap.
		start := make(chan struct{})
		errs := make([]error, writers)
		var wg sync.WaitGroup
		for i := range writers {
			wg.Go(func() {
				<-start
				_, errs[i] = f.store.Commit(ctx, nsID, key, "text/plain", staged[i])
			})
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d writer %d: %v", round, i, err)
			}
		}
	}

	if n := f.driftedBlobs(t); n != 0 {
		t.Fatalf("%d blobs have a refcount that disagrees with their objects", n)
	}

	// Every loser is now unreferenced and collectable; only the winners stay.
	f.store.sweepBlobs(ctx)
	f.store.sweepXorbs(ctx)

	var rows int
	if err := f.pool.QueryRow(ctx, "SELECT COUNT(*) FROM blobs").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != rounds {
		t.Errorf("%d blob rows after GC, want %d — one winner per key", rows, rounds)
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != rounds {
		t.Errorf("%d stored xorbs after GC, want %d", n, rounds)
	}
	for round := range rounds {
		obj, err := f.db.GetObject(ctx, nsID, fmt.Sprintf("contended-%d", round))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.readRange(t, obj.BlobHash, 0, obj.Size); err != nil {
			t.Errorf("round %d: the winning object lost its bytes: %v", round, err)
		}
	}
	if n := f.driftedXorbs(t); n != 0 {
		t.Errorf("%d xorbs have a refcount that disagrees with their terms", n)
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
	if etag != md5ABC {
		t.Errorf("etag = %s, want %s", etag, md5ABC)
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != 1 {
		t.Errorf("%d stored xorbs, want 1 — a copy must not duplicate bytes", n)
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
	_, _, linked, err := f.store.LinkBlob(ctx, nsID, "k", hashABC, "text/plain", nil)
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
	size, _, linked, err := f.store.LinkBlob(ctx, nsID, "k", hashABC, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("stored content should link")
	}
	if size != 3 {
		t.Errorf("size = %d, want the stored 3", size)
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != 1 {
		t.Errorf("%d stored xorbs, want 1", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
}

// The link endpoint must not confirm the existence of another tenant's content.
func TestLinkBlobIsTenantScoped(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()

	mine := f.tenant(t, "mine")
	theirs := f.tenant(t, "theirs")
	theirNS := f.namespace(t, "theirs-ns", &theirs)
	myNS := f.namespace(t, "mine-ns", &mine)

	// Their content is stored, but my tenant has never seen it.
	if _, err := f.store.Commit(ctx, theirNS, "secret", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	_, _, linked, err := f.store.LinkBlob(ctx, myNS, "guess", hashABC, "text/plain", &mine)
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
	_, _, linked, err = f.store.LinkBlob(ctx, theirNS, "again", hashABC, "text/plain", &theirs)
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
		replaced, err := f.db.PutPart(ctx, uploadID, int32(i+1), staged.StagingKey, staged.Size, staged.ETag, 0)
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
			ETag:       staged.ETag,
		})
	}

	etag, err := f.store.CompleteMultipart(ctx, upload, parts)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if want := multipartETag("a", "b", "c"); etag != want {
		t.Errorf("etag = %s, want %s", etag, want)
	}

	got, err := f.readRange(t, hashABC, 0, 3)
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
	if obj.Size != 3 || obj.BlobHash != hashABC {
		t.Errorf("object = %+v, want 3 bytes stored as the hash of the whole object %s", obj, hashABC)
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
		if _, err := f.db.PutPart(ctx, uploadID, int32(i+1), staged.StagingKey, staged.Size, staged.ETag, 0); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, db.PartMeta{
			PartNumber: int32(i + 1), StagingKey: staged.StagingKey,
			Size: staged.Size, ETag: staged.ETag,
		})
	}
	if _, err := f.store.CompleteMultipart(ctx, upload, parts); err != nil {
		t.Fatal(err)
	}

	if n := f.countUnder(t, storage.XorbPrefix); n != 1 {
		t.Errorf("%d stored xorbs, want 1", n)
	}
	if n, _ := f.refcount(t, hashABC); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
}

// The assembled object is chunked as one stream, so where the client split
// its parts moves no boundary: it dedups chunk for chunk against a single
// upload of the same bytes.
func TestCompleteMultipartChunksTheWholeObject(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	data := pseudoRandom("multipart chunks", 3<<20)
	uploadID, err := f.db.CreateMultipart(ctx, nsID, "k", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	upload, err := f.db.GetMultipart(ctx, nsID, "k", uploadID)
	if err != nil {
		t.Fatal(err)
	}
	var parts []db.PartMeta
	for i, cut := range [][2]int{{0, 1_000_003}, {1_000_003, 2_500_000}, {2_500_000, len(data)}} {
		staged, err := f.store.PutPart(ctx, upload, int32(i+1), bytes.NewReader(data[cut[0]:cut[1]]), -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(staged.Chunks) != 0 {
			t.Errorf("part %d was chunked on its own", i+1)
		}
		if _, err := f.db.PutPart(ctx, uploadID, int32(i+1), staged.StagingKey, staged.Size, staged.ETag, 0); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, db.PartMeta{PartNumber: int32(i + 1), StagingKey: staged.StagingKey, Size: staged.Size, ETag: staged.ETag})
	}
	if _, err := f.store.CompleteMultipart(ctx, upload, parts); err != nil {
		t.Fatal(err)
	}

	obj, err := f.db.GetObject(ctx, nsID, "k")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, c := range chunkAll(data, len(data)) {
		want = append(want, c.Hash)
	}
	if got := f.blobChunks(t, obj.BlobHash); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the assembled object holds %d chunks, want the %d a single upload cuts, in order", len(got), len(want))
	}
	got, err := f.readRange(t, obj.BlobHash, 0, obj.Size)
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back %d bytes, %v; want the %d uploaded", len(got), err, len(data))
	}
}

// Objects that share most of their bytes share most of their storage: an
// edit stores only the chunks around it, and the new version's terms reuse
// the old version's xorb for the rest.
func TestCommitSharesChunksBetweenSimilarObjects(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	data := pseudoRandom("similar", 4<<20)
	edited := bytes.Clone(data)
	copy(edited[2<<20:], "an edit in the middle")

	first, err := f.store.Stage(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "v1", "application/octet-stream", first); err != nil {
		t.Fatal(err)
	}
	second, err := f.store.Stage(ctx, bytes.NewReader(edited))
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.store.plan(ctx, second, nsID)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.decoys) != 0 {
		t.Error("runs the namespace already holds should not be written again")
	}
	if len(p.xorbs) != 1 || len(p.xorbs[0].chunks) > 3 {
		t.Errorf("planned %d new xorbs (%v), want one holding the few edited chunks", len(p.xorbs), p.xorbs)
	}
	if _, err := f.store.Commit(ctx, nsID, "v2", "application/octet-stream", second); err != nil {
		t.Fatal(err)
	}

	v1 := f.xorbsOf(t, first.Hash)
	v2 := f.xorbsOf(t, second.Hash)
	if len(v1) != 1 || len(v2) != 2 || !slices.Contains(v2, v1[0]) {
		t.Errorf("v1 uses %v and v2 %v, want v2 to reuse v1's xorb and add one", v1, v2)
	}
	if n, _ := f.xorbRefcount(t, v1[0]); n != 2 {
		t.Errorf("v1's xorb refcount = %d, want 2: both versions use it", n)
	}
	if n := f.driftedXorbs(t); n != 0 {
		t.Errorf("%d xorbs have a refcount that disagrees with their terms", n)
	}
	for key, want := range map[string][]byte{"v1": data, "v2": edited} {
		obj, err := f.db.GetObject(ctx, nsID, key)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.readRange(t, obj.BlobHash, 0, obj.Size); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s read back wrong: %v", key, err)
		}
	}
}

// A run of chunks only another namespace holds is reused, so it is stored
// once, but written all the same as a decoy; and a run too short to be worth
// a term is stored again rather than scattering the blob.
func TestPlanDecoysRunsOnlyOthersHoldAndSkipsShortRuns(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	mine := f.namespace(t, "mine", nil)
	theirs := f.namespace(t, "theirs", nil)

	data := pseudoRandom("theirs", 4<<20)
	if _, err := f.store.Commit(ctx, theirs, "k", "application/octet-stream", mustStage(t, f, data)); err != nil {
		t.Fatal(err)
	}

	// Most of their file, with an edit in the middle.
	edited := bytes.Clone(data)
	copy(edited[2<<20:], "an edit in the middle")
	staged := mustStage(t, f, edited)
	p, err := f.store.plan(ctx, staged, mine)
	if err != nil {
		t.Fatal(err)
	}
	var decoyed, fresh int
	for _, d := range p.decoys {
		decoyed += len(d)
	}
	for _, x := range p.xorbs {
		fresh += len(x.chunks)
	}
	if fresh > 3 || decoyed+fresh != len(staged.Chunks) {
		t.Errorf("%d chunks new and %d decoys of %d, want all but the edited ones reused and written as decoys",
			fresh, decoyed, len(staged.Chunks))
	}

	// Only a few chunks of theirs, fewer than a run.
	short := bytes.Clone(edited[:4*minChunk])
	short = append(short, pseudoRandom("mine", 1<<20)...)
	staged = mustStage(t, f, short)
	p, err = f.store.plan(ctx, staged, mine)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.decoys) != 0 {
		t.Errorf("a run shorter than %d chunks was reused", minDedupRun)
	}
	if _, err := f.store.Commit(ctx, mine, "short", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	if got, err := f.readRange(t, staged.Hash, 0, staged.Size); err != nil || !bytes.Equal(got, short) {
		t.Errorf("read back wrong: %v", err)
	}
}

func mustStage(t *testing.T, f *fixture, data []byte) StagedBlob {
	t.Helper()
	staged, err := f.store.Stage(t.Context(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return staged
}

// Bytes at a xorb's address with no row are what a failed commit leaves, and
// may be serialized differently from this commit's. The commit replaces them
// rather than trusting its own offsets into them.
func TestCommitReplacesAnOrphanedXorb(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if err := f.bucket.WriteAll(ctx, storage.XorbPath(xorbABC), []byte("not this commit's xorb"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "k", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.readRange(t, hashABC, 0, 3); err != nil || string(got) != "abc" {
		t.Errorf("read %q, %v; want abc", got, err)
	}
}

// Content stored before chunking keeps working: it copies, dedups and is
// read as the one file it is.
func TestWholeFileBlobsStillCopyAndDedup(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	f.putWholeFile(t, nsID, "old", "abc")
	src, err := f.db.GetObject(ctx, nsID, "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CopyObject(ctx, src, nsID, "copy"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "again", "text/plain", f.stage(t, "abc")); err != nil {
		t.Fatal(err)
	}

	if n, _ := f.refcount(t, hashABC); n != 3 {
		t.Errorf("refcount = %d, want 3 on the one whole-file blob", n)
	}
	if n := f.countUnder(t, storage.XorbPrefix); n != 0 {
		t.Errorf("%d xorbs stored, want none: the content is already stored whole", n)
	}
	if got, err := f.readRange(t, hashABC, 0, 3); err != nil || string(got) != "abc" {
		t.Errorf("read %q, %v; want abc", got, err)
	}
}
