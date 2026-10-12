package db

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ggoggam/simplecas/internal/apperr"
)

func TestEscapeLike(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain prefix is untouched", "photos/", "photos/"},
		{"percent is escaped", "50%", `50\%`},
		{"underscore is escaped", "a_b", `a\_b`},
		{"backslash is escaped first", `a\b`, `a\\b`},
		{"combined", `a\%_`, `a\\\%\_`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := escapeLike(tc.in); got != tc.want {
				t.Errorf("escapeLike(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ClaimBlob reports whether the bytes need writing, which is what tells the
// write path it must upload them before committing.
func TestClaimBlobRefcounting(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	hash := hashOf("blob")

	var isNew bool
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		claim, err := ClaimBlob(ctx, tx, hash, 42, "")
		isNew = claim.Fresh
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("the first claim must report the blob as new")
	}
	if n, ok := refcount(t, d, hash); !ok || n != 1 {
		t.Errorf("refcount = %d (present=%v), want 1", n, ok)
	}

	// A second claim is an update, not an insert.
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		claim, err := ClaimBlob(ctx, tx, hash, 42, "")
		isNew = claim.NeedsBytes()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("a repeat claim must not ask for the bytes — a live reference vouches for them")
	}
	if n, _ := refcount(t, d, hash); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
}

// A whole-file blob revived from refcount 0 may be one whose bytes GC deleted
// before failing to commit the row's removal, so the claim has to ask for the
// bytes again rather than trust them. A chunked blob's manifest outlives its
// references and keeps its chunks, so its revival needs nothing.
func TestClaimBlobRevivalNeedsBytesOnlyForWholeFiles(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	for _, tc := range []struct {
		name      string
		wholeFile bool
		want      bool
	}{
		{"whole file", true, true},
		{"chunked", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash := hashOf("revived " + tc.name)
			putObject(t, d, nsID, tc.name, hash, 10)
			if tc.wholeFile {
				wholeFile(t, d, hash)
			}
			if _, err := d.DeleteObject(ctx, nsID, tc.name); err != nil {
				t.Fatal(err)
			}

			var claim BlobClaim
			err := d.InTx(ctx, func(tx pgx.Tx) error {
				var err error
				claim, err = ClaimBlob(ctx, tx, hash, 10, "")
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if !claim.Revived || claim.Fresh {
				t.Errorf("claim = %+v, want a revival", claim)
			}
			if got := claim.NeedsBytes(); got != tc.want {
				t.Errorf("NeedsBytes() = %v, want %v", got, tc.want)
			}
			if n, _ := refcount(t, d, hash); n != 1 {
				t.Errorf("refcount = %d, want 1", n)
			}
		})
	}
}

// A double release must not drive the count negative, which would hide the blob
// from the sweep forever.
func TestReleaseBlobFloorsAtZero(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	hash := hashOf("floor")

	err := d.InTx(ctx, func(tx pgx.Tx) error {
		if _, err := ClaimBlob(ctx, tx, hash, 1, ""); err != nil {
			return err
		}
		for range 3 {
			if err := ReleaseBlob(ctx, tx, hash); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := refcount(t, d, hash); n != 0 {
		t.Errorf("refcount = %d, want 0 (floored)", n)
	}
}

func TestClaimExistingBlob(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	hash := hashOf("existing")

	// Absent blob: the link fast path must decline rather than dangle.
	err := d.InTx(ctx, func(tx pgx.Tx) error {
		_, _, ok, err := ClaimExistingBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if ok {
			t.Error("claiming an absent blob should report ok=false")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Present blob: returns the authoritative stored size, not a caller's claim.
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		_, err := ClaimBlob(ctx, tx, hash, 4096, "")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		size, _, ok, err := ClaimExistingBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if !ok {
			t.Fatal("expected the stored blob to be claimable")
		}
		if size != 4096 {
			t.Errorf("size = %d, want the stored 4096", size)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := refcount(t, d, hash); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}

	// Zero-ref blob: its bytes may already be gone, and the link path has
	// nothing to restore them from, so it must decline.
	err = d.InTx(ctx, func(tx pgx.Tx) error {
		for range 2 {
			if err := ReleaseBlob(ctx, tx, hash); err != nil {
				return err
			}
		}
		_, _, ok, err := ClaimExistingBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if ok {
			t.Error("claiming a zero-ref blob should report ok=false")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := refcount(t, d, hash); n != 0 {
		t.Errorf("refcount = %d, want 0 — the declined claim must not count", n)
	}
}

func TestUpsertObjectOverwriteReleasesTheOldBlob(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	oldHash, newHash := hashOf("old"), hashOf("new")
	putObject(t, d, nsID, "k", oldHash, 10)
	putObject(t, d, nsID, "k", newHash, 20)

	if n, _ := refcount(t, d, oldHash); n != 0 {
		t.Errorf("old blob refcount = %d, want 0 after the overwrite", n)
	}
	if n, _ := refcount(t, d, newHash); n != 1 {
		t.Errorf("new blob refcount = %d, want 1", n)
	}

	obj, err := d.GetObject(ctx, nsID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if obj.BlobHash != newHash || obj.Size != 20 {
		t.Errorf("object = %+v, want the new blob", obj)
	}
}

// Overwriting an object with byte-identical content claims then releases the
// same blob, so the refcount must net out unchanged rather than creep upward.
func TestUpsertObjectIdenticalContentNetsOut(t *testing.T) {
	d := testDB(t)
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("same")

	putObject(t, d, nsID, "k", hash, 10)
	putObject(t, d, nsID, "k", hash, 10)
	putObject(t, d, nsID, "k", hash, 10)

	if n, _ := refcount(t, d, hash); n != 1 {
		t.Errorf("refcount = %d, want 1 — repeated identical writes must not inflate it", n)
	}
}

// Two keys pointing at identical content is the whole point: one blob, two
// references, one copy of the bytes.
func TestDedupSharesOneBlobAcrossNamespaces(t *testing.T) {
	d := testDB(t)
	a := mustNamespace(t, d, "ns-a", nil)
	b := mustNamespace(t, d, "ns-b", nil)
	hash := hashOf("shared")

	putObject(t, d, a, "one", hash, 100)
	putObject(t, d, b, "two", hash, 100)

	if n, _ := refcount(t, d, hash); n != 2 {
		t.Errorf("refcount = %d, want 2", n)
	}
	var blobs int
	if err := d.pool.QueryRow(t.Context(), "SELECT COUNT(*) FROM blobs").Scan(&blobs); err != nil {
		t.Fatal(err)
	}
	if blobs != 1 {
		t.Errorf("stored %d blob rows, want 1", blobs)
	}
}

func TestGetAndDeleteObject(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	hash := hashOf("del")

	if _, err := d.GetObject(ctx, nsID, "nope"); !errors.Is(err, apperr.ErrNoSuchKey) {
		t.Errorf("missing object = %v, want ErrNoSuchKey", err)
	}

	putObject(t, d, nsID, "k", hash, 5)
	existed, err := d.DeleteObject(ctx, nsID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Error("deleting a present key should report existed=true")
	}
	if n, _ := refcount(t, d, hash); n != 0 {
		t.Errorf("refcount = %d, want 0 after delete", n)
	}

	// Deleting again is a silent no-op, so S3's idempotent DELETE holds.
	existed, err = d.DeleteObject(ctx, nsID, "k")
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Error("deleting a missing key should report existed=false")
	}
}

// The link fast path must not become a cross-tenant existence oracle.
func TestBlobReferencedInTenant(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()

	mine, err := d.CreateTenant(ctx, "mine", mustUser(t, d, "me@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := d.CreateTenant(ctx, "theirs", mustUser(t, d, "them@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	theirNS := mustNamespace(t, d, "theirs-ns", &theirs)
	mustNamespace(t, d, "mine-ns", &mine)

	hash := hashOf("theirsecret")
	putObject(t, d, theirNS, "secret", hash, 9)

	err = d.InTx(ctx, func(tx pgx.Tx) error {
		theirsSees, err := BlobReferencedInTenant(ctx, tx, hash, theirs)
		if err != nil {
			return err
		}
		if !theirsSees {
			t.Error("the owning tenant should see its own content")
		}
		mineSees, err := BlobReferencedInTenant(ctx, tx, hash, mine)
		if err != nil {
			return err
		}
		if mineSees {
			t.Error("another tenant's content must not be visible to the link path")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

func keysOf(objs []ObjectMeta) []string {
	out := make([]string, len(objs))
	for i, o := range objs {
		out[i] = o.Key
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestListObjects(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	for _, k := range []string{
		"a.txt",
		"photos/2024/one.jpg",
		"photos/2024/two.jpg",
		"photos/2025/three.jpg",
		"photos/loose.jpg",
		"z.txt",
	} {
		putObject(t, d, nsID, k, hashOf(k), 1)
	}

	t.Run("flat listing is byte-ordered", func(t *testing.T) {
		got, err := d.ListObjects(ctx, nsID, "", 0, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"a.txt", "photos/2024/one.jpg", "photos/2024/two.jpg",
			"photos/2025/three.jpg", "photos/loose.jpg", "z.txt"}
		if !equal(keysOf(got.Objects), want) {
			t.Errorf("keys = %v, want %v", keysOf(got.Objects), want)
		}
		if got.IsTruncated {
			t.Error("should not be truncated")
		}
		if len(got.CommonPrefixes) != 0 {
			t.Errorf("common prefixes = %v, want none without a delimiter", got.CommonPrefixes)
		}
	})

	t.Run("prefix filters", func(t *testing.T) {
		got, err := d.ListObjects(ctx, nsID, "photos/2024/", 0, "", 100)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"photos/2024/one.jpg", "photos/2024/two.jpg"}
		if !equal(keysOf(got.Objects), want) {
			t.Errorf("keys = %v, want %v", keysOf(got.Objects), want)
		}
	})

	t.Run("delimiter groups into common prefixes", func(t *testing.T) {
		got, err := d.ListObjects(ctx, nsID, "", '/', "", 100)
		if err != nil {
			t.Fatal(err)
		}
		if !equal(keysOf(got.Objects), []string{"a.txt", "z.txt"}) {
			t.Errorf("keys = %v, want the two top-level objects", keysOf(got.Objects))
		}
		if !equal(got.CommonPrefixes, []string{"photos/"}) {
			t.Errorf("common prefixes = %v, want [photos/]", got.CommonPrefixes)
		}
	})

	t.Run("delimiter one level down", func(t *testing.T) {
		got, err := d.ListObjects(ctx, nsID, "photos/", '/', "", 100)
		if err != nil {
			t.Fatal(err)
		}
		if !equal(keysOf(got.Objects), []string{"photos/loose.jpg"}) {
			t.Errorf("keys = %v, want [photos/loose.jpg]", keysOf(got.Objects))
		}
		want := []string{"photos/2024/", "photos/2025/"}
		if !equal(got.CommonPrefixes, want) {
			t.Errorf("common prefixes = %v, want %v", got.CommonPrefixes, want)
		}
	})

	t.Run("empty results are empty slices, not nil", func(t *testing.T) {
		got, err := d.ListObjects(ctx, nsID, "nothing/", '/', "", 100)
		if err != nil {
			t.Fatal(err)
		}
		if got.Objects == nil || got.CommonPrefixes == nil {
			t.Error("nil slices would serialise as JSON null and break the PWA")
		}
	})
}

// Paging must walk the whole keyspace exactly once, with no gaps or repeats.
func TestListObjectsPagination(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	want := []string{"k1", "k2", "k3", "k4", "k5"}
	for _, k := range want {
		putObject(t, d, nsID, k, hashOf(k), 1)
	}

	var seen []string
	marker := ""
	for range 10 {
		page, err := d.ListObjects(ctx, nsID, "", 0, marker, 2)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, keysOf(page.Objects)...)
		if !page.IsTruncated {
			break
		}
		if page.NextMarker == "" {
			t.Fatal("a truncated page must carry a resume marker")
		}
		marker = page.NextMarker
	}
	if !equal(seen, want) {
		t.Errorf("paged through %v, want %v", seen, want)
	}
}

// Truncation counts common prefixes toward the limit, and resuming past a
// group must not re-emit it.
func TestListObjectsPaginationAcrossGroups(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	for _, k := range []string{"a/1", "a/2", "b/1", "c/1", "d"} {
		putObject(t, d, nsID, k, hashOf(k), 1)
	}

	var prefixes, objects []string
	marker := ""
	for range 10 {
		page, err := d.ListObjects(ctx, nsID, "", '/', marker, 1)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, page.CommonPrefixes...)
		objects = append(objects, keysOf(page.Objects)...)
		if !page.IsTruncated {
			break
		}
		marker = page.NextMarker
	}

	if !equal(prefixes, []string{"a/", "b/", "c/"}) {
		t.Errorf("prefixes = %v, want [a/ b/ c/] exactly once each", prefixes)
	}
	if !equal(objects, []string{"d"}) {
		t.Errorf("objects = %v, want [d]", objects)
	}
}

// A prefix containing LIKE metacharacters must match literally.
func TestListObjectsEscapesLikeMetacharacters(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	for _, k := range []string{"50%/real", "50x/decoy", "a_b/real", "axb/decoy"} {
		putObject(t, d, nsID, k, hashOf(k), 1)
	}

	got, err := d.ListObjects(ctx, nsID, "50%/", 0, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(keysOf(got.Objects), []string{"50%/real"}) {
		t.Errorf("%% prefix matched %v, want only the literal match", keysOf(got.Objects))
	}

	got, err = d.ListObjects(ctx, nsID, "a_b/", 0, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !equal(keysOf(got.Objects), []string{"a_b/real"}) {
		t.Errorf("_ prefix matched %v, want only the literal match", keysOf(got.Objects))
	}
}
