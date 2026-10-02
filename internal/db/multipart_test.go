package db

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// age backdates an upload and its parts so the expiry sweep can see them.
func age(t *testing.T, d *DB, id uuid.UUID, seconds int) {
	t.Helper()
	_, err := d.pool.Exec(t.Context(),
		"UPDATE multipart_uploads SET created_at = now() - make_interval(secs => $2) WHERE id = $1",
		id, float64(seconds))
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.pool.Exec(t.Context(),
		"UPDATE multipart_parts SET created_at = now() - make_interval(secs => $2) WHERE upload_id = $1",
		id, float64(seconds))
	if err != nil {
		t.Fatal(err)
	}
}

// The upload id is a Postgres uuid; this also pins down that google/uuid values
// round-trip through pgx without a custom codec.
func TestMultipartCreateAndGet(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	id, err := d.CreateMultipart(ctx, nsID, "big.bin", "application/octet-stream")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected a generated upload id")
	}

	up, err := d.GetMultipart(ctx, nsID, "big.bin", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if up.ID != id || up.NamespaceID != nsID || up.Key != "big.bin" {
		t.Errorf("upload = %+v", up)
	}
	if up.ContentType != "application/octet-stream" {
		t.Errorf("content type = %q", up.ContentType)
	}

	// The namespace and key are part of the identity, not decoration.
	other := mustNamespace(t, d, "other", nil)
	if _, err := d.GetMultipart(ctx, other, "big.bin", id); !errors.Is(err, apperr.ErrNoSuchUpload) {
		t.Errorf("wrong namespace = %v, want ErrNoSuchUpload", err)
	}
	if _, err := d.GetMultipart(ctx, nsID, "other.bin", id); !errors.Is(err, apperr.ErrNoSuchUpload) {
		t.Errorf("wrong key = %v, want ErrNoSuchUpload", err)
	}
	if _, err := d.GetMultipart(ctx, nsID, "big.bin", uuid.New()); !errors.Is(err, apperr.ErrNoSuchUpload) {
		t.Errorf("unknown id = %v, want ErrNoSuchUpload", err)
	}
}

// Re-uploading a part must hand back the superseded staging key, or a retried
// part would orphan the first attempt's bytes.
func TestPutPartReplacementReturnsTheOldStagingKey(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	id, err := d.CreateMultipart(ctx, nsID, "big.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}

	replaced, err := d.PutPart(ctx, id, 1, "staging/first", 100, hashOf("p1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if replaced != "" {
		t.Errorf("first upload of a part replaced %q, want nothing", replaced)
	}

	replaced, err = d.PutPart(ctx, id, 1, "staging/second", 120, hashOf("p1b"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if replaced != "staging/first" {
		t.Errorf("replaced = %q, want staging/first", replaced)
	}

	parts, err := d.ListParts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0].StagingKey != "staging/second" || parts[0].Size != 120 {
		t.Errorf("parts = %+v, want the replacement only", parts)
	}
}

func TestListPartsPage(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	id, err := d.CreateMultipart(ctx, nsID, "big.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	for i := int32(1); i <= 5; i++ {
		if _, err := d.PutPart(ctx, id, i, "staging/p", 10, hashOf("p"), 0); err != nil {
			t.Fatal(err)
		}
	}

	page, err := d.ListPartsPage(ctx, id, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Parts) != 2 || !page.IsTruncated {
		t.Fatalf("first page = %d parts, truncated=%v", len(page.Parts), page.IsTruncated)
	}
	if page.Parts[0].PartNumber != 1 || page.Parts[1].PartNumber != 2 {
		t.Errorf("parts = %+v, want 1 and 2", page.Parts)
	}

	// Resume after the last part number returned.
	page, err = d.ListPartsPage(ctx, id, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Parts) != 3 || page.IsTruncated {
		t.Errorf("second page = %d parts, truncated=%v; want 3 and false", len(page.Parts), page.IsTruncated)
	}

	// The exact-fit case must not report truncation.
	page, err = d.ListPartsPage(ctx, id, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if page.IsTruncated {
		t.Error("a page holding every remaining part must not be truncated")
	}

	empty, err := d.ListPartsPage(ctx, id, 99, 10)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Parts == nil {
		t.Error("an empty page must be an empty slice, not nil")
	}
}

func TestListMultipartUploads(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	for _, key := range []string{"a/one", "a/two", "b/three"} {
		if _, err := d.CreateMultipart(ctx, nsID, key, "application/octet-stream"); err != nil {
			t.Fatal(err)
		}
	}

	all, err := d.ListMultipartUploads(ctx, nsID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("listed %d uploads, want 3", len(all))
	}
	if all[0].Key != "a/one" || all[2].Key != "b/three" {
		t.Errorf("uploads are not key-ordered: %+v", all)
	}

	scoped, err := d.ListMultipartUploads(ctx, nsID, "a/", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 2 {
		t.Errorf("prefix listing = %d, want 2", len(scoped))
	}

	none, err := d.ListMultipartUploads(ctx, nsID, "zz/", 100)
	if err != nil {
		t.Fatal(err)
	}
	if none == nil {
		t.Error("an empty listing must be an empty slice, not nil")
	}
}

func TestRemoveMultipartReturnsStagingKeys(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	id, err := d.CreateMultipart(ctx, nsID, "big.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutPart(ctx, id, 1, "staging/a", 10, hashOf("a"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutPart(ctx, id, 2, "staging/b", 10, hashOf("b"), 0); err != nil {
		t.Fatal(err)
	}

	keys, err := d.RemoveMultipart(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Errorf("returned %v, want both staging keys so the caller can free the bytes", keys)
	}
	if _, err := d.GetMultipart(ctx, nsID, "big.bin", id); !errors.Is(err, apperr.ErrNoSuchUpload) {
		t.Errorf("upload should be gone, got %v", err)
	}
	// Part rows cascade with the upload.
	parts, err := d.ListParts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 0 {
		t.Errorf("parts survived the upload: %+v", parts)
	}
}

// The staging sweeper deliberately refuses to collect part-referenced files, so
// this expiry sweep is the only thing that ever reclaims an abandoned upload.
func TestSweepMultipart(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	stale, err := d.CreateMultipart(ctx, nsID, "stale.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutPart(ctx, stale, 1, "staging/stale", 10, hashOf("s"), 0); err != nil {
		t.Fatal(err)
	}
	fresh, err := d.CreateMultipart(ctx, nsID, "fresh.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutPart(ctx, fresh, 1, "staging/fresh", 10, hashOf("f"), 0); err != nil {
		t.Fatal(err)
	}

	// Nothing is stale yet.
	swept, err := d.SweepMultipart(ctx, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if swept.Uploads != 0 {
		t.Fatalf("swept %d uploads, want 0 — nothing has expired", swept.Uploads)
	}

	age(t, d, stale, 7200)
	swept, err = d.SweepMultipart(ctx, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if swept.Uploads != 1 {
		t.Fatalf("swept %d uploads, want 1", swept.Uploads)
	}
	if len(swept.StagingKeys) != 1 || swept.StagingKeys[0] != "staging/stale" {
		t.Errorf("staging keys = %v, want [staging/stale]", swept.StagingKeys)
	}
	if _, err := d.GetMultipart(ctx, nsID, "fresh.bin", fresh); err != nil {
		t.Errorf("the fresh upload must survive: %v", err)
	}
}

// Recent activity on any part keeps an old upload alive: a slow multi-hour
// upload is not an abandoned one.
func TestSweepMultipartSparesRecentlyActiveUploads(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)

	id, err := d.CreateMultipart(ctx, nsID, "slow.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutPart(ctx, id, 1, "staging/old", 10, hashOf("o"), 0); err != nil {
		t.Fatal(err)
	}
	age(t, d, id, 7200)

	// A part uploaded just now resets the activity clock.
	if _, err := d.PutPart(ctx, id, 2, "staging/new", 10, hashOf("n"), 0); err != nil {
		t.Fatal(err)
	}

	swept, err := d.SweepMultipart(ctx, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if swept.Uploads != 0 {
		t.Errorf("swept %d uploads, want 0 — a part arrived within the window", swept.Uploads)
	}
}

func TestStagingKeyReferenced(t *testing.T) {
	d := testDB(t)
	ctx := t.Context()
	nsID := mustNamespace(t, d, "ns", nil)
	id, err := d.CreateMultipart(ctx, nsID, "big.bin", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutPart(ctx, id, 1, "staging/live", 10, hashOf("l"), 0); err != nil {
		t.Fatal(err)
	}

	ok, err := d.StagingKeyReferenced(ctx, "staging/live")
	if err != nil || !ok {
		t.Errorf("live part = %v, %v; want referenced", ok, err)
	}
	ok, err = d.StagingKeyReferenced(ctx, "staging/orphan")
	if err != nil || ok {
		t.Errorf("orphan = %v, %v; want unreferenced", ok, err)
	}
}
