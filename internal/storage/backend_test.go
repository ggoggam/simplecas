package storage_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"

	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testblob"
)

// The behaviour the store relies on from every backend, checked on fs and,
// when SIMPLECAS_TEST_S3_URL is set, on a real S3 store. The fs-only details
// (temp files, sidecars) are covered in storage_test.go.
func TestBackendContract(t *testing.T) {
	backends := map[string]func(*testing.T) *storage.Bucket{
		"fs": openFS,
		"s3": testblob.OpenS3,
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			t.Run("check", func(t *testing.T) {
				if err := open(t).Check(t.Context()); err != nil {
					t.Fatalf("Check: %v", err)
				}
			})
			t.Run("copy leaves the source", func(t *testing.T) { testCopy(t, open(t)) })
			t.Run("range reads", func(t *testing.T) { testRange(t, open(t)) })
			t.Run("listing has modification times", func(t *testing.T) { testList(t, open(t)) })
			t.Run("missing keys are NotFound", func(t *testing.T) { testNotFound(t, open(t)) })
			t.Run("delete", func(t *testing.T) { testDelete(t, open(t)) })
			t.Run("put once", func(t *testing.T) { testPutOnce(t, open(t)) })
		})
	}
}

// Two stores opened on the same S3 bucket under different roots must not see
// each other's keys: the root is the only thing keeping two deployments, or
// two tests, apart.
func TestS3RootIsolatesKeys(t *testing.T) {
	a, b := testblob.OpenS3(t), testblob.OpenS3(t)
	ctx := t.Context()
	write(t, a, storage.StagingPath("mine"), "a")

	if ok, err := b.Exists(ctx, storage.StagingPath("mine")); err != nil || ok {
		t.Fatalf("Exists under another root = %v, %v; want false", ok, err)
	}
	if keys := list(t, b, ""); len(keys) != 0 {
		t.Fatalf("another root lists %v, want nothing", keys)
	}
}

func openFS(t *testing.T) *storage.Bucket {
	b, err := storage.Open(t.Context(), config.StorageConfig{Backend: "fs", Root: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

const hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"

func testCopy(t *testing.T, b *storage.Bucket) {
	ctx := t.Context()
	staging, blobKey := storage.StagingPath("upload-1"), storage.BlobPath(hash)
	write(t, b, staging, "content-addressed bytes")

	if err := b.Copy(ctx, blobKey, staging, nil); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if got := read(t, b, blobKey); got != "content-addressed bytes" {
		t.Errorf("copy = %q", got)
	}
	if ok, _ := b.Exists(ctx, staging); !ok {
		t.Error("Copy must not consume the source")
	}
}

func testRange(t *testing.T, b *storage.Bucket) {
	key := storage.BlobPath(hash)
	write(t, b, key, "0123456789")

	for _, tc := range []struct {
		offset, length int64
		want           string
	}{
		{3, 4, "3456"},
		{0, 1, "0"},
		{7, -1, "789"}, // to the end
		{9, 5, "9"},    // past the end is cut short, not refused
	} {
		r, err := b.NewRangeReader(t.Context(), key, tc.offset, tc.length, nil)
		if err != nil {
			t.Fatalf("NewRangeReader(%d, %d): %v", tc.offset, tc.length, err)
		}
		got, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatalf("read (%d, %d): %v", tc.offset, tc.length, err)
		}
		if string(got) != tc.want {
			t.Errorf("range (%d, %d) = %q, want %q", tc.offset, tc.length, got, tc.want)
		}
	}
}

// The staging and orphan sweeps list a prefix and age what they find by its
// modification time.
func testList(t *testing.T, b *storage.Bucket) {
	ctx := t.Context()
	before := time.Now().Add(-time.Minute)
	write(t, b, storage.StagingPath("a"), "one")
	write(t, b, storage.StagingPath("b"), "two")
	write(t, b, storage.BlobPath(hash), "elsewhere")

	it := b.List(&blob.ListOptions{Prefix: storage.StagingPrefix})
	var keys []string
	for {
		obj, err := it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		keys = append(keys, obj.Key)
		if obj.ModTime.Before(before) || obj.ModTime.After(time.Now().Add(time.Minute)) {
			t.Errorf("%s ModTime = %v, want about now", obj.Key, obj.ModTime)
		}
	}
	if len(keys) != 2 || keys[0] != storage.StagingPath("a") || keys[1] != storage.StagingPath("b") {
		t.Errorf("listed %v, want the two staged keys in order", keys)
	}
}

// The store treats NotFound from a read or a delete as "already gone".
func testNotFound(t *testing.T, b *storage.Bucket) {
	ctx := t.Context()
	key := storage.BlobPath(hash)
	if _, err := b.NewReader(ctx, key, nil); gcerrors.Code(err) != gcerrors.NotFound {
		t.Errorf("NewReader of a missing key: %v, want NotFound", err)
	}
	if _, err := b.Attributes(ctx, key); gcerrors.Code(err) != gcerrors.NotFound {
		t.Errorf("Attributes of a missing key: %v, want NotFound", err)
	}
}

func testDelete(t *testing.T, b *storage.Bucket) {
	ctx := t.Context()
	key := storage.StagingPath("gone")
	write(t, b, key, "x")
	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := b.Exists(ctx, key); ok {
		t.Error("key still present after Delete")
	}
}

func write(t *testing.T, b *storage.Bucket, key, body string) {
	t.Helper()
	if err := b.WriteAll(t.Context(), key, []byte(body), nil); err != nil {
		t.Fatalf("write %s: %v", key, err)
	}
}

func read(t *testing.T, b *storage.Bucket, key string) string {
	t.Helper()
	got, err := b.ReadAll(t.Context(), key)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return string(got)
}

func list(t *testing.T, b *storage.Bucket, prefix string) []string {
	t.Helper()
	ctx := context.Background()
	var keys []string
	it := b.List(&blob.ListOptions{Prefix: prefix})
	for {
		obj, err := it.Next(ctx)
		if err == io.EOF {
			return keys
		}
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		keys = append(keys, obj.Key)
	}
}

// PutOnce writes under the bucket's root like every other call, and with
// ifNew leaves an existing object alone.
func testPutOnce(t *testing.T, b *storage.Bucket) {
	ctx := t.Context()
	key := storage.XorbPath(hash)
	if err := b.PutOnce(ctx, key, []byte("first"), true); err != nil {
		t.Fatalf("PutOnce: %v", err)
	}
	if err := b.PutOnce(ctx, key, []byte("second"), true); !errors.Is(err, storage.ErrExists) {
		t.Errorf("a second ifNew PutOnce = %v, want ErrExists", err)
	}
	if got, err := b.ReadAll(ctx, key); err != nil || string(got) != "first" {
		t.Errorf("read %q, %v; want the first write kept", got, err)
	}
	if err := b.PutOnce(ctx, key, []byte("replaced"), false); err != nil {
		t.Fatalf("PutOnce: %v", err)
	}
	if got, err := b.ReadAll(ctx, key); err != nil || string(got) != "replaced" {
		t.Errorf("read %q, %v; want the unconditional write", got, err)
	}
}
