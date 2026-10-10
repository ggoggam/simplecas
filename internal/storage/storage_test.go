package storage

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/config"
)

func TestBlobPathFansOut(t *testing.T) {
	const hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if got, want := BlobPath(hash), "blobs/af/13/"+hash; got != want {
		t.Errorf("BlobPath() = %q, want %q", got, want)
	}
	// A hash too short to fan out must degrade rather than panic.
	if got := BlobPath("ab"); got != "blobs/ab" {
		t.Errorf("BlobPath(short) = %q", got)
	}
}

func TestHashFromBlobPath(t *testing.T) {
	const hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if got, ok := HashFromBlobPath(BlobPath(hash)); !ok || got != hash {
		t.Errorf("HashFromBlobPath(BlobPath(h)) = %q, %v; want the hash back", got, ok)
	}
	// Nothing BlobPath would not have written for a BLAKE3 digest is a blob.
	for _, key := range []string{
		"blobs/ab",
		"blobs/README",
		"blobs/af/13/" + hash + ".tmp",
		"blobs/af/14/" + hash,
		"blobs/" + hash,
		"blobs/AF/13/" + strings.ToUpper(hash),
		"blobs/af/13/af13" + strings.Repeat("z", 60),
		"staging/af/13/" + hash,
	} {
		if got, ok := HashFromBlobPath(key); ok {
			t.Errorf("HashFromBlobPath(%q) = %q, want no hash", key, got)
		}
	}
}

func TestHashFromXorbPath(t *testing.T) {
	const hash = "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632"
	if got, want := XorbPath(hash), "xorbs/ee/a2/"+hash; got != want {
		t.Errorf("XorbPath() = %q, want %q", got, want)
	}
	if got, ok := HashFromXorbPath(XorbPath(hash)); !ok || got != hash {
		t.Errorf("HashFromXorbPath(XorbPath(h)) = %q, %v; want the hash back", got, ok)
	}
	for _, key := range []string{"xorbs/README", BlobPath(hash), "xorbs/ee/a2/" + hash + ".tmp"} {
		if got, ok := HashFromXorbPath(key); ok {
			t.Errorf("HashFromXorbPath(%q) = %q, want no hash", key, got)
		}
	}
}

func TestStagingPath(t *testing.T) {
	got := StagingPath("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if want := "staging/6ba7b810-9dad-11d1-80b4-00c04fd430c8"; got != want {
		t.Errorf("StagingPath() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, StagingPrefix) {
		t.Error("StagingPath must sit under StagingPrefix so the sweeper finds it")
	}
}

func TestKeyPrefix(t *testing.T) {
	tests := []struct{ name, root, want string }{
		{"empty means no prefix", "", ""},
		{"a bare slash means no prefix", "/", ""},
		{"whitespace only", "   ", ""},
		{"plain segment gains a trailing slash", "cas", "cas/"},
		{"leading and trailing slashes are trimmed", "/cas/", "cas/"},
		{"nested segments are preserved", "/a/b/", "a/b/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyPrefix(tc.root); got != tc.want {
				t.Errorf("keyPrefix(%q) = %q, want %q", tc.root, got, tc.want)
			}
		})
	}
}

func TestContainerURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.StorageConfig
		want string
	}{
		{
			"defaults to the public service domain",
			config.StorageConfig{AccountName: "acct", Container: "cas"},
			"https://acct.blob.core.windows.net/cas",
		},
		{
			"an explicit endpoint wins (emulator, sovereign cloud)",
			config.StorageConfig{Endpoint: "http://127.0.0.1:10000/devstoreaccount1", Container: "cas"},
			"http://127.0.0.1:10000/devstoreaccount1/cas",
		},
		{
			"a trailing slash on the endpoint is not doubled",
			config.StorageConfig{Endpoint: "https://host/", Container: "cas"},
			"https://host/cas",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerURL(tc.cfg); got != tc.want {
				t.Errorf("containerURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenRejectsUnknownBackend(t *testing.T) {
	if _, err := Open(t.Context(), config.StorageConfig{Backend: "ipfs"}); err == nil {
		t.Fatal("expected an error for an unknown backend")
	}
}

// openTestFS gives each test its own filesystem-backed bucket.
func openTestFS(t *testing.T) *Bucket {
	t.Helper()
	b, err := Open(t.Context(), config.StorageConfig{Backend: "fs", Root: t.TempDir()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func write(t *testing.T, b *Bucket, key, body string) {
	t.Helper()
	if err := b.WriteAll(t.Context(), key, []byte(body), nil); err != nil {
		t.Fatalf("write %s: %v", key, err)
	}
}

func TestOpenFSCreatesRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nested", "data")
	b, err := Open(t.Context(), config.StorageConfig{Backend: "fs", Root: root})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = b.Close() }()

	if _, err := os.Stat(root); err != nil {
		t.Errorf("root directory was not created: %v", err)
	}
	if err := b.Check(t.Context()); err != nil {
		t.Errorf("Check: %v", err)
	}
}

// The staging -> blobs promotion in the write path. Copy must leave the source
// in place, because the caller deletes staging separately and treats that
// delete as best-effort.
func TestCopyPromotesStagingToBlob(t *testing.T) {
	b := openTestFS(t)
	ctx := t.Context()

	const body = "content-addressed bytes"
	staging := StagingPath("upload-1")
	blobKey := BlobPath("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
	write(t, b, staging, body)

	if err := b.Copy(ctx, blobKey, staging, nil); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	got, err := b.ReadAll(ctx, blobKey)
	if err != nil {
		t.Fatalf("read the copy: %v", err)
	}
	if string(got) != body {
		t.Errorf("copied content = %q, want %q", got, body)
	}
	if ok, _ := b.Exists(ctx, staging); !ok {
		t.Error("Copy must not consume the source")
	}
}

// Range GETs serve object slices straight from the backend.
func TestRangeReader(t *testing.T) {
	b := openTestFS(t)
	key := BlobPath("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	write(t, b, key, "0123456789")

	r, err := b.NewRangeReader(t.Context(), key, 3, 4, nil)
	if err != nil {
		t.Fatalf("NewRangeReader: %v", err)
	}
	defer func() { _ = r.Close() }()

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "3456" {
		t.Errorf("range read = %q, want %q", got, "3456")
	}
}

// The staging sweeper lists this prefix and needs modification times; with
// fileblob's metadata sidecars suppressed, nothing but real staged files
// should appear.
func TestListStagingPrefix(t *testing.T) {
	b := openTestFS(t)
	ctx := t.Context()

	write(t, b, StagingPath("a"), "one")
	write(t, b, StagingPath("b"), "two")
	write(t, b, BlobPath("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), "elsewhere")

	var keys []string
	it := b.List(&blob.ListOptions{Prefix: StagingPrefix})
	for {
		obj, err := it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if obj.IsDir {
			continue
		}
		keys = append(keys, obj.Key)
		if obj.ModTime.IsZero() {
			t.Errorf("%s has no modification time; the sweeper needs one", obj.Key)
		}
	}

	if len(keys) != 2 {
		t.Fatalf("listed %v, want exactly the two staged files", keys)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, StagingPrefix) {
			t.Errorf("unexpected key %q outside the staging prefix", k)
		}
	}
}

func TestDelete(t *testing.T) {
	b := openTestFS(t)
	ctx := t.Context()
	key := StagingPath("gone")
	write(t, b, key, "x")

	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := b.Exists(ctx, key); ok {
		t.Error("key still present after Delete")
	}
}

// fileblob finalises a write by renaming a temporary file into place, and
// rename fails with EXDEV across mount points. The default temp location is
// os.TempDir, which in the normal deployment — a mounted volume for the blob
// directory — is on a different filesystem, so every upload would fail with
// "invalid cross-device link".
//
// Rather than trying to arrange two mount points, this makes the temp directory
// unusable: if writes still succeed, they are not going through it.
func TestFSWritesDoNotUseTheSystemTempDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the directory permissions this test relies on")
	}

	blocked := filepath.Join(t.TempDir(), "blocked-tmp")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })
	t.Setenv("TMPDIR", blocked)

	// Confirm the premise: the temp directory really is unusable.
	if _, err := os.CreateTemp("", "probe"); err == nil {
		t.Skip("the temp directory is still writable, so this test proves nothing")
	}

	b := openTestFS(t)
	const body = "content-addressed bytes"
	key := BlobPath("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")

	w, err := b.NewWriter(t.Context(), key, nil)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Close is where the rename happens, so this is the call that would fail.
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v — writes are still routed through os.TempDir", err)
	}

	got, err := b.ReadAll(t.Context(), key)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != body {
		t.Errorf("content = %q, want %q", got, body)
	}
}
