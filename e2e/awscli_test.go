package e2e

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// aws s3 — the high-level commands
// ---------------------------------------------------------------------------

func TestBucketCommands(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)

	aws.run("s3", "mb", "s3://alpha")
	aws.run("s3api", "create-bucket", "--bucket", "beta")

	if got := lsNames(aws.run("s3", "ls")); !slices.Equal(got, []string{"alpha", "beta"}) {
		t.Fatalf("s3 ls = %v, want [alpha beta]", got)
	}
	var buckets struct{ Buckets []struct{ Name string } }
	aws.json(&buckets, "s3api", "list-buckets")
	if len(buckets.Buckets) != 2 {
		t.Fatalf("list-buckets = %+v, want two buckets", buckets)
	}

	aws.run("s3api", "head-bucket", "--bucket", "alpha")
	aws.run("s3api", "get-bucket-location", "--bucket", "alpha")
	aws.fails("BucketAlreadyOwnedByYou", "s3api", "create-bucket", "--bucket", "alpha")
	aws.fails("404", "s3api", "head-bucket", "--bucket", "missing")
	aws.fails("InvalidBucketName", "s3", "mb", "s3://Not_Valid")
	aws.fails("InvalidBucketName", "s3api", "create-bucket", "--bucket", "healthz")

	file := writeFile(t, t.TempDir(), "k.txt", []byte("keep me"))
	aws.run("s3", "cp", file, "s3://alpha/k.txt")
	aws.fails("BucketNotEmpty", "s3", "rb", "s3://alpha")

	aws.run("s3", "rb", "s3://alpha", "--force")
	aws.run("s3", "rb", "s3://beta")
	if got := lsNames(aws.run("s3", "ls")); len(got) != 0 {
		t.Fatalf("s3 ls after rb = %v, want none", got)
	}
}

func TestCopyUpAndDown(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	dir := t.TempDir()
	aws.run("s3", "mb", "s3://docs")

	content := []byte("hello, simplecas\n")
	aws.run("s3", "cp", writeFile(t, dir, "hello.txt", content), "s3://docs/hello.txt")

	h := aws.head("docs", "hello.txt")
	if h.ContentLength != int64(len(content)) || h.ETag != etagOf(content) {
		t.Errorf("head-object = %+v, want %d bytes with etag %s", h, len(content), etagOf(content))
	}
	// The CLI guesses the type from the extension.
	if h.ContentType != "text/plain" {
		t.Errorf("content type = %q, want text/plain", h.ContentType)
	}
	// The CLI reports metadata names as they arrive, so this also checks the
	// header is sent in S3's lowercase rather than Go's canonical case.
	if want := strings.Trim(etagOf(content), `"`); h.Metadata["blake3"] != want {
		t.Errorf("metadata = %v, want blake3 = %s", h.Metadata, want)
	}

	out := filepath.Join(dir, "out.txt")
	aws.run("s3", "cp", "s3://docs/hello.txt", out)
	sameBytes(t, "downloaded hello.txt", readFile(t, out), content)

	// An explicit type wins over the guess.
	aws.run("s3", "cp", writeFile(t, dir, "data.bin", []byte(`{"a":1}`)), "s3://docs/data.bin",
		"--content-type", "application/json")
	if h := aws.head("docs", "data.bin"); h.ContentType != "application/json" {
		t.Errorf("content type = %q, want application/json", h.ContentType)
	}

	// Identical content dedups to the same blob, so the ETag repeats.
	aws.run("s3", "cp", writeFile(t, dir, "again.txt", content), "s3://docs/copies/again.txt")
	if h := aws.head("docs", "copies/again.txt"); h.ETag != etagOf(content) {
		t.Errorf("duplicate etag = %s, want %s", h.ETag, etagOf(content))
	}

	aws.run("s3", "cp", writeFile(t, dir, "empty", nil), "s3://docs/empty")
	if h := aws.head("docs", "empty"); h.ContentLength != 0 {
		t.Errorf("empty object length = %d", h.ContentLength)
	}
	aws.run("s3", "cp", "s3://docs/empty", filepath.Join(dir, "empty.out"))
	sameBytes(t, "downloaded empty", readFile(t, filepath.Join(dir, "empty.out")), nil)

	aws.fails("404", "s3", "cp", "s3://docs/missing", filepath.Join(dir, "missing"))
}

// Keys that need escaping in a URL path must survive the round trip intact.
func TestAwkwardKeys(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	aws.run("s3", "mb", "s3://keys")

	keys := []string{
		"with space/file name.txt",
		"unicode/üñí€😀.txt",
		"plus+sign",
		"percent%20literal",
		"equals=and&amp",
		"double//slash",
		"trailing-dot.",
	}
	file := writeFile(t, t.TempDir(), "body", []byte("awkward"))
	for _, key := range keys {
		aws.run("s3api", "put-object", "--bucket", "keys", "--key", key, "--body", file)
	}

	var listing struct{ Contents []struct{ Key string } }
	aws.json(&listing, "s3api", "list-objects-v2", "--bucket", "keys")
	var got []string
	for _, c := range listing.Contents {
		got = append(got, c.Key)
	}
	want := slices.Sorted(slices.Values(keys))
	if !slices.Equal(got, want) {
		t.Fatalf("listed keys = %q, want %q", got, want)
	}

	for _, key := range keys {
		sameBytes(t, key, aws.download("keys", key), []byte("awkward"))
	}
}

// Past the 5 MiB threshold the CLI switches to a multipart upload, and to
// ranged GETs on the way back down.
func TestMultipartUploadAndDownload(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	dir := t.TempDir()
	aws.run("s3", "mb", "s3://big")

	content := randomBytes(12<<20+123, 1) // three parts, the last one short
	aws.run("s3", "cp", writeFile(t, dir, "big.bin", content), "s3://big/big.bin")

	h := aws.head("big", "big.bin")
	if h.ContentLength != int64(len(content)) || h.ETag != etagOf(content) {
		t.Errorf("head-object = %+v, want %d bytes with etag %s", h, len(content), etagOf(content))
	}

	out := filepath.Join(dir, "big.out")
	aws.run("s3", "cp", "s3://big/big.bin", out)
	sameBytes(t, "downloaded big.bin", readFile(t, out), content)

	var uploads struct{ Uploads []struct{ UploadId string } }
	aws.json(&uploads, "s3api", "list-multipart-uploads", "--bucket", "big")
	if len(uploads.Uploads) != 0 {
		t.Errorf("uploads left open after cp: %+v", uploads.Uploads)
	}
}

// `cp -` uploads a stream of unknown length; `cp … -` writes to stdout.
func TestStdinAndStdout(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	aws.run("s3", "mb", "s3://pipe")

	small := []byte("piped in\n")
	aws.runStdin(small, "s3", "cp", "-", "s3://pipe/small")
	sameBytes(t, "small via stdout", []byte(aws.run("s3", "cp", "s3://pipe/small", "-")), small)

	// Larger than one chunk, so the CLI has to multipart a stream it cannot
	// size up front.
	large := randomBytes(partSize+partSize/2, 2)
	aws.runStdin(large, "s3", "cp", "-", "s3://pipe/large")
	if h := aws.head("pipe", "large"); h.ETag != etagOf(large) {
		t.Errorf("streamed etag = %s, want %s", h.ETag, etagOf(large))
	}
	sameBytes(t, "large via stdout", []byte(aws.run("s3", "cp", "s3://pipe/large", "-")), large)
}

func TestListing(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	aws.run("s3", "mb", "s3://tree")

	src := t.TempDir()
	for _, name := range []string{"top.txt", "a/1.txt", "a/2.txt", "b/c/3.txt"} {
		writeFile(t, src, name, []byte(name))
	}
	aws.run("s3", "cp", src, "s3://tree/", "--recursive")

	if got, want := lsNames(aws.run("s3", "ls", "s3://tree/")), []string{"a/", "b/", "top.txt"}; !slices.Equal(got, want) {
		t.Errorf("s3 ls = %v, want %v", got, want)
	}
	if got, want := lsNames(aws.run("s3", "ls", "s3://tree/a/")), []string{"1.txt", "2.txt"}; !slices.Equal(got, want) {
		t.Errorf("s3 ls a/ = %v, want %v", got, want)
	}
	all := []string{"a/1.txt", "a/2.txt", "b/c/3.txt", "top.txt"}
	if got := lsNames(aws.run("s3", "ls", "s3://tree/", "--recursive")); !slices.Equal(got, all) {
		t.Errorf("s3 ls --recursive = %v, want %v", got, all)
	}
	if out := aws.run("s3", "ls", "s3://tree/", "--recursive", "--summarize"); !strings.Contains(out, "Total Objects: 4") {
		t.Errorf("--summarize output lacks the object count:\n%s", out)
	}

	type listing struct {
		Contents       []struct{ Key string }
		CommonPrefixes []struct{ Prefix string }
		NextToken      string
	}
	keys := func(l listing) []string {
		var out []string
		for _, c := range l.Contents {
			out = append(out, c.Key)
		}
		return out
	}

	var l listing
	aws.json(&l, "s3api", "list-objects-v2", "--bucket", "tree", "--delimiter", "/")
	var prefixes []string
	for _, p := range l.CommonPrefixes {
		prefixes = append(prefixes, p.Prefix)
	}
	if !slices.Equal(keys(l), []string{"top.txt"}) || !slices.Equal(prefixes, []string{"a/", "b/"}) {
		t.Errorf("delimited listing: keys %v prefixes %v", keys(l), prefixes)
	}

	l = listing{}
	aws.json(&l, "s3api", "list-objects-v2", "--bucket", "tree", "--prefix", "a/")
	if got := keys(l); !slices.Equal(got, []string{"a/1.txt", "a/2.txt"}) {
		t.Errorf("--prefix a/ = %v", got)
	}

	// One key per page: the CLI follows the continuation tokens itself.
	l = listing{}
	aws.json(&l, "s3api", "list-objects-v2", "--bucket", "tree", "--page-size", "1")
	if got := keys(l); !slices.Equal(got, all) {
		t.Errorf("list-objects-v2 --page-size 1 = %v, want %v", got, all)
	}

	// V1 pages on markers rather than tokens.
	l = listing{}
	aws.json(&l, "s3api", "list-objects", "--bucket", "tree", "--page-size", "1")
	if got := keys(l); !slices.Equal(got, all) {
		t.Errorf("list-objects --page-size 1 = %v, want %v", got, all)
	}

	// Client-side truncation hands back a token to resume from.
	var first, rest listing
	aws.json(&first, "s3api", "list-objects-v2", "--bucket", "tree", "--max-items", "2", "--page-size", "1")
	if first.NextToken == "" {
		t.Fatalf("--max-items 2 returned no NextToken: %+v", first)
	}
	aws.json(&rest, "s3api", "list-objects-v2", "--bucket", "tree", "--starting-token", first.NextToken)
	if got := append(keys(first), keys(rest)...); !slices.Equal(got, all) {
		t.Errorf("resumed listing = %v, want %v", got, all)
	}
}

func TestSync(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	aws.run("s3", "mb", "s3://mirror")

	src := t.TempDir()
	writeFile(t, src, "keep.txt", []byte("keep"))
	writeFile(t, src, "gone.txt", []byte("gone"))
	writeFile(t, src, "sub/nested.txt", []byte("nested"))
	aws.run("s3", "sync", src, "s3://mirror/")

	if got, want := lsNames(aws.run("s3", "ls", "s3://mirror/", "--recursive")),
		[]string{"gone.txt", "keep.txt", "sub/nested.txt"}; !slices.Equal(got, want) {
		t.Fatalf("after first sync: %v, want %v", got, want)
	}

	// Nothing changed locally, so a second sync must transfer nothing. That
	// depends on the server's sizes and LastModified times reading back right.
	if out := aws.run("s3", "sync", src, "s3://mirror/"); strings.TrimSpace(out) != "" {
		t.Errorf("no-op sync transferred something:\n%s", out)
	}

	writeFile(t, src, "keep.txt", []byte("keep, but longer"))
	writeFile(t, src, "new.txt", []byte("new"))
	if err := os.Remove(filepath.Join(src, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	aws.run("s3", "sync", src, "s3://mirror/", "--delete")

	if got, want := lsNames(aws.run("s3", "ls", "s3://mirror/", "--recursive")),
		[]string{"keep.txt", "new.txt", "sub/nested.txt"}; !slices.Equal(got, want) {
		t.Fatalf("after sync --delete: %v, want %v", got, want)
	}

	dst := t.TempDir()
	aws.run("s3", "sync", "s3://mirror/", dst)
	for _, name := range []string{"keep.txt", "new.txt", "sub/nested.txt"} {
		sameBytes(t, name, readFile(t, filepath.Join(dst, name)), readFile(t, filepath.Join(src, name)))
	}
	if _, err := os.Stat(filepath.Join(dst, "gone.txt")); !os.IsNotExist(err) {
		t.Errorf("gone.txt was synced down: %v", err)
	}
}

// Copies between buckets are server-side: CopyObject for small objects and
// UploadPartCopy past the multipart threshold. The CLI reads the source's tags
// first, so GetObjectTagging has to answer too.
func TestCopyAndMoveBetweenBuckets(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	dir := t.TempDir()
	aws.run("s3", "mb", "s3://src")
	aws.run("s3", "mb", "s3://dst")

	small := []byte("small object")
	large := randomBytes(11<<20, 3)
	aws.run("s3", "cp", writeFile(t, dir, "small", small), "s3://src/small")
	aws.run("s3", "cp", writeFile(t, dir, "large", large), "s3://src/large")
	aws.run("s3", "cp", writeFile(t, dir, "move-me", []byte("moving")), "s3://src/move-me")

	aws.run("s3", "cp", "s3://src/small", "s3://dst/small")
	sameBytes(t, "copied small", aws.download("dst", "small"), small)

	aws.run("s3", "cp", "s3://src/large", "s3://dst/large")
	if h := aws.head("dst", "large"); h.ETag != etagOf(large) {
		t.Errorf("multipart-copied etag = %s, want %s", h.ETag, etagOf(large))
	}
	sameBytes(t, "copied large", aws.download("dst", "large"), large)

	aws.run("s3", "mv", "s3://src/move-me", "s3://dst/moved")
	sameBytes(t, "moved", aws.download("dst", "moved"), []byte("moving"))
	aws.fails("404", "s3api", "head-object", "--bucket", "src", "--key", "move-me")

	aws.run("s3", "cp", "s3://src/", "s3://dst/backup/", "--recursive")
	if got, want := lsNames(aws.run("s3", "ls", "s3://dst/backup/")), []string{"large", "small"}; !slices.Equal(got, want) {
		t.Errorf("recursive copy = %v, want %v", got, want)
	}

	aws.run("s3", "mb", "s3://replica")
	aws.run("s3", "sync", "s3://src/", "s3://replica/")
	if got, want := lsNames(aws.run("s3", "ls", "s3://replica/")), []string{"large", "small"}; !slices.Equal(got, want) {
		t.Errorf("bucket-to-bucket sync = %v, want %v", got, want)
	}
}

// The copy cases the bucket-to-bucket test does not reach: copies within one
// bucket, over an existing key, out of awkward keys, with filters, and the
// failures.
func TestCopy(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	dir := t.TempDir()
	aws.run("s3", "mb", "s3://copies")
	aws.run("s3", "mb", "s3://elsewhere")

	original := []byte(`{"version":1}`)
	aws.run("s3", "cp", writeFile(t, dir, "orig.json", original), "s3://copies/orig.json")

	// Within one bucket, keeping the source's content type.
	aws.run("s3", "cp", "s3://copies/orig.json", "s3://copies/dup.json")
	h := aws.head("copies", "dup.json")
	if h.ETag != etagOf(original) || h.ContentType != "application/json" {
		t.Errorf("same-bucket copy = %+v, want etag %s and application/json", h, etagOf(original))
	}

	// --content-type on an s3-to-s3 copy sends the REPLACE directive.
	aws.run("s3", "cp", "s3://copies/orig.json", "s3://elsewhere/orig.txt", "--content-type", "text/plain")
	if h := aws.head("elsewhere", "orig.txt"); h.ContentType != "text/plain" || h.ETag != etagOf(original) {
		t.Errorf("copy with --content-type = %+v, want text/plain and etag %s", h, etagOf(original))
	}
	aws.run("s3api", "copy-object", "--bucket", "elsewhere", "--key", "orig.bin",
		"--copy-source", "copies/orig.json",
		"--metadata-directive", "REPLACE", "--content-type", "application/octet-stream")
	if h := aws.head("elsewhere", "orig.bin"); h.ContentType != "application/octet-stream" {
		t.Errorf("copy-object REPLACE content type = %q", h.ContentType)
	}
	if h := aws.head("copies", "orig.json"); h.ContentType != "application/json" {
		t.Errorf("source content type changed to %q by a REPLACE copy", h.ContentType)
	}

	// Over an existing key: the destination takes the source's bytes.
	aws.run("s3", "cp", writeFile(t, dir, "target", []byte("to be replaced")), "s3://copies/target")
	aws.run("s3", "cp", "s3://copies/orig.json", "s3://copies/target")
	sameBytes(t, "overwritten by copy", aws.download("copies", "target"), original)

	// A copy shares the blob but not the object: removing either side
	// leaves the other intact.
	aws.run("s3", "rm", "s3://copies/orig.json")
	sameBytes(t, "copy after source deleted", aws.download("copies", "dup.json"), original)
	aws.run("s3", "cp", "s3://copies/dup.json", "s3://copies/orig.json")
	aws.run("s3", "rm", "s3://copies/dup.json")
	sameBytes(t, "source after copy deleted", aws.download("copies", "orig.json"), original)

	// x-amz-copy-source is URL-encoded, so awkward source keys must decode.
	for _, key := range []string{"with space/name.txt", "unicode/üñí.txt", "plus+sign", "percent%2Fliteral"} {
		aws.run("s3api", "put-object", "--bucket", "copies", "--key", key,
			"--body", writeFile(t, dir, "awkward", []byte(key)))
		aws.run("s3", "cp", "s3://copies/"+key, "s3://elsewhere/"+key)
		sameBytes(t, "copied "+key, aws.download("elsewhere", key), []byte(key))
	}

	// Recursive copies honour the CLI's include/exclude filters.
	for _, name := range []string{"logs/a.log", "logs/b.log", "logs/keep.txt"} {
		aws.run("s3", "cp", writeFile(t, dir, name, []byte(name)), "s3://copies/"+name)
	}
	aws.run("s3", "cp", "s3://copies/logs/", "s3://elsewhere/logs/", "--recursive",
		"--exclude", "*", "--include", "*.log")
	if got, want := lsNames(aws.run("s3", "ls", "s3://elsewhere/logs/")), []string{"a.log", "b.log"}; !slices.Equal(got, want) {
		t.Errorf("filtered recursive copy = %v, want %v", got, want)
	}

	// And down to a local directory.
	local := t.TempDir()
	aws.run("s3", "cp", "s3://copies/logs/", local, "--recursive")
	for _, name := range []string{"a.log", "b.log", "keep.txt"} {
		sameBytes(t, "downloaded "+name, readFile(t, filepath.Join(local, name)), []byte("logs/"+name))
	}

	aws.fails("404", "s3", "cp", "s3://copies/missing", "s3://elsewhere/missing")
	aws.fails("NoSuchKey", "s3api", "copy-object", "--bucket", "elsewhere", "--key", "k",
		"--copy-source", "copies/missing")
	aws.fails("NoSuchBucket", "s3api", "copy-object", "--bucket", "nowhere", "--key", "k",
		"--copy-source", "copies/orig.json")
	aws.fails("NoSuchBucket", "s3api", "copy-object", "--bucket", "elsewhere", "--key", "k",
		"--copy-source", "nowhere/orig.json")
}

func TestRemove(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	aws.run("s3", "mb", "s3://trash")

	src := t.TempDir()
	for _, name := range []string{"one", "logs/a", "logs/b", "logs/deep/c", "x", "y", "z"} {
		writeFile(t, src, name, []byte(name))
	}
	aws.run("s3", "cp", src, "s3://trash/", "--recursive")

	aws.run("s3", "rm", "s3://trash/one")
	aws.run("s3", "rm", "s3://trash/logs/", "--recursive")
	if got, want := lsNames(aws.run("s3", "ls", "s3://trash/", "--recursive")), []string{"x", "y", "z"}; !slices.Equal(got, want) {
		t.Fatalf("after rm: %v, want %v", got, want)
	}

	var deleted struct {
		Deleted []struct{ Key string }
		Errors  []struct{ Key, Code string }
	}
	aws.json(&deleted, "s3api", "delete-objects", "--bucket", "trash",
		"--delete", `{"Objects":[{"Key":"x"},{"Key":"y"}]}`)
	if len(deleted.Deleted) != 2 || len(deleted.Errors) != 0 {
		t.Errorf("delete-objects = %+v, want two deletions", deleted)
	}
	aws.run("s3api", "delete-objects", "--bucket", "trash",
		"--delete", `{"Objects":[{"Key":"z"}],"Quiet":true}`)

	if got := lsNames(aws.run("s3", "ls", "s3://trash/", "--recursive")); len(got) != 0 {
		t.Fatalf("bucket not empty after deletes: %v", got)
	}
	aws.run("s3", "rb", "s3://trash")
}

// ---------------------------------------------------------------------------
// aws s3api — the operations one at a time
// ---------------------------------------------------------------------------

func TestS3APIObjectOperations(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	dir := t.TempDir()
	aws.run("s3api", "create-bucket", "--bucket", "objects")
	aws.run("s3api", "create-bucket", "--bucket", "other")

	content := []byte("0123456789abcdef")
	var put struct{ ETag string }
	aws.json(&put, "s3api", "put-object", "--bucket", "objects", "--key", "doc.json",
		"--body", writeFile(t, dir, "doc", content), "--content-type", "application/json")
	if put.ETag != etagOf(content) {
		t.Errorf("put-object etag = %s, want %s", put.ETag, etagOf(content))
	}

	if h := aws.head("objects", "doc.json"); h.ContentType != "application/json" || h.ContentLength != int64(len(content)) {
		t.Errorf("head-object = %+v", h)
	}

	var ranged struct {
		ContentRange  string
		ContentLength int64
	}
	rangeOut := filepath.Join(dir, "range")
	aws.json(&ranged, "s3api", "get-object", "--bucket", "objects", "--key", "doc.json",
		"--range", "bytes=2-5", rangeOut)
	if ranged.ContentRange != "bytes 2-5/16" || ranged.ContentLength != 4 {
		t.Errorf("ranged get = %+v", ranged)
	}
	sameBytes(t, "range 2-5", readFile(t, rangeOut), content[2:6])

	var suffix struct{ ContentRange string }
	aws.json(&suffix, "s3api", "get-object", "--bucket", "objects", "--key", "doc.json",
		"--range", "bytes=-3", rangeOut)
	sameBytes(t, "suffix range", readFile(t, rangeOut), content[13:])

	var copied struct{ CopyObjectResult struct{ ETag string } }
	aws.json(&copied, "s3api", "copy-object", "--bucket", "other", "--key", "copy.json",
		"--copy-source", "objects/doc.json")
	if copied.CopyObjectResult.ETag != etagOf(content) {
		t.Errorf("copy-object etag = %s, want %s", copied.CopyObjectResult.ETag, etagOf(content))
	}
	sameBytes(t, "copied object", aws.download("other", "copy.json"), content)

	var tags struct{ TagSet []any }
	aws.json(&tags, "s3api", "get-object-tagging", "--bucket", "objects", "--key", "doc.json")
	if len(tags.TagSet) != 0 {
		t.Errorf("tag set = %v, want empty", tags.TagSet)
	}
	aws.fails("NotImplemented", "s3api", "put-object-tagging", "--bucket", "objects", "--key", "doc.json",
		"--tagging", `{"TagSet":[{"Key":"k","Value":"v"}]}`)
	aws.fails("NotImplemented", "s3api", "put-bucket-versioning", "--bucket", "objects",
		"--versioning-configuration", "Status=Enabled")

	aws.fails("NoSuchKey", "s3api", "get-object", "--bucket", "objects", "--key", "missing", filepath.Join(dir, "x"))
	aws.fails("404", "s3api", "head-object", "--bucket", "objects", "--key", "missing")
	aws.fails("NoSuchBucket", "s3api", "get-object", "--bucket", "nope", "--key", "k", filepath.Join(dir, "x"))
	aws.fails("InvalidRange", "s3api", "get-object", "--bucket", "objects", "--key", "doc.json",
		"--range", "bytes=100-200", filepath.Join(dir, "x"))

	aws.run("s3api", "delete-object", "--bucket", "objects", "--key", "doc.json")
	aws.fails("404", "s3api", "head-object", "--bucket", "objects", "--key", "doc.json")
}

func TestS3APIMultipart(t *testing.T) {
	t.Parallel()
	aws := newStack(t).admin(t)
	dir := t.TempDir()
	aws.run("s3api", "create-bucket", "--bucket", "multipart")

	type upload struct{ UploadId string }
	type part struct{ ETag string }

	part1 := randomBytes(partSize, 4)
	part2 := randomBytes(1<<20, 5)

	var u upload
	aws.json(&u, "s3api", "create-multipart-upload", "--bucket", "multipart", "--key", "assembled",
		"--content-type", "application/octet-stream")

	// Parts may arrive out of order.
	var p2, p1 part
	aws.json(&p2, "s3api", "upload-part", "--bucket", "multipart", "--key", "assembled",
		"--upload-id", u.UploadId, "--part-number", "2", "--body", writeFile(t, dir, "p2", part2))
	aws.json(&p1, "s3api", "upload-part", "--bucket", "multipart", "--key", "assembled",
		"--upload-id", u.UploadId, "--part-number", "1", "--body", writeFile(t, dir, "p1", part1))

	var parts struct {
		Parts []struct {
			PartNumber int
			Size       int64
			ETag       string
		}
	}
	aws.json(&parts, "s3api", "list-parts", "--bucket", "multipart", "--key", "assembled", "--upload-id", u.UploadId)
	if len(parts.Parts) != 2 || parts.Parts[0].PartNumber != 1 || parts.Parts[1].Size != int64(len(part2)) {
		t.Errorf("list-parts = %+v", parts)
	}

	var open struct {
		Uploads []struct{ Key, UploadId string }
	}
	aws.json(&open, "s3api", "list-multipart-uploads", "--bucket", "multipart")
	if len(open.Uploads) != 1 || open.Uploads[0].UploadId != u.UploadId {
		t.Errorf("list-multipart-uploads = %+v", open)
	}

	manifest := `{"Parts":[{"PartNumber":1,"ETag":` + quoteJSON(p1.ETag) + `},{"PartNumber":2,"ETag":` + quoteJSON(p2.ETag) + `}]}`
	aws.run("s3api", "complete-multipart-upload", "--bucket", "multipart", "--key", "assembled",
		"--upload-id", u.UploadId, "--multipart-upload", manifest)

	whole := append(slices.Clone(part1), part2...)
	if h := aws.head("multipart", "assembled"); h.ETag != etagOf(whole) {
		t.Errorf("assembled etag = %s, want %s", h.ETag, etagOf(whole))
	}
	sameBytes(t, "assembled", aws.download("multipart", "assembled"), whole)

	// A part copied out of an existing object, by range.
	var c upload
	aws.json(&c, "s3api", "create-multipart-upload", "--bucket", "multipart", "--key", "slice")
	var copied struct{ CopyPartResult struct{ ETag string } }
	aws.json(&copied, "s3api", "upload-part-copy", "--bucket", "multipart", "--key", "slice",
		"--upload-id", c.UploadId, "--part-number", "1",
		"--copy-source", "multipart/assembled", "--copy-source-range", "bytes=100-1123")
	aws.run("s3api", "complete-multipart-upload", "--bucket", "multipart", "--key", "slice", "--upload-id", c.UploadId,
		"--multipart-upload", `{"Parts":[{"PartNumber":1,"ETag":`+quoteJSON(copied.CopyPartResult.ETag)+`}]}`)
	sameBytes(t, "range-copied part", aws.download("multipart", "slice"), whole[100:1124])

	// An aborted upload is gone, and its id is no longer accepted.
	var a upload
	aws.json(&a, "s3api", "create-multipart-upload", "--bucket", "multipart", "--key", "abandoned")
	aws.run("s3api", "upload-part", "--bucket", "multipart", "--key", "abandoned",
		"--upload-id", a.UploadId, "--part-number", "1", "--body", writeFile(t, dir, "p", []byte("partial")))
	aws.run("s3api", "abort-multipart-upload", "--bucket", "multipart", "--key", "abandoned", "--upload-id", a.UploadId)
	aws.fails("NoSuchUpload", "s3api", "upload-part", "--bucket", "multipart", "--key", "abandoned",
		"--upload-id", a.UploadId, "--part-number", "2", "--body", filepath.Join(dir, "p"))

	open.Uploads = nil
	aws.json(&open, "s3api", "list-multipart-uploads", "--bucket", "multipart")
	if len(open.Uploads) != 0 {
		t.Errorf("uploads still open: %+v", open.Uploads)
	}
	aws.fails("404", "s3api", "head-object", "--bucket", "multipart", "--key", "abandoned")
}

// quoteJSON renders an ETag (which carries its own double quotes) as a JSON
// string literal.
func quoteJSON(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// ---------------------------------------------------------------------------
// Authentication and tenancy
// ---------------------------------------------------------------------------

func TestSignatureIsChecked(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.admin(t).run("s3", "mb", "s3://locked")

	s.cli(t, adminKeyID, "not-the-secret").fails("SignatureDoesNotMatch", "s3", "ls", "s3://locked")
	s.cli(t, "SCASNOSUCHKEY", "whatever").fails("AccessDenied", "s3", "ls")
	s.admin(t).fails("AccessDenied", "s3", "ls", "--no-sign-request")
}

// With auth off the gateway is open, which is what the README's
// --no-sign-request example depends on.
func TestAnonymousAccessWhenAuthIsOff(t *testing.T) {
	t.Parallel()
	aws := newStack(t, withAuthDisabled()).cli(t, "x", "x")
	anon := "--no-sign-request"

	aws.run("s3", "mb", "s3://open", anon)
	content := []byte("anyone can read this")
	aws.run("s3", "cp", writeFile(t, t.TempDir(), "f", content), "s3://open/f", anon)
	if got := lsNames(aws.run("s3", "ls", "s3://open/", anon)); !slices.Equal(got, []string{"f"}) {
		t.Errorf("s3 ls = %v", got)
	}
	sameBytes(t, "anonymous download", []byte(aws.run("s3", "cp", "s3://open/f", "-", anon)), content)
}

// A team key sees only its team's buckets, owns the buckets it creates,
// cannot copy out of a bucket it cannot see, and is told a taken name is its
// own only when it is.
func TestTeamCredential(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	admin := s.admin(t)
	ctx := context.Background()

	owner, err := s.db.ResolveUser(ctx, "https://idp.test", "owner", "owner@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	tenantID, err := s.db.CreateTenant(ctx, "team-a", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	const keyID, secret = "SCASE2ETEAMA", "team-a-secret"
	if err := s.db.CreateS3Credential(ctx, tenantID, keyID, secret, "e2e"); err != nil {
		t.Fatal(err)
	}
	team := s.cli(t, keyID, secret)

	admin.run("s3", "mb", "s3://admin-only")
	admin.run("s3", "cp", writeFile(t, t.TempDir(), "secret", []byte("root's")), "s3://admin-only/secret")

	team.run("s3", "mb", "s3://team-bucket")
	team.run("s3", "cp", writeFile(t, t.TempDir(), "ours", []byte("team's")), "s3://team-bucket/ours")

	if got := lsNames(team.run("s3", "ls")); !slices.Equal(got, []string{"team-bucket"}) {
		t.Errorf("team s3 ls = %v, want only team-bucket", got)
	}
	team.fails("NoSuchBucket", "s3", "ls", "s3://admin-only/")
	team.fails("NoSuchBucket", "s3api", "copy-object", "--bucket", "team-bucket", "--key", "stolen",
		"--copy-source", "admin-only/secret")

	// Names are global: the team learns admin-only is taken, and nothing more.
	team.fails("BucketAlreadyExists", "s3api", "create-bucket", "--bucket", "admin-only")
	team.fails("BucketAlreadyOwnedByYou", "s3api", "create-bucket", "--bucket", "team-bucket")
	admin.fails("BucketAlreadyOwnedByYou", "s3api", "create-bucket", "--bucket", "team-bucket")

	if got := lsNames(admin.run("s3", "ls")); !slices.Equal(got, []string{"admin-only", "team-bucket"}) {
		t.Errorf("admin s3 ls = %v, want both buckets", got)
	}
	ns, err := s.db.GetNamespace(ctx, "team-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if ns.TenantID == nil || *ns.TenantID != tenantID {
		t.Errorf("team-bucket tenant = %v, want %d", ns.TenantID, tenantID)
	}
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// Over HTTPS the CLI sends payloads it streams as aws-chunked with a trailing
// checksum. If the framing were stored rather than decoded, the object would
// come back longer than it went in and hash to a different ETag.
func TestChunkedUploadsOverTLS(t *testing.T) {
	t.Parallel()
	aws := newStack(t, withTLS()).admin(t)
	dir := t.TempDir()
	aws.run("s3", "mb", "s3://secure")

	small := []byte("over tls")
	aws.runStdin(small, "s3", "cp", "-", "s3://secure/small")
	if h := aws.head("secure", "small"); h.ContentLength != int64(len(small)) || h.ETag != etagOf(small) {
		t.Errorf("streamed small = %+v, want %d bytes etag %s", h, len(small), etagOf(small))
	}

	large := randomBytes(2*partSize+17, 6)
	aws.runStdin(large, "s3", "cp", "-", "s3://secure/large")
	sameBytes(t, "streamed large", aws.download("secure", "large"), large)

	file := randomBytes(3<<20, 7)
	aws.run("s3", "cp", writeFile(t, dir, "file", file), "s3://secure/file")
	if h := aws.head("secure", "file"); h.ETag != etagOf(file) {
		t.Errorf("file etag = %s, want %s", h.ETag, etagOf(file))
	}
	sameBytes(t, "file over tls", aws.download("secure", "file"), file)
}
