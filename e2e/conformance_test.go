package e2e

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/ggoggam/simplecas/internal/testblob"
)

// The S3 conformance suite: each case states one piece of S3 behaviour through
// the AWS SDK for Go, and runs against two endpoints.
//
//   - reference: a real S3 implementation (the RustFS that
//     SIMPLECAS_TEST_S3_URL names). Every case must pass here, which is what
//     keeps the assertions honest: they describe S3, not simplecas.
//   - simplecas: a fully assembled server.
//
// A case simplecas is known to fail names its gap, the readiness-tracker row
// that owns the fix. On simplecas such a case is expected to fail and is
// reported as skipped with the first failure; if it starts passing, the test
// fails so the gap is removed here and in the tracker. Gaps never apply to the
// reference.
//
// The other suites in this package and internal/s3 check simplecas against
// itself; this one checks it against S3.

// Tracker rows the known gaps belong to.
const (
	gapMetadata    = "Metadata dropped; CopyObject ignores REPLACE"
	gapConditional = "Conditional headers ignored"
	gapProtocol    = "Listing and protocol details"
)

type conformanceCase struct {
	name string
	gap  string
	run  func(t T, c *endpoint)
}

var conformanceCases = []conformanceCase{
	{name: "put get head", run: testPutGetHead},
	{name: "etag of a single-part object is its MD5", run: testSinglePartETag},
	{name: "a wrong Content-MD5 is refused", run: testBadContentMD5},
	{name: "user metadata round trips", gap: gapMetadata, run: testUserMetadata},
	{name: "missing key", run: testMissingKey},
	{name: "missing bucket", run: testMissingBucket},
	{name: "ranges", run: testRanges},
	{name: "an unsatisfiable range is refused", run: testUnsatisfiableRange},
	{name: "delete is idempotent", run: testDeleteIdempotent},
	{name: "batch delete", run: testBatchDelete},
	{name: "list by prefix and delimiter", run: testListDelimiter},
	{name: "list pagination", run: testListPagination},
	{name: "list orders keys by UTF-8 bytes", run: testListOrder},
	{name: "awkward keys round trip", run: testAwkwardKeys},
	{name: "copy keeps the content type", run: testCopyKeepsContentType},
	{name: "copy with REPLACE sets the content type", run: testCopyReplace},
	{name: "multipart", run: testMultipart},
	{name: "multipart etag counts its parts", run: testMultipartETag},
	{name: "a small middle part is refused", gap: gapProtocol, run: testMultipartSmallPart},
	{name: "a wrong part etag is refused", run: testMultipartWrongETag},
	{name: "an aborted upload is gone", run: testMultipartAbort},
	{name: "conditional get", gap: gapConditional, run: testConditionalGet},
	{name: "conditional put", gap: gapConditional, run: testConditionalPut},
	{name: "a non-empty bucket is not deleted", run: testBucketNotEmpty},
	{name: "presigned put and get", run: testPresignedPutGet},
}

func TestS3Conformance(t *testing.T) {
	t.Parallel()
	t.Run("reference", func(t *testing.T) {
		t.Parallel()
		target, ok := testblob.S3(t)
		if !ok {
			t.Skipf("set %s to run the suite against a reference S3", testblob.EnvVar)
		}
		runConformance(t, &endpoint{client: target.Client()}, false)
	})
	t.Run("simplecas", func(t *testing.T) {
		t.Parallel()
		s := newStack(t)
		runConformance(t, &endpoint{client: s.sdk(adminKeyID, adminSecret)}, true)
	})
}

func runConformance(t *testing.T, c *endpoint, gaps bool) {
	for _, tc := range conformanceCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !gaps || tc.gap == "" {
				tc.run(t, c)
				return
			}
			failure := expectFailure(t, func(r T) { tc.run(r, c) })
			if failure == "" {
				t.Fatalf("passes now: drop the gap %q from this case and update the tracker", tc.gap)
			}
			t.Skipf("known gap (%s): %s", tc.gap, failure)
		})
	}
}

// T is what a case uses of *testing.T, so a known gap can run against a
// recorder instead.
type T interface {
	Helper()
	Context() context.Context
	Cleanup(func())
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// recorder collects a case's failures without failing the test.
type recorder struct {
	*testing.T
	failures []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	runtime.Goexit()
}

// expectFailure runs fn against a recorder and returns its first failure, or ""
// when it passed. fn runs on its own goroutine so Fatalf can stop it there.
func expectFailure(t *testing.T, fn func(T)) string {
	r := &recorder{T: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(r)
	}()
	<-done
	if len(r.failures) == 0 {
		return ""
	}
	return r.failures[0]
}

// endpoint is one S3 service the cases run against.
type endpoint struct {
	client *awss3.Client
}

// sdk returns an SDK client signed with one credential.
func (s *stack) sdk(keyID, secret string) *awss3.Client {
	return awss3.New(awss3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(s.url),
		UsePathStyle: true,
		Credentials:  credentials.NewStaticCredentialsProvider(keyID, secret, ""),
	})
}

// bucket creates a bucket for one case and removes it, with whatever the case
// left in it, when the case finishes. Names are random because the reference
// is shared by every case and every run.
func (c *endpoint) bucket(t T) string {
	t.Helper()
	var suffix [8]byte
	_, _ = rand.Read(suffix[:])
	name := "conf-" + hex.EncodeToString(suffix[:])
	if _, err := c.client.CreateBucket(t.Context(), &awss3.CreateBucketInput{Bucket: aws.String(name)}); err != nil {
		t.Fatalf("CreateBucket %s: %v", name, err)
	}
	t.Cleanup(func() { c.removeBucket(name) })
	return name
}

func (c *endpoint) removeBucket(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	uploads, err := c.client.ListMultipartUploads(ctx, &awss3.ListMultipartUploadsInput{Bucket: aws.String(name)})
	if err == nil {
		for _, u := range uploads.Uploads {
			_, _ = c.client.AbortMultipartUpload(ctx, &awss3.AbortMultipartUploadInput{
				Bucket: aws.String(name), Key: u.Key, UploadId: u.UploadId,
			})
		}
	}
	pages := awss3.NewListObjectsV2Paginator(c.client, &awss3.ListObjectsV2Input{Bucket: aws.String(name)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			break
		}
		for _, obj := range page.Contents {
			_, _ = c.client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(name), Key: obj.Key})
		}
	}
	_, _ = c.client.DeleteBucket(ctx, &awss3.DeleteBucketInput{Bucket: aws.String(name)})
}

func (c *endpoint) put(t T, bucket, key string, body []byte) *awss3.PutObjectOutput {
	t.Helper()
	out, err := c.client.PutObject(t.Context(), &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(body),
	})
	if err != nil {
		t.Fatalf("PutObject %s: %v", key, err)
	}
	return out
}

func (c *endpoint) get(t T, bucket, key string) []byte {
	t.Helper()
	out, err := c.client.GetObject(t.Context(), &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		t.Fatalf("GetObject %s: %v", key, err)
	}
	return readBody(t, out.Body)
}

func (c *endpoint) keys(t T, bucket string) []string {
	t.Helper()
	out, err := c.client.ListObjectsV2(t.Context(), &awss3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatalf("ListObjectsV2: %v", err)
	}
	return objectKeys(out.Contents)
}

func readBody(t T, body io.ReadCloser) []byte {
	t.Helper()
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return data
}

func objectKeys(objects []types.Object) []string {
	keys := []string{}
	for _, o := range objects {
		keys = append(keys, aws.ToString(o.Key))
	}
	return keys
}

func prefixes(common []types.CommonPrefix) []string {
	out := []string{}
	for _, p := range common {
		out = append(out, aws.ToString(p.Prefix))
	}
	return out
}

// wantError fails unless err is an S3 error with the given code.
func wantError(t T, what string, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded, want %s", what, code)
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != code {
		t.Fatalf("%s: %v, want %s", what, err, code)
	}
}

// wantStatus fails unless err is an HTTP response with the given status.
func wantStatus(t T, what string, err error, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded, want HTTP %d", what, status)
	}
	var respErr *smithyhttp.ResponseError
	if !errors.As(err, &respErr) || respErr.HTTPStatusCode() != status {
		t.Fatalf("%s: %v, want HTTP %d", what, err, status)
	}
}

func md5ETag(data []byte) string {
	sum := md5.Sum(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

func testPutGetHead(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	body := []byte("hello, world")
	put, err := c.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("greeting.txt"),
		Body: bytes.NewReader(body), ContentType: aws.String("text/plain"),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	get, err := c.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("greeting.txt")})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if got := readBody(t, get.Body); !bytes.Equal(got, body) {
		t.Errorf("GetObject body = %q, want %q", got, body)
	}
	if aws.ToString(get.ContentType) != "text/plain" || aws.ToInt64(get.ContentLength) != int64(len(body)) {
		t.Errorf("GetObject = %s, %d bytes; want text/plain, %d", aws.ToString(get.ContentType), aws.ToInt64(get.ContentLength), len(body))
	}

	head, err := c.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("greeting.txt")})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if aws.ToInt64(head.ContentLength) != int64(len(body)) || aws.ToString(head.ContentType) != "text/plain" {
		t.Errorf("HeadObject = %s, %d bytes", aws.ToString(head.ContentType), aws.ToInt64(head.ContentLength))
	}
	if head.LastModified == nil || time.Since(*head.LastModified) > time.Hour {
		t.Errorf("HeadObject LastModified = %v, want about now", head.LastModified)
	}
	etag := aws.ToString(put.ETag)
	if etag == "" || aws.ToString(get.ETag) != etag || aws.ToString(head.ETag) != etag {
		t.Errorf("ETags put %s, get %s, head %s; want one non-empty value", etag, aws.ToString(get.ETag), aws.ToString(head.ETag))
	}
}

func testSinglePartETag(t T, c *endpoint) {
	bucket := c.bucket(t)
	body := []byte("an etag clients can check")
	if got := aws.ToString(c.put(t, bucket, "k", body).ETag); got != md5ETag(body) {
		t.Errorf("ETag = %s, want the MD5 %s", got, md5ETag(body))
	}
}

func testBadContentMD5(t T, c *endpoint) {
	bucket := c.bucket(t)
	wrong := md5.Sum([]byte("something else"))
	_, err := c.client.PutObject(t.Context(), &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("k"), Body: bytes.NewReader([]byte("the body")),
		ContentMD5: aws.String(base64.StdEncoding.EncodeToString(wrong[:])),
	})
	wantError(t, "PutObject with a wrong Content-MD5", err, "BadDigest")
	if keys := c.keys(t, bucket); len(keys) != 0 {
		t.Errorf("bucket holds %v after a refused put", keys)
	}
}

func testUserMetadata(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	if _, err := c.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("k"), Body: bytes.NewReader([]byte("x")),
		Metadata: map[string]string{"colour": "blue"},
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	head, err := c.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("k")})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if head.Metadata["colour"] != "blue" {
		t.Errorf("Metadata = %v, want colour=blue", head.Metadata)
	}
}

func testMissingKey(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	_, err := c.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("missing")})
	wantError(t, "GetObject of a missing key", err, "NoSuchKey")
	_, err = c.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("missing")})
	wantStatus(t, "HeadObject of a missing key", err, http.StatusNotFound)
}

func testMissingBucket(t T, c *endpoint) {
	ctx := t.Context()
	_, err := c.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String("conf-missing-bucket"), Key: aws.String("k")})
	wantError(t, "GetObject in a missing bucket", err, "NoSuchBucket")
	_, err = c.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String("conf-missing-bucket")})
	wantError(t, "ListObjectsV2 of a missing bucket", err, "NoSuchBucket")
	_, err = c.client.HeadBucket(ctx, &awss3.HeadBucketInput{Bucket: aws.String("conf-missing-bucket")})
	wantStatus(t, "HeadBucket of a missing bucket", err, http.StatusNotFound)
}

func testRanges(t T, c *endpoint) {
	bucket := c.bucket(t)
	c.put(t, bucket, "digits", []byte("0123456789"))
	for _, tc := range []struct{ header, want, contentRange string }{
		{"bytes=2-5", "2345", "bytes 2-5/10"},
		{"bytes=7-", "789", "bytes 7-9/10"},
		{"bytes=-3", "789", "bytes 7-9/10"},
		{"bytes=8-100", "89", "bytes 8-9/10"},
	} {
		out, err := c.client.GetObject(t.Context(), &awss3.GetObjectInput{
			Bucket: aws.String(bucket), Key: aws.String("digits"), Range: aws.String(tc.header),
		})
		if err != nil {
			t.Fatalf("GetObject %s: %v", tc.header, err)
		}
		if got := readBody(t, out.Body); string(got) != tc.want {
			t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
		}
		if got := aws.ToString(out.ContentRange); got != tc.contentRange {
			t.Errorf("%s Content-Range = %q, want %q", tc.header, got, tc.contentRange)
		}
		if got := aws.ToInt64(out.ContentLength); got != int64(len(tc.want)) {
			t.Errorf("%s Content-Length = %d, want %d", tc.header, got, len(tc.want))
		}
	}
}

func testUnsatisfiableRange(t T, c *endpoint) {
	bucket := c.bucket(t)
	c.put(t, bucket, "digits", []byte("0123456789"))
	_, err := c.client.GetObject(t.Context(), &awss3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("digits"), Range: aws.String("bytes=20-30"),
	})
	wantError(t, "GetObject bytes=20-30 of 10 bytes", err, "InvalidRange")
}

func testDeleteIdempotent(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	c.put(t, bucket, "k", []byte("x"))
	for i := range 2 {
		if _, err := c.client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String("k")}); err != nil {
			t.Fatalf("DeleteObject #%d: %v", i+1, err)
		}
	}
	if _, err := c.client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String("never-was")}); err != nil {
		t.Errorf("DeleteObject of a key that never existed: %v", err)
	}
}

func testBatchDelete(t T, c *endpoint) {
	bucket := c.bucket(t)
	c.put(t, bucket, "a", []byte("a"))
	c.put(t, bucket, "b", []byte("b"))
	c.put(t, bucket, "keep", []byte("keep"))
	out, err := c.client.DeleteObjects(t.Context(), &awss3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{Objects: []types.ObjectIdentifier{
			{Key: aws.String("a")}, {Key: aws.String("b")}, {Key: aws.String("never-was")},
		}},
	})
	if err != nil {
		t.Fatalf("DeleteObjects: %v", err)
	}
	var deleted []string
	for _, d := range out.Deleted {
		deleted = append(deleted, aws.ToString(d.Key))
	}
	slices.Sort(deleted)
	if !slices.Equal(deleted, []string{"a", "b", "never-was"}) || len(out.Errors) != 0 {
		t.Errorf("Deleted %v, errors %v; want all three deleted, a missing key included", deleted, out.Errors)
	}
	if keys := c.keys(t, bucket); !slices.Equal(keys, []string{"keep"}) {
		t.Errorf("left %v, want [keep]", keys)
	}
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

func testListDelimiter(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	for _, k := range []string{"a/1", "a/2", "b/1", "c", "d/e/f"} {
		c.put(t, bucket, k, []byte(k))
	}

	top, err := c.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(bucket), Delimiter: aws.String("/")})
	if err != nil {
		t.Fatalf("ListObjectsV2: %v", err)
	}
	if got := objectKeys(top.Contents); !slices.Equal(got, []string{"c"}) {
		t.Errorf("top-level keys = %v, want [c]", got)
	}
	if got := prefixes(top.CommonPrefixes); !slices.Equal(got, []string{"a/", "b/", "d/"}) {
		t.Errorf("top-level prefixes = %v, want [a/ b/ d/]", got)
	}
	if got := aws.ToInt32(top.KeyCount); got != 4 {
		t.Errorf("KeyCount = %d, want 4: keys and prefixes both count", got)
	}

	inA, err := c.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("a/")})
	if err != nil {
		t.Fatalf("ListObjectsV2 a/: %v", err)
	}
	if got := objectKeys(inA.Contents); !slices.Equal(got, []string{"a/1", "a/2"}) {
		t.Errorf("a/ keys = %v", got)
	}

	inD, err := c.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String("d/"), Delimiter: aws.String("/"),
	})
	if err != nil {
		t.Fatalf("ListObjectsV2 d/: %v", err)
	}
	if got := prefixes(inD.CommonPrefixes); !slices.Equal(got, []string{"d/e/"}) || len(inD.Contents) != 0 {
		t.Errorf("d/ = keys %v, prefixes %v; want only the prefix d/e/", objectKeys(inD.Contents), got)
	}
}

func testListPagination(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	want := []string{"k0", "k1", "k2", "k3", "k4"}
	for _, k := range want {
		c.put(t, bucket, k, []byte(k))
	}

	var got []string
	var token *string
	for page := 1; ; page++ {
		out, err := c.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
			Bucket: aws.String(bucket), MaxKeys: aws.Int32(2), ContinuationToken: token,
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 page %d: %v", page, err)
		}
		if len(out.Contents) > 2 {
			t.Fatalf("page %d holds %d keys, over MaxKeys 2", page, len(out.Contents))
		}
		got = append(got, objectKeys(out.Contents)...)
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		if out.NextContinuationToken == nil || page > len(want) {
			t.Fatalf("page %d is truncated with token %v", page, out.NextContinuationToken)
		}
		token = out.NextContinuationToken
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged keys = %v, want %v", got, want)
	}

	after, err := c.client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(bucket), StartAfter: aws.String("k2")})
	if err != nil {
		t.Fatalf("ListObjectsV2 StartAfter: %v", err)
	}
	if got := objectKeys(after.Contents); !slices.Equal(got, []string{"k3", "k4"}) {
		t.Errorf("StartAfter k2 = %v, want [k3 k4]", got)
	}
}

func testListOrder(t T, c *endpoint) {
	bucket := c.bucket(t)
	keys := []string{"z", "é", "B", "a b", "a+b", "a", "ä", "_"}
	for _, k := range keys {
		c.put(t, bucket, k, []byte(k))
	}
	want := slices.Clone(keys)
	slices.Sort(want) // Go orders strings by their UTF-8 bytes, as S3 does
	if got := c.keys(t, bucket); !slices.Equal(got, want) {
		t.Errorf("listed %q, want %q", got, want)
	}
}

// Every one of these has to survive SigV4's canonical URI, which encodes
// differently from a browser or Go's url package. Empty and dot path segments
// ("a//b", "a/./b") and a leading slash are valid on AWS but left out: the
// reference stores keys as file paths, refusing the first two and listing
// "/k" as "k".
func testAwkwardKeys(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	keys := []string{
		"with space", "plus+sign", "percent%20literal", "tilde~", "equals=and&amp",
		"parens(1)", "bang!", "star*", "quote'd", "colon:semi;", "comma,at@",
		"dollar$", "unicode-é-한-🙂", "trailing/",
	}
	for _, key := range keys {
		body := []byte("body of " + key)
		c.put(t, bucket, key, body)
		if got := c.get(t, bucket, key); !bytes.Equal(got, body) {
			t.Errorf("GetObject %q = %q", key, got)
		}
		if _, err := c.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}); err != nil {
			t.Errorf("HeadObject %q: %v", key, err)
		}
	}
	want := slices.Clone(keys)
	slices.Sort(want)
	if got := c.keys(t, bucket); !slices.Equal(got, want) {
		t.Errorf("listed %q, want %q", got, want)
	}
	for _, key := range keys {
		if _, err := c.client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}); err != nil {
			t.Errorf("DeleteObject %q: %v", key, err)
		}
	}
	if got := c.keys(t, bucket); len(got) != 0 {
		t.Errorf("left %q after deleting every key", got)
	}
}

// ---------------------------------------------------------------------------
// Copy
// ---------------------------------------------------------------------------

func testCopyKeepsContentType(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	if _, err := c.client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("src"), Body: bytes.NewReader([]byte("copy me")),
		ContentType: aws.String("text/csv"),
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if _, err := c.client.CopyObject(ctx, &awss3.CopyObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("dst"), CopySource: aws.String(bucket + "/src"),
	}); err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	head, err := c.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("dst")})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if got := aws.ToString(head.ContentType); got != "text/csv" {
		t.Errorf("copied Content-Type = %q, want text/csv", got)
	}
	if got := c.get(t, bucket, "dst"); string(got) != "copy me" {
		t.Errorf("copied body = %q", got)
	}
}

func testCopyReplace(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	c.put(t, bucket, "src", []byte(`{"a":1}`))
	if _, err := c.client.CopyObject(ctx, &awss3.CopyObjectInput{
		Bucket: aws.String(bucket), Key: aws.String("dst"), CopySource: aws.String(bucket + "/src"),
		MetadataDirective: types.MetadataDirectiveReplace, ContentType: aws.String("application/json"),
	}); err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	head, err := c.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String("dst")})
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if got := aws.ToString(head.ContentType); got != "application/json" {
		t.Errorf("Content-Type after REPLACE = %q, want application/json", got)
	}
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

// minPart is S3's smallest part other than the last.
const minPart = 5 << 20

func (c *endpoint) createUpload(t T, bucket, key string) string {
	t.Helper()
	out, err := c.client.CreateMultipartUpload(t.Context(), &awss3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	return aws.ToString(out.UploadId)
}

func (c *endpoint) uploadPart(t T, bucket, key, uploadID string, n int32, body []byte) types.CompletedPart {
	t.Helper()
	out, err := c.client.UploadPart(t.Context(), &awss3.UploadPartInput{
		Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		PartNumber: aws.Int32(n), Body: bytes.NewReader(body),
	})
	if err != nil {
		t.Fatalf("UploadPart %d: %v", n, err)
	}
	return types.CompletedPart{PartNumber: aws.Int32(n), ETag: out.ETag}
}

func (c *endpoint) complete(t T, bucket, key, uploadID string, parts ...types.CompletedPart) (*awss3.CompleteMultipartUploadOutput, error) {
	return c.client.CompleteMultipartUpload(t.Context(), &awss3.CompleteMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
}

func testMultipart(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	first, last := randomBytes(minPart, 1), []byte("the short last part")
	id := c.createUpload(t, bucket, "big")
	p1 := c.uploadPart(t, bucket, "big", id, 1, first)
	p2 := c.uploadPart(t, bucket, "big", id, 2, last)

	listed, err := c.client.ListParts(ctx, &awss3.ListPartsInput{Bucket: aws.String(bucket), Key: aws.String("big"), UploadId: aws.String(id)})
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	if len(listed.Parts) != 2 || aws.ToInt64(listed.Parts[0].Size) != minPart || aws.ToInt64(listed.Parts[1].Size) != int64(len(last)) {
		t.Errorf("ListParts = %+v, want parts of %d and %d bytes", listed.Parts, minPart, len(last))
	}
	uploads, err := c.client.ListMultipartUploads(ctx, &awss3.ListMultipartUploadsInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	if len(uploads.Uploads) != 1 || aws.ToString(uploads.Uploads[0].UploadId) != id {
		t.Errorf("ListMultipartUploads = %+v, want just %s", uploads.Uploads, id)
	}

	if _, err := c.complete(t, bucket, "big", id, p1, p2); err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	want := append(slices.Clone(first), last...)
	if got := c.get(t, bucket, "big"); !bytes.Equal(got, want) {
		t.Errorf("assembled object: %d bytes, want %d", len(got), len(want))
	}
	uploads, err = c.client.ListMultipartUploads(ctx, &awss3.ListMultipartUploadsInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	if len(uploads.Uploads) != 0 {
		t.Errorf("a completed upload is still listed: %+v", uploads.Uploads)
	}
}

// S3's multipart ETag is the MD5 of the parts' MD5s, then "-" and the part
// count; tools read the count from it.
func testMultipartETag(t T, c *endpoint) {
	bucket := c.bucket(t)
	first, last := randomBytes(minPart, 2), []byte("tail")
	id := c.createUpload(t, bucket, "k")
	p1 := c.uploadPart(t, bucket, "k", id, 1, first)
	p2 := c.uploadPart(t, bucket, "k", id, 2, last)
	if got := aws.ToString(p1.ETag); got != md5ETag(first) {
		t.Errorf("part ETag = %s, want the part's MD5 %s", got, md5ETag(first))
	}
	out, err := c.complete(t, bucket, "k", id, p1, p2)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	a, b := md5.Sum(first), md5.Sum(last)
	sum := md5.Sum(append(a[:], b[:]...))
	if want := `"` + hex.EncodeToString(sum[:]) + `-2"`; aws.ToString(out.ETag) != want {
		t.Errorf("ETag = %s, want %s", aws.ToString(out.ETag), want)
	}
}

func testMultipartSmallPart(t T, c *endpoint) {
	bucket := c.bucket(t)
	id := c.createUpload(t, bucket, "k")
	p1 := c.uploadPart(t, bucket, "k", id, 1, []byte("far below five mebibytes"))
	p2 := c.uploadPart(t, bucket, "k", id, 2, []byte("last"))
	_, err := c.complete(t, bucket, "k", id, p1, p2)
	wantError(t, "CompleteMultipartUpload with a small first part", err, "EntityTooSmall")
}

func testMultipartWrongETag(t T, c *endpoint) {
	bucket := c.bucket(t)
	id := c.createUpload(t, bucket, "k")
	part := c.uploadPart(t, bucket, "k", id, 1, []byte("only part"))
	part.ETag = aws.String(md5ETag([]byte("not this part")))
	_, err := c.complete(t, bucket, "k", id, part)
	wantError(t, "CompleteMultipartUpload with a wrong part ETag", err, "InvalidPart")
}

func testMultipartAbort(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	id := c.createUpload(t, bucket, "k")
	c.uploadPart(t, bucket, "k", id, 1, []byte("part"))
	if _, err := c.client.AbortMultipartUpload(ctx, &awss3.AbortMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String("k"), UploadId: aws.String(id),
	}); err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}
	_, err := c.client.UploadPart(ctx, &awss3.UploadPartInput{
		Bucket: aws.String(bucket), Key: aws.String("k"), UploadId: aws.String(id),
		PartNumber: aws.Int32(2), Body: bytes.NewReader([]byte("late")),
	})
	wantError(t, "UploadPart to an aborted upload", err, "NoSuchUpload")
	if keys := c.keys(t, bucket); len(keys) != 0 {
		t.Errorf("an aborted upload left %v", keys)
	}
}

// ---------------------------------------------------------------------------
// Conditional requests
// ---------------------------------------------------------------------------

func testConditionalGet(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	etag := aws.ToString(c.put(t, bucket, "k", []byte("v1")).ETag)

	_, err := c.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("k"), IfNoneMatch: aws.String(etag)})
	wantStatus(t, "GetObject If-None-Match the current ETag", err, http.StatusNotModified)
	_, err = c.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("k"), IfMatch: aws.String(`"0000"`)})
	wantError(t, "GetObject If-Match another ETag", err, "PreconditionFailed")
	if _, err := c.client.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("k"), IfMatch: aws.String(etag)}); err != nil {
		t.Errorf("GetObject If-Match the current ETag: %v", err)
	}
}

// If-None-Match: * on a put is how Terraform and others take a lock.
func testConditionalPut(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	putIfAbsent := func(body string) error {
		_, err := c.client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(bucket), Key: aws.String("lock"), Body: strings.NewReader(body),
			IfNoneMatch: aws.String("*"),
		})
		return err
	}
	if err := putIfAbsent("first"); err != nil {
		t.Fatalf("first conditional put: %v", err)
	}
	wantError(t, "second conditional put", putIfAbsent("second"), "PreconditionFailed")
	if got := c.get(t, bucket, "lock"); string(got) != "first" {
		t.Errorf("lock holds %q, want the first writer's", got)
	}
}

// ---------------------------------------------------------------------------
// Buckets and presigning
// ---------------------------------------------------------------------------

func testBucketNotEmpty(t T, c *endpoint) {
	bucket := c.bucket(t)
	c.put(t, bucket, "k", []byte("x"))
	_, err := c.client.DeleteBucket(t.Context(), &awss3.DeleteBucketInput{Bucket: aws.String(bucket)})
	wantError(t, "DeleteBucket of a bucket holding a key", err, "BucketNotEmpty")
}

func testPresignedPutGet(t T, c *endpoint) {
	ctx, bucket := t.Context(), c.bucket(t)
	presign := awss3.NewPresignClient(c.client, awss3.WithPresignExpires(5*time.Minute))
	body := []byte("uploaded with nothing but a URL")

	put, err := presign.PresignPutObject(ctx, &awss3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String("k")})
	if err != nil {
		t.Fatalf("PresignPutObject: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, put.URL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if status, resp := roundTrip(t, req); status != http.StatusOK {
		t.Fatalf("presigned PUT = %d %s", status, resp)
	}

	get, err := presign.PresignGetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("k")})
	if err != nil {
		t.Fatalf("PresignGetObject: %v", err)
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, get.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if status, resp := roundTrip(t, req); status != http.StatusOK || !bytes.Equal(resp, body) {
		t.Errorf("presigned GET = %d %q, want 200 %q", status, resp, body)
	}
}

func roundTrip(t T, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", req.Method, err)
	}
	return resp.StatusCode, readBody(t, resp.Body)
}
