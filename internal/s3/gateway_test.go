package s3

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ggoggam/simplecas/internal/cas"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testdb"
)

// Published BLAKE3 digest of "abc", which is the ETag every upload of that
// content must produce.
const abcHash = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"

// newGateway builds a gateway over a scratch database and a scratch fs bucket.
// Each option adjusts the configuration before the gateway is built.
func newGateway(t *testing.T, options ...func(*config.Config)) *Gateway {
	t.Helper()
	ctx := t.Context()
	dsn := testdb.URL(t)

	database, err := db.Connect(ctx, dsn, 8)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(database.Close)

	bucket, err := storage.Open(ctx, config.StorageConfig{Backend: "fs", Root: t.TempDir()})
	if err != nil {
		t.Fatalf("open bucket: %v", err)
	}
	t.Cleanup(func() { _ = bucket.Close() })

	cfg := config.Default()
	cfg.Database.URL = dsn
	for _, option := range options {
		option(&cfg)
	}
	log := slog.New(slog.DiscardHandler)
	gc := config.GcConfig{IntervalSecs: 60, GraceSecs: 300, MultipartExpirySecs: 86400}

	return New(database, bucket, cas.New(database, bucket, gc, cfg.Limits, log), &cfg, log)
}

// do issues a request against the gateway and returns the recorded response.
func do(t *testing.T, g *Gateway, method, target string, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

// decode parses an XML response body into v.
func decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := xml.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, w.Body.String())
	}
}

// errorCode pulls the S3 error code out of an error response.
func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	decode(t, w, &e)
	return e.Code
}

func mustStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d\nbody: %s", w.Code, want, w.Body.String())
	}
}

// createNS creates a namespace through the gateway.
func createNS(t *testing.T, g *Gateway, name string) {
	t.Helper()
	mustStatus(t, do(t, g, http.MethodPut, "/"+name, ""), http.StatusOK)
}

// putObj uploads an object through the gateway and returns its ETag.
func putObj(t *testing.T, g *Gateway, ns, key, body, contentType string) string {
	t.Helper()
	w := do(t, g, http.MethodPut, "/"+ns+"/"+key, body, "Content-Type", contentType)
	mustStatus(t, w, http.StatusOK)
	return w.Header().Get("ETag")
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

func TestNamespaceLifecycleOverHTTP(t *testing.T) {
	g := newGateway(t)

	w := do(t, g, http.MethodPut, "/photos", "")
	mustStatus(t, w, http.StatusOK)
	if got := w.Header().Get("Location"); got != "/photos" {
		t.Errorf("Location = %q, want /photos", got)
	}

	// Duplicate create.
	w = do(t, g, http.MethodPut, "/photos", "")
	mustStatus(t, w, http.StatusConflict)
	if code := errorCode(t, w); code != "BucketAlreadyOwnedByYou" {
		t.Errorf("code = %q", code)
	}

	// Invalid name.
	w = do(t, g, http.MethodPut, "/Bad_Name", "")
	mustStatus(t, w, http.StatusBadRequest)
	if code := errorCode(t, w); code != "InvalidBucketName" {
		t.Errorf("code = %q", code)
	}

	// HeadBucket.
	mustStatus(t, do(t, g, http.MethodHead, "/photos", ""), http.StatusOK)
	mustStatus(t, do(t, g, http.MethodHead, "/missing", ""), http.StatusNotFound)

	// ListBuckets.
	w = do(t, g, http.MethodGet, "/", "")
	mustStatus(t, w, http.StatusOK)
	var listing listAllMyBucketsResult
	decode(t, w, &listing)
	if len(listing.Buckets.Bucket) != 1 || listing.Buckets.Bucket[0].Name != "photos" {
		t.Errorf("buckets = %+v", listing.Buckets.Bucket)
	}

	// DeleteBucket while occupied, then once empty.
	putObj(t, g, "photos", "cat.jpg", "abc", "image/jpeg")
	w = do(t, g, http.MethodDelete, "/photos", "")
	mustStatus(t, w, http.StatusConflict)
	if code := errorCode(t, w); code != "BucketNotEmpty" {
		t.Errorf("code = %q", code)
	}
	mustStatus(t, do(t, g, http.MethodDelete, "/photos/cat.jpg", ""), http.StatusNoContent)
	mustStatus(t, do(t, g, http.MethodDelete, "/photos", ""), http.StatusNoContent)
}

func TestGetBucketLocationAndVersioning(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "photos")

	w := do(t, g, http.MethodGet, "/photos?location", "")
	mustStatus(t, w, http.StatusOK)
	var loc locationConstraint
	decode(t, w, &loc)
	if loc.Region != "us-east-1" {
		t.Errorf("region = %q, want the configured us-east-1", loc.Region)
	}

	// Versioning is unsupported, and reported as never-enabled.
	w = do(t, g, http.MethodGet, "/photos?versioning", "")
	mustStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "VersioningConfiguration") {
		t.Errorf("body = %s", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

func TestPutGetHeadDeleteObject(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "photos")

	etag := putObj(t, g, "photos", "cat.jpg", "abc", "image/jpeg")
	if etag != `"`+abcHash+`"` {
		t.Errorf("ETag = %s, want the quoted content hash", etag)
	}

	w := do(t, g, http.MethodGet, "/photos/cat.jpg", "")
	mustStatus(t, w, http.StatusOK)
	if got := w.Body.String(); got != "abc" {
		t.Errorf("body = %q", got)
	}
	for header, want := range map[string]string{
		"Content-Type":      "image/jpeg",
		"ETag":              `"` + abcHash + `"`,
		"Accept-Ranges":     "bytes",
		"x-amz-meta-blake3": abcHash,
		"Content-Length":    "3",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if w.Header().Get("Last-Modified") == "" {
		t.Error("Last-Modified was not set")
	}

	// HEAD carries the same headers with no body.
	w = do(t, g, http.MethodHead, "/photos/cat.jpg", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.Len() != 0 {
		t.Errorf("HEAD returned a body: %q", w.Body.String())
	}
	if got := w.Header().Get("Content-Length"); got != "3" {
		t.Errorf("HEAD Content-Length = %q, want 3", got)
	}

	// Missing key.
	w = do(t, g, http.MethodGet, "/photos/missing.jpg", "")
	mustStatus(t, w, http.StatusNotFound)
	if code := errorCode(t, w); code != "NoSuchKey" {
		t.Errorf("code = %q", code)
	}

	// Missing namespace.
	w = do(t, g, http.MethodGet, "/nosuch/cat.jpg", "")
	mustStatus(t, w, http.StatusNotFound)
	if code := errorCode(t, w); code != "NoSuchBucket" {
		t.Errorf("code = %q", code)
	}

	// DELETE is idempotent.
	mustStatus(t, do(t, g, http.MethodDelete, "/photos/cat.jpg", ""), http.StatusNoContent)
	mustStatus(t, do(t, g, http.MethodDelete, "/photos/cat.jpg", ""), http.StatusNoContent)
}

func TestPutObjectDefaultsContentType(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "photos")

	w := do(t, g, http.MethodPut, "/photos/blob", "abc")
	mustStatus(t, w, http.StatusOK)

	w = do(t, g, http.MethodGet, "/photos/blob", "")
	if got := w.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
}

func TestZeroByteObject(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "photos")

	w := do(t, g, http.MethodPut, "/photos/empty", "")
	mustStatus(t, w, http.StatusOK)

	w = do(t, g, http.MethodGet, "/photos/empty", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", w.Body.String())
	}
	if got := w.Header().Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want 0", got)
	}

	// A range against a zero-byte object serves the whole (empty) body rather
	// than failing.
	w = do(t, g, http.MethodGet, "/photos/empty", "", "Range", "bytes=0-10")
	mustStatus(t, w, http.StatusOK)
}

func TestRangeRequests(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")
	putObj(t, g, "files", "digits", "0123456789", "text/plain")

	tests := []struct {
		name         string
		header       string
		status       int
		body         string
		contentRange string
	}{
		{"closed", "bytes=2-5", http.StatusPartialContent, "2345", "bytes 2-5/10"},
		{"open-ended", "bytes=7-", http.StatusPartialContent, "789", "bytes 7-9/10"},
		{"suffix", "bytes=-3", http.StatusPartialContent, "789", "bytes 7-9/10"},
		{"clamped end", "bytes=8-99", http.StatusPartialContent, "89", "bytes 8-9/10"},
		{"whole object as a range", "bytes=0-9", http.StatusPartialContent, "0123456789", "bytes 0-9/10"},
		// Not honoured, so the whole object is served.
		{"multi-range", "bytes=0-1,4-5", http.StatusOK, "0123456789", ""},
		{"unknown unit", "items=0-1", http.StatusOK, "0123456789", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, g, http.MethodGet, "/files/digits", "", "Range", tc.header)
			mustStatus(t, w, tc.status)
			if got := w.Body.String(); got != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
			if got := w.Header().Get("Content-Range"); got != tc.contentRange {
				t.Errorf("Content-Range = %q, want %q", got, tc.contentRange)
			}
		})
	}

	// Unsatisfiable.
	w := do(t, g, http.MethodGet, "/files/digits", "", "Range", "bytes=50-")
	mustStatus(t, w, http.StatusRequestedRangeNotSatisfiable)
	if code := errorCode(t, w); code != "InvalidRange" {
		t.Errorf("code = %q", code)
	}
}

// Keys containing "//" and dot segments must survive routing untouched.
func TestKeysWithAwkwardPaths(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	for _, key := range []string{"dir//double", "dir/./dot", "a/b/c/deep", "with%20space"} {
		t.Run(key, func(t *testing.T) {
			w := do(t, g, http.MethodPut, "/files/"+key, "abc", "Content-Type", "text/plain")
			mustStatus(t, w, http.StatusOK)

			w = do(t, g, http.MethodGet, "/files/"+key, "")
			mustStatus(t, w, http.StatusOK)
			if got := w.Body.String(); got != "abc" {
				t.Errorf("body = %q", got)
			}
		})
	}

	// The double-slash key is stored with the slashes intact.
	w := do(t, g, http.MethodGet, "/files?list-type=2&prefix=dir//", "")
	mustStatus(t, w, http.StatusOK)
	var listing listBucketResult
	decode(t, w, &listing)
	if len(listing.Contents) != 1 || listing.Contents[0].Key != "dir//double" {
		t.Errorf("contents = %+v, want the literal dir//double key", listing.Contents)
	}
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

func TestListObjectsV2(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")
	for _, key := range []string{"a.txt", "photos/1.jpg", "photos/2.jpg", "z.txt"} {
		putObj(t, g, "files", key, "abc", "text/plain")
	}

	t.Run("flat", func(t *testing.T) {
		w := do(t, g, http.MethodGet, "/files?list-type=2", "")
		mustStatus(t, w, http.StatusOK)
		var l listBucketResult
		decode(t, w, &l)
		if l.Name != "files" || l.KeyCount != 4 || l.IsTruncated {
			t.Errorf("listing = %+v", l)
		}
		if len(l.Contents) != 4 {
			t.Fatalf("contents = %+v", l.Contents)
		}
		if l.Contents[0].Key != "a.txt" || l.Contents[0].ETag != `"`+abcHash+`"` {
			t.Errorf("first entry = %+v", l.Contents[0])
		}
		if l.Contents[0].StorageClass != "STANDARD" {
			t.Errorf("storage class = %q", l.Contents[0].StorageClass)
		}
	})

	t.Run("delimiter", func(t *testing.T) {
		w := do(t, g, http.MethodGet, "/files?list-type=2&delimiter=/", "")
		mustStatus(t, w, http.StatusOK)
		var l listBucketResult
		decode(t, w, &l)
		if l.Delimiter == nil || *l.Delimiter != "/" {
			t.Errorf("delimiter = %v", l.Delimiter)
		}
		if len(l.Contents) != 2 || len(l.CommonPrefixes) != 1 {
			t.Fatalf("contents = %+v, prefixes = %+v", l.Contents, l.CommonPrefixes)
		}
		if l.CommonPrefixes[0].Prefix != "photos/" {
			t.Errorf("prefix = %q", l.CommonPrefixes[0].Prefix)
		}
		// Prefixes count toward KeyCount.
		if l.KeyCount != 3 {
			t.Errorf("KeyCount = %d, want 3", l.KeyCount)
		}
	})

	t.Run("prefix", func(t *testing.T) {
		w := do(t, g, http.MethodGet, "/files?list-type=2&prefix=photos/", "")
		var l listBucketResult
		decode(t, w, &l)
		if l.Prefix != "photos/" || len(l.Contents) != 2 {
			t.Errorf("listing = %+v", l)
		}
	})

	t.Run("continuation token walks every key once", func(t *testing.T) {
		var seen []string
		target := "/files?list-type=2&max-keys=2"
		for range 10 {
			w := do(t, g, http.MethodGet, target, "")
			mustStatus(t, w, http.StatusOK)
			var l listBucketResult
			decode(t, w, &l)
			for _, c := range l.Contents {
				seen = append(seen, c.Key)
			}
			if !l.IsTruncated {
				break
			}
			if l.NextContinuationToken == nil {
				t.Fatal("a truncated listing must carry a continuation token")
			}
			target = "/files?list-type=2&max-keys=2&continuation-token=" +
				strings.ReplaceAll(*l.NextContinuationToken, "=", "%3D")
		}
		want := []string{"a.txt", "photos/1.jpg", "photos/2.jpg", "z.txt"}
		if strings.Join(seen, ",") != strings.Join(want, ",") {
			t.Errorf("paged through %v, want %v", seen, want)
		}
	})

	t.Run("start-after skips ahead", func(t *testing.T) {
		w := do(t, g, http.MethodGet, "/files?list-type=2&start-after=photos/1.jpg", "")
		var l listBucketResult
		decode(t, w, &l)
		if len(l.Contents) != 2 || l.Contents[0].Key != "photos/2.jpg" {
			t.Errorf("contents = %+v", l.Contents)
		}
	})

	t.Run("bad continuation token", func(t *testing.T) {
		w := do(t, g, http.MethodGet, "/files?list-type=2&continuation-token=!!!not-base64", "")
		mustStatus(t, w, http.StatusBadRequest)
		if code := errorCode(t, w); code != "InvalidArgument" {
			t.Errorf("code = %q", code)
		}
	})

	t.Run("bad delimiter", func(t *testing.T) {
		w := do(t, g, http.MethodGet, "/files?list-type=2&delimiter=ab", "")
		mustStatus(t, w, http.StatusBadRequest)
	})
}

// V1 listings use a raw marker and report NextMarker instead of a token.
func TestListObjectsV1(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")
	for _, key := range []string{"k1", "k2", "k3"} {
		putObj(t, g, "files", key, "abc", "text/plain")
	}

	w := do(t, g, http.MethodGet, "/files?max-keys=2", "")
	mustStatus(t, w, http.StatusOK)
	var l listBucketResult
	decode(t, w, &l)
	if !l.IsTruncated {
		t.Fatal("expected a truncated listing")
	}
	if l.Marker == nil {
		t.Error("V1 must report Marker, even when empty")
	}
	if l.NextMarker == nil || *l.NextMarker == "" {
		t.Fatalf("NextMarker = %v, want a resume key", l.NextMarker)
	}
	if l.NextContinuationToken != nil {
		t.Error("V1 must not emit a V2 continuation token")
	}

	w = do(t, g, http.MethodGet, "/files?max-keys=2&marker="+*l.NextMarker, "")
	// A fresh value per decode: xml.Unmarshal appends into a non-empty slice.
	var second listBucketResult
	decode(t, w, &second)
	if len(second.Contents) != 1 || second.Contents[0].Key != "k3" {
		t.Errorf("second page = %+v", second.Contents)
	}
}

// ---------------------------------------------------------------------------
// Copy and batch delete
// ---------------------------------------------------------------------------

func TestCopyObjectOverHTTP(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "src")
	createNS(t, g, "dst")
	putObj(t, g, "src", "orig.txt", "abc", "text/plain")

	w := do(t, g, http.MethodPut, "/dst/copy.txt", "",
		"x-amz-copy-source", "/src/orig.txt")
	mustStatus(t, w, http.StatusOK)
	var result copyObjectResult
	decode(t, w, &result)
	if result.ETag != `"`+abcHash+`"` {
		t.Errorf("ETag = %s", result.ETag)
	}
	if result.LastModified == "" {
		t.Error("LastModified was not set")
	}

	// The copy carries the source's content and media type.
	w = do(t, g, http.MethodGet, "/dst/copy.txt", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("body = %q", w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want the source's", got)
	}

	// Failure modes.
	w = do(t, g, http.MethodPut, "/dst/x", "", "x-amz-copy-source", "/src/missing")
	mustStatus(t, w, http.StatusNotFound)
	w = do(t, g, http.MethodPut, "/dst/x", "", "x-amz-copy-source", "nokey")
	mustStatus(t, w, http.StatusBadRequest)
}

// The AWS CLI copies anything over its multipart threshold as UploadPartCopy
// calls, one byte range of the source per part.
func TestUploadPartCopyOverHTTP(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "src")
	createNS(t, g, "dst")
	putObj(t, g, "src", "orig.txt", "abcdef", "text/plain")
	wantETag := putObj(t, g, "src", "reference.txt", "abcdef", "text/plain")

	w := do(t, g, http.MethodPost, "/dst/copy.txt?uploads", "")
	mustStatus(t, w, http.StatusOK)
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	partURL := func(n int) string {
		return fmt.Sprintf("/dst/copy.txt?partNumber=%d&uploadId=%s", n, initiated.UploadID)
	}

	var etags []string
	for i, rng := range []string{"bytes=0-3", "bytes=4-5"} {
		w := do(t, g, http.MethodPut, partURL(i+1), "",
			"x-amz-copy-source", "/src/orig.txt", "x-amz-copy-source-range", rng)
		mustStatus(t, w, http.StatusOK)
		var result copyPartResult
		decode(t, w, &result)
		if result.ETag == "" || result.LastModified == "" {
			t.Fatalf("part %d: incomplete CopyPartResult %s", i+1, w.Body.String())
		}
		etags = append(etags, result.ETag)
	}

	manifest := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>
		<Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part>
	</CompleteMultipartUpload>`, etags[0], etags[1])
	w = do(t, g, http.MethodPost, "/dst/copy.txt?uploadId="+initiated.UploadID, manifest)
	mustStatus(t, w, http.StatusOK)

	w = do(t, g, http.MethodGet, "/dst/copy.txt", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abcdef" {
		t.Errorf("assembled copy = %q, want abcdef", w.Body.String())
	}
	if got := w.Header().Get("ETag"); got != wantETag {
		t.Errorf("ETag = %s, want %s: the copy must dedup against the source", got, wantETag)
	}

	// Failure modes.
	w = do(t, g, http.MethodPost, "/dst/other.txt?uploads", "")
	decode(t, w, &initiated)
	other := fmt.Sprintf("/dst/other.txt?partNumber=1&uploadId=%s", initiated.UploadID)
	for _, rng := range []string{"bytes=0-6", "bytes=3-2", "bytes=2-", "0-1"} {
		w = do(t, g, http.MethodPut, other, "", "x-amz-copy-source", "/src/orig.txt", "x-amz-copy-source-range", rng)
		if w.Code != http.StatusBadRequest || errorCode(t, w) != "InvalidArgument" {
			t.Errorf("range %q: %d %s, want 400 InvalidArgument", rng, w.Code, w.Body.String())
		}
	}
	w = do(t, g, http.MethodPut, other, "", "x-amz-copy-source", "/src/missing")
	mustStatus(t, w, http.StatusNotFound)
}

func TestUploadPartCopyEnforcesThePartLimit(t *testing.T) {
	g := newGateway(t, func(c *config.Config) { c.Limits.MaxPartBytes = 3 })
	createNS(t, g, "bkt")
	putObj(t, g, "bkt", "src", "abcdef", "text/plain")
	w := do(t, g, http.MethodPost, "/bkt/dst?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)

	w = do(t, g, http.MethodPut, "/bkt/dst?partNumber=1&uploadId="+initiated.UploadID, "",
		"x-amz-copy-source", "/bkt/src")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "EntityTooLarge" {
		t.Errorf("whole-source part copy over the limit: %d %s", w.Code, w.Body.String())
	}
	w = do(t, g, http.MethodPut, "/bkt/dst?partNumber=1&uploadId="+initiated.UploadID, "",
		"x-amz-copy-source", "/bkt/src", "x-amz-copy-source-range", "bytes=0-2")
	mustStatus(t, w, http.StatusOK)
}

// Tags are not stored, but the AWS CLI reads them before every s3-to-s3 copy,
// so reading them must work.
func TestGetObjectTaggingIsEmpty(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "bkt")
	putObj(t, g, "bkt", "doc", "abc", "text/plain")

	w := do(t, g, http.MethodGet, "/bkt/doc?tagging", "")
	mustStatus(t, w, http.StatusOK)
	var got struct {
		XMLName xml.Name
		TagSet  *struct {
			Tags []struct{} `xml:"Tag"`
		} `xml:"TagSet"`
	}
	decode(t, w, &got)
	if got.XMLName.Local != "Tagging" || got.TagSet == nil || len(got.TagSet.Tags) != 0 {
		t.Errorf("body = %s, want an empty TagSet", w.Body.String())
	}

	w = do(t, g, http.MethodGet, "/bkt/missing?tagging", "")
	mustStatus(t, w, http.StatusNotFound)
	if code := errorCode(t, w); code != "NoSuchKey" {
		t.Errorf("code = %q, want NoSuchKey", code)
	}
}

func TestDeleteObjectsBatch(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")
	putObj(t, g, "files", "a.txt", "abc", "text/plain")
	putObj(t, g, "files", "b.txt", "abc", "text/plain")

	body := `<Delete>
		<Object><Key>a.txt</Key></Object>
		<Object><Key>b.txt</Key></Object>
		<Object><Key>never-existed.txt</Key></Object>
	</Delete>`
	w := do(t, g, http.MethodPost, "/files?delete", body, "Content-Type", "application/xml")
	mustStatus(t, w, http.StatusOK)

	var result deleteResult
	decode(t, w, &result)
	// S3 reports an absent key as deleted too.
	if len(result.Deleted) != 3 {
		t.Errorf("deleted = %+v, want all three reported", result.Deleted)
	}
	if len(result.Errors) != 0 {
		t.Errorf("errors = %+v", result.Errors)
	}

	mustStatus(t, do(t, g, http.MethodGet, "/files/a.txt", ""), http.StatusNotFound)
}

func TestDeleteObjectsQuiet(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")
	putObj(t, g, "files", "a.txt", "abc", "text/plain")

	body := `<Delete><Object><Key>a.txt</Key></Object><Quiet>true</Quiet></Delete>`
	w := do(t, g, http.MethodPost, "/files?delete", body)
	mustStatus(t, w, http.StatusOK)

	var result deleteResult
	decode(t, w, &result)
	if len(result.Deleted) != 0 {
		t.Errorf("quiet mode should suppress Deleted entries, got %+v", result.Deleted)
	}
}

func TestDeleteObjectsMalformedBody(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	w := do(t, g, http.MethodPost, "/files?delete", "<Delete><Object>")
	mustStatus(t, w, http.StatusBadRequest)
	if code := errorCode(t, w); code != "MalformedXML" {
		t.Errorf("code = %q", code)
	}
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

func TestMultipartRoundTrip(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	// Initiate.
	w := do(t, g, http.MethodPost, "/files/big.bin?uploads", "", "Content-Type", "text/plain")
	mustStatus(t, w, http.StatusOK)
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	if initiated.Bucket != "files" || initiated.Key != "big.bin" || initiated.UploadID == "" {
		t.Fatalf("initiate = %+v", initiated)
	}
	uploadID := initiated.UploadID

	// Upload two parts that concatenate to "abc".
	base := "/files/big.bin?uploadId=" + uploadID
	w = do(t, g, http.MethodPut, base+"&partNumber=1", "ab")
	mustStatus(t, w, http.StatusOK)
	etag1 := w.Header().Get("ETag")
	w = do(t, g, http.MethodPut, base+"&partNumber=2", "c")
	mustStatus(t, w, http.StatusOK)
	etag2 := w.Header().Get("ETag")
	if etag1 == "" || etag2 == "" {
		t.Fatal("parts must return ETags")
	}

	// ListParts.
	w = do(t, g, http.MethodGet, base, "")
	mustStatus(t, w, http.StatusOK)
	var parts listPartsResult
	decode(t, w, &parts)
	if len(parts.Parts) != 2 || parts.IsTruncated {
		t.Fatalf("parts = %+v", parts)
	}
	if parts.Parts[0].PartNumber != 1 || parts.Parts[0].Size != 2 {
		t.Errorf("part 1 = %+v", parts.Parts[0])
	}
	if parts.Parts[0].ETag != etag1 {
		t.Errorf("listed etag = %s, want %s", parts.Parts[0].ETag, etag1)
	}

	// ListMultipartUploads.
	w = do(t, g, http.MethodGet, "/files?uploads", "")
	mustStatus(t, w, http.StatusOK)
	var uploads listMultipartUploadsResult
	decode(t, w, &uploads)
	if len(uploads.Uploads) != 1 || uploads.Uploads[0].UploadID != uploadID {
		t.Errorf("uploads = %+v", uploads.Uploads)
	}
	if uploads.Uploads[0].Initiated == "" {
		t.Error("Initiated was not set")
	}

	// Complete, with the ETags echoed back for verification.
	manifest := `<CompleteMultipartUpload>
		<Part><PartNumber>1</PartNumber><ETag>` + etag1 + `</ETag></Part>
		<Part><PartNumber>2</PartNumber><ETag>` + etag2 + `</ETag></Part>
	</CompleteMultipartUpload>`
	w = do(t, g, http.MethodPost, base, manifest, "Content-Type", "application/xml")
	mustStatus(t, w, http.StatusOK)
	var completed completeMultipartUploadResult
	decode(t, w, &completed)
	// The assembled object hashes as the whole content.
	if completed.ETag != `"`+abcHash+`"` {
		t.Errorf("ETag = %s, want the hash of the assembled object", completed.ETag)
	}
	if completed.Location != "/files/big.bin" {
		t.Errorf("Location = %q", completed.Location)
	}

	// The object is readable, with the content type from the initiation.
	w = do(t, g, http.MethodGet, "/files/big.bin", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("body = %q, want abc", w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want the type given at initiation", got)
	}

	// The upload is finished, so its endpoints stop resolving.
	mustStatus(t, do(t, g, http.MethodGet, base, ""), http.StatusNotFound)
}

func TestMultipartAbort(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	w := do(t, g, http.MethodPost, "/files/big.bin?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	base := "/files/big.bin?uploadId=" + initiated.UploadID

	mustStatus(t, do(t, g, http.MethodPut, base+"&partNumber=1", "abc"), http.StatusOK)
	mustStatus(t, do(t, g, http.MethodDelete, base, ""), http.StatusNoContent)
	mustStatus(t, do(t, g, http.MethodGet, base, ""), http.StatusNotFound)
	// The object was never created.
	mustStatus(t, do(t, g, http.MethodGet, "/files/big.bin", ""), http.StatusNotFound)
}

func TestMultipartValidation(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	w := do(t, g, http.MethodPost, "/files/big.bin?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	base := "/files/big.bin?uploadId=" + initiated.UploadID

	mustStatus(t, do(t, g, http.MethodPut, base+"&partNumber=1", "ab"), http.StatusOK)

	tests := []struct {
		name     string
		manifest string
		status   int
		code     string
	}{
		{
			name:     "no parts",
			manifest: `<CompleteMultipartUpload></CompleteMultipartUpload>`,
			status:   http.StatusBadRequest, code: "InvalidPart",
		},
		{
			name: "part never uploaded",
			manifest: `<CompleteMultipartUpload>
				<Part><PartNumber>7</PartNumber></Part></CompleteMultipartUpload>`,
			status: http.StatusBadRequest, code: "InvalidPart",
		},
		{
			name: "descending part numbers",
			manifest: `<CompleteMultipartUpload>
				<Part><PartNumber>2</PartNumber></Part>
				<Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`,
			status: http.StatusBadRequest, code: "InvalidPart",
		},
		{
			name: "etag mismatch",
			manifest: `<CompleteMultipartUpload>
				<Part><PartNumber>1</PartNumber><ETag>"deadbeef"</ETag></Part>
				</CompleteMultipartUpload>`,
			status: http.StatusBadRequest, code: "InvalidPart",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, g, http.MethodPost, base, tc.manifest)
			mustStatus(t, w, tc.status)
			if code := errorCode(t, w); code != tc.code {
				t.Errorf("code = %q, want %q", code, tc.code)
			}
		})
	}

	// Bad part numbers on upload.
	for _, pn := range []string{"0", "10001", "abc"} {
		w := do(t, g, http.MethodPut, base+"&partNumber="+pn, "x")
		mustStatus(t, w, http.StatusBadRequest)
	}

	// An unknown upload id is a 404, whether it is a valid UUID or not.
	for _, id := range []string{"6ba7b810-9dad-11d1-80b4-00c04fd430c8", "garbage"} {
		w := do(t, g, http.MethodGet, "/files/big.bin?uploadId="+id, "")
		mustStatus(t, w, http.StatusNotFound)
		if code := errorCode(t, w); code != "NoSuchUpload" {
			t.Errorf("code = %q for id %q", code, id)
		}
	}
}

// Re-uploading a part supersedes the first attempt.
func TestMultipartPartReplacement(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	w := do(t, g, http.MethodPost, "/files/big.bin?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	base := "/files/big.bin?uploadId=" + initiated.UploadID

	mustStatus(t, do(t, g, http.MethodPut, base+"&partNumber=1", "WRONG"), http.StatusOK)
	mustStatus(t, do(t, g, http.MethodPut, base+"&partNumber=1", "abc"), http.StatusOK)

	manifest := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`
	w = do(t, g, http.MethodPost, base, manifest)
	mustStatus(t, w, http.StatusOK)
	var completed completeMultipartUploadResult
	decode(t, w, &completed)
	if completed.ETag != `"`+abcHash+`"` {
		t.Errorf("ETag = %s, want the replacement's content", completed.ETag)
	}
}

func TestListPartsPagination(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	w := do(t, g, http.MethodPost, "/files/big.bin?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	base := "/files/big.bin?uploadId=" + initiated.UploadID

	for i := 1; i <= 3; i++ {
		mustStatus(t, do(t, g, http.MethodPut, base+"&partNumber="+string(rune('0'+i)), "x"), http.StatusOK)
	}

	w = do(t, g, http.MethodGet, base+"&max-parts=2", "")
	mustStatus(t, w, http.StatusOK)
	var page listPartsResult
	decode(t, w, &page)
	if len(page.Parts) != 2 || !page.IsTruncated {
		t.Fatalf("page = %+v", page)
	}
	if page.NextPartNumberMarker == nil || *page.NextPartNumberMarker != 2 {
		t.Fatalf("NextPartNumberMarker = %v, want 2", page.NextPartNumberMarker)
	}

	w = do(t, g, http.MethodGet, base+"&max-parts=2&part-number-marker=2", "")
	var second listPartsResult
	decode(t, w, &second)
	if len(second.Parts) != 1 || second.Parts[0].PartNumber != 3 {
		t.Errorf("second page parts = %+v, want just part 3", second.Parts)
	}
	if second.IsTruncated {
		t.Error("the final page must not be truncated")
	}
	if second.NextPartNumberMarker != nil {
		t.Error("the final page must not carry a next marker")
	}
}

// ---------------------------------------------------------------------------
// Method handling
// ---------------------------------------------------------------------------

func TestMethodNotAllowed(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	tests := []struct{ name, method, target string }{
		{"service root rejects POST", http.MethodPost, "/"},
		{"namespace rejects PATCH", http.MethodPatch, "/files"},
		{"namespace POST without ?delete", http.MethodPost, "/files"},
		{"object rejects PATCH", http.MethodPatch, "/files/key"},
		{"object POST without ?uploads or ?uploadId", http.MethodPost, "/files/key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, g, tc.method, tc.target, "")
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", w.Code)
			}
			if w.Header().Get("Allow") == "" {
				t.Error("a 405 should advertise the allowed methods")
			}
		})
	}
}

// A signed-auth instance rejects unsigned requests at every level.
func TestUnsignedRequestsRejectedWhenAuthEnabled(t *testing.T) {
	g := newGateway(t)
	g.cfg.Auth = config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     "AKID",
		SecretAccessKey: "secret",
	}

	for _, target := range []string{"/", "/files", "/files/key"} {
		w := do(t, g, http.MethodGet, target, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", target, w.Code)
		}
		if code := errorCode(t, w); code != "AccessDenied" {
			t.Errorf("GET %s code = %q", target, code)
		}
	}
}

// A large body streams through staging rather than being buffered, so a size
// well past any XML limit must still upload and read back byte-exact.
func TestLargeObjectRoundTrip(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	body := strings.Repeat("simplecas", 200_000) // ~1.8 MiB
	w := do(t, g, http.MethodPut, "/files/large", body, "Content-Type", "application/octet-stream")
	mustStatus(t, w, http.StatusOK)

	w = do(t, g, http.MethodGet, "/files/large", "")
	mustStatus(t, w, http.StatusOK)
	got, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("round-tripped %d bytes, want %d", len(got), len(body))
	}
}

// Each of these used to fall through to the plain operation and act on the
// resource itself. They must now be refused and leave it untouched.
func TestUnsupportedSubresourcesLeaveResourcesAlone(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "sub")
	putObj(t, g, "sub", "doc", "abc", "text/plain")

	for _, req := range []struct{ method, target, body string }{
		{http.MethodPut, "/sub/doc?tagging", "<Tagging><TagSet/></Tagging>"},
		{http.MethodDelete, "/sub/doc?tagging", ""},
		{http.MethodDelete, "/sub?cors", ""},
		{http.MethodPut, "/sub?versioning", "<VersioningConfiguration/>"},
	} {
		w := do(t, g, req.method, req.target, req.body)
		mustStatus(t, w, http.StatusNotImplemented)
		if code := errorCode(t, w); code != "NotImplemented" {
			t.Errorf("%s %s: code = %q, want NotImplemented", req.method, req.target, code)
		}
	}

	w := do(t, g, http.MethodGet, "/sub/doc", "")
	mustStatus(t, w, http.StatusOK)
	if w.Body.String() != "abc" {
		t.Errorf("object body = %q after refused subresource calls, want abc", w.Body.String())
	}
	mustStatus(t, do(t, g, http.MethodHead, "/sub", ""), http.StatusOK)
}

// An uploaded HTML page must not render on the app's origin, where it could
// act with a signed-in user's session.
func TestObjectsAreServedDefused(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "web")
	putObj(t, g, "web", "evil.html", "<script>alert(1)</script>", "text/html")
	putObj(t, g, "web", "cat.png", "abc", "image/png")

	w := do(t, g, http.MethodGet, "/web/evil.html", "")
	mustStatus(t, w, http.StatusOK)
	if got := w.Header().Get("Content-Disposition"); got != "attachment" {
		t.Errorf("text/html Content-Disposition = %q, want attachment", got)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "sandbox" {
		t.Errorf("Content-Security-Policy = %q, want sandbox", got)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}

	// HEAD carries the same headers, and a previewable image stays inline.
	w = do(t, g, http.MethodHead, "/web/cat.png", "")
	if got := w.Header().Get("Content-Disposition"); got != "" {
		t.Errorf("image/png Content-Disposition = %q, want inline (unset)", got)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("HEAD X-Content-Type-Options = %q, want nosniff", got)
	}
}

func TestSizeLimitsOverHTTP(t *testing.T) {
	g := newGateway(t, func(c *config.Config) {
		c.Limits.MaxObjectBytes = 3
		c.Limits.MaxPartBytes = 2
	})
	if w := do(t, g, http.MethodPut, "/bucket", ""); w.Code != http.StatusOK {
		t.Fatalf("create bucket: %d", w.Code)
	}

	w := do(t, g, http.MethodPut, "/bucket/big", "abcd")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "EntityTooLarge" {
		t.Errorf("oversize PUT: %d %s, want 400 EntityTooLarge", w.Code, w.Body.String())
	}

	// The framing makes this body longer than the limit on the wire, but the
	// object it decodes to fits.
	framed := "3\r\nabc\r\n0\r\n\r\n"
	w = do(t, g, http.MethodPut, "/bucket/framed", framed,
		"x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		"x-amz-decoded-content-length", "3")
	if w.Code != http.StatusOK {
		t.Errorf("framed PUT that decodes within the limit: %d %s", w.Code, w.Body.String())
	}

	w = do(t, g, http.MethodPost, "/bucket/parts?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	w = do(t, g, http.MethodPut, "/bucket/parts?partNumber=1&uploadId="+initiated.UploadID, "abc")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "EntityTooLarge" {
		t.Errorf("oversize part: %d %s, want 400 EntityTooLarge", w.Code, w.Body.String())
	}
}
