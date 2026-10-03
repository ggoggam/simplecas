package s3

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/storage"
)

// Published digests of "abc", in the form their headers carry them.
const (
	abcSHA256Hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	abcMD5       = "kAFQmDzST7DWlj99KOF/cg=="
	abcCRC32     = "NSRBwg=="
	abcCRC32C    = "Nks/tw=="
	abcSHA1      = "qZk+NkcGgWq6PiVxeFDCbJzQ2J0="
	abcSHA256    = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
)

// helloCRC64NVME is the CRC64NVME the AWS CLI sent for a file holding
// "hello\n": its default checksum, so the one that has to be right.
const helloCRC64NVME = "akP7S61aVgc="

// readWith reads body through newPayload with the given headers, returning
// whatever error the checks produce, up front or at the end of the body.
func readWith(body string, headers ...string) error {
	r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	_, err := readPayload(r)
	return err
}

// codeOf is the S3 error code err renders as, or "" for nil.
func codeOf(err error) string {
	if err == nil {
		return ""
	}
	return apperr.From(err).S3Code()
}

func TestPayloadHoldsTheBodyToItsSignedHash(t *testing.T) {
	if err := readWith("abc", "x-amz-content-sha256", abcSHA256Hex); err != nil {
		t.Errorf("matching body: %v", err)
	}
	if err := readWith("abd", "x-amz-content-sha256", abcSHA256Hex); !errors.Is(err, apperr.ErrContentSHA256Mismatch) {
		t.Errorf("swapped body: err = %v, want XAmzContentSHA256Mismatch", err)
	}
	if err := readWith("abc", "x-amz-content-sha256", strings.ToUpper(abcSHA256Hex)); err != nil {
		t.Errorf("uppercase hex digest: %v", err)
	}
	if err := readWith("whatever", "x-amz-content-sha256", unsignedPayload); err != nil {
		t.Errorf("UNSIGNED-PAYLOAD: %v", err)
	}
}

func TestPayloadChecksDigestHeaders(t *testing.T) {
	tests := []struct{ header, value, body string }{
		{"Content-MD5", abcMD5, "abc"},
		{"x-amz-checksum-crc32", abcCRC32, "abc"},
		{"x-amz-checksum-crc32c", abcCRC32C, "abc"},
		{"x-amz-checksum-crc64nvme", helloCRC64NVME, "hello\n"},
		{"x-amz-checksum-sha1", abcSHA1, "abc"},
		{"x-amz-checksum-sha256", abcSHA256, "abc"},
	}
	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			if err := readWith(tc.body, tc.header, tc.value); err != nil {
				t.Errorf("matching body: %v", err)
			}
			if err := readWith(tc.body+"!", tc.header, tc.value); codeOf(err) != "BadDigest" {
				t.Errorf("altered body: err = %v, want BadDigest", err)
			}
		})
	}
}

// What the AWS CLI sends over TLS: an unsigned aws-chunked body whose checksum
// trails it, announced up front in x-amz-trailer.
func TestPayloadChecksTrailingChecksum(t *testing.T) {
	framed := func(data, trailers string) string {
		return "3\r\n" + data + "\r\n0\r\n" + trailers + "\r\n"
	}
	tests := []struct {
		name     string
		body     string
		declared string
		want     string
	}{
		{"matching", framed("abc", "x-amz-checksum-crc32:"+abcCRC32+"\r\n"), "x-amz-checksum-crc32", ""},
		{"the CLI's default algorithm", "6\r\nhello\n\r\n0\r\nx-amz-checksum-crc64nvme:" + helloCRC64NVME + "\r\n\r\n",
			"x-amz-checksum-crc64nvme", ""},
		{"body altered", framed("abd", "x-amz-checksum-crc32:"+abcCRC32+"\r\n"), "x-amz-checksum-crc32", "BadDigest"},
		{"declared but never sent", framed("abc", ""), "x-amz-checksum-crc32", "InvalidRequest"},
		{"sent but never declared", framed("abc", "x-amz-checksum-crc32:"+abcCRC32+"\r\n"), "", "InvalidRequest"},
		{"sent under another algorithm", framed("abc", "x-amz-checksum-sha1:"+abcSHA1+"\r\n"), "x-amz-checksum-crc32", "InvalidRequest"},
		{"not a checksum", framed("abc", "x-amz-checksum-crc32:nope\r\n"), "x-amz-checksum-crc32", "InvalidRequest"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := []string{"x-amz-content-sha256", streamingUnsignedTrailer}
			if tc.declared != "" {
				headers = append(headers, "x-amz-trailer", tc.declared)
			}
			if err := readWith(tc.body, headers...); codeOf(err) != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// Headers that are malformed in themselves are refused before the body is read.
func TestPayloadRefusesMalformedDigestHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{"payload hash that is neither a digest nor a mode", []string{"x-amz-content-sha256", "nonsense"}, "InvalidArgument"},
		{"short payload hash", []string{"x-amz-content-sha256", abcSHA256Hex[:32]}, "InvalidArgument"},
		{"SigV4a streaming", []string{"x-amz-content-sha256", "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"}, "InvalidArgument"},
		{"a digest over aws-chunked framing", []string{"x-amz-content-sha256", abcSHA256Hex, "Content-Encoding", "aws-chunked"}, "InvalidArgument"},
		{"Content-MD5 not base64", []string{"Content-MD5", "not base64!"}, "InvalidDigest"},
		{"Content-MD5 the wrong length", []string{"Content-MD5", abcCRC32}, "InvalidDigest"},
		{"checksum not base64", []string{"x-amz-checksum-crc32", "!!"}, "InvalidRequest"},
		{"checksum the wrong length", []string{"x-amz-checksum-crc32", abcSHA1}, "InvalidRequest"},
		{"unsupported trailer", []string{"x-amz-content-sha256", streamingUnsignedTrailer, "x-amz-trailer", "x-amz-checksum-md5"}, "InvalidArgument"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader("abc"))
			for i := 0; i+1 < len(tc.headers); i += 2 {
				r.Header.Set(tc.headers[i], tc.headers[i+1])
			}
			if _, err := newPayload(r, nil); codeOf(err) != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Through the gateway
// ---------------------------------------------------------------------------

// storedKeys lists what the blob store holds under prefix.
func storedKeys(t *testing.T, g *Gateway, prefix string) []string {
	t.Helper()
	var keys []string
	iter := g.blob.List(&blob.ListOptions{Prefix: prefix})
	for {
		obj, err := iter.Next(t.Context())
		if errors.Is(err, io.EOF) {
			return keys
		}
		if err != nil {
			t.Fatalf("list %s: %v", prefix, err)
		}
		keys = append(keys, obj.Key)
	}
}

// assertNothingStored checks that a refused upload left nothing behind: no
// object or blob row, no blob bytes, no staging file.
func (f *tenantFixture) assertNothingStored(t *testing.T) {
	t.Helper()
	for _, table := range []string{"objects", "blobs", "multipart_parts"} {
		var n int
		if err := f.pool.QueryRow(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s has %d rows after a refused upload", table, n)
		}
	}
	assertNoBytesStored(t, f.g)
}

func assertNoBytesStored(t *testing.T, g *Gateway) {
	t.Helper()
	for _, prefix := range []string{storage.StagingPrefix, "blobs/"} {
		if keys := storedKeys(t, g, prefix); len(keys) != 0 {
			t.Errorf("blob store still holds %v after a refused upload", keys)
		}
	}
}

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// A captured signed request is good for 15 minutes. Before the body was held
// to x-amz-content-sha256, anyone holding one could send different bytes under
// it and have them stored as the signer's.
func TestSwappedBodyUnderSignedHeadersIsRefused(t *testing.T) {
	f := newTenantFixture(t)

	w := f.asA(t, http.MethodPut, "/ns-a/doc.txt", "evil", "x-amz-content-sha256", sha256Of("abc"))
	mustCode(t, w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
	f.assertNothingStored(t)
	mustCode(t, f.asA(t, http.MethodGet, "/ns-a/doc.txt", ""), http.StatusNotFound, "NoSuchKey")

	// The same request with the bytes it was signed over goes through.
	w = f.asA(t, http.MethodPut, "/ns-a/doc.txt", "abc", "x-amz-content-sha256", sha256Of("abc"))
	mustCode(t, w, http.StatusOK, "")
	if got := w.Header().Get("ETag"); got != quotedETag(abcHash) {
		t.Errorf("ETag = %s, want %s", got, quotedETag(abcHash))
	}
}

func TestSwappedPartUnderSignedHeadersIsRefused(t *testing.T) {
	f := newTenantFixture(t)

	var initiated initiateMultipartUploadResult
	decode(t, f.asA(t, http.MethodPost, "/ns-a/big.bin?uploads", ""), &initiated)
	part := "/ns-a/big.bin?partNumber=1&uploadId=" + initiated.UploadID

	w := f.asA(t, http.MethodPut, part, "evil", "x-amz-content-sha256", sha256Of("abc"))
	mustCode(t, w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
	f.assertNothingStored(t)

	var parts listPartsResult
	decode(t, f.asA(t, http.MethodGet, "/ns-a/big.bin?uploadId="+initiated.UploadID, ""), &parts)
	if len(parts.Parts) != 0 {
		t.Errorf("a refused part was recorded: %+v", parts.Parts)
	}
}

// The batch-delete manifest is a body too: swapping it would turn someone's
// signed delete of one key into a delete of others.
func TestSwappedDeleteManifestIsRefused(t *testing.T) {
	f := newTenantFixture(t)
	mustCode(t, f.asA(t, http.MethodPut, "/ns-a/keep.txt", "abc"), http.StatusOK, "")

	signedFor := `<Delete><Object><Key>other.txt</Key></Object></Delete>`
	sent := `<Delete><Object><Key>keep.txt</Key></Object></Delete>`
	w := f.asA(t, http.MethodPost, "/ns-a?delete", sent, "x-amz-content-sha256", sha256Of(signedFor))
	mustCode(t, w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")

	if got := f.asA(t, http.MethodGet, "/ns-a/keep.txt", "").Body.String(); got != "abc" {
		t.Fatalf("keep.txt after a refused delete = %q, want abc", got)
	}
}

// S3 requires x-amz-content-sha256 on every SigV4 request; without it the
// signature would hold the body to nothing.
func TestSignedRequestWithoutPayloadHashIsRefused(t *testing.T) {
	f := newTenantFixture(t)

	r := httptest.NewRequest(http.MethodPut, "/ns-a/doc.txt", strings.NewReader("abc"))
	r.Host = "cas.example.com"
	signAt(r, f.keyA, f.secretA, now(), "s3")
	r.Header.Del("x-amz-content-sha256")
	w := httptest.NewRecorder()
	f.g.ServeHTTP(w, r)

	mustCode(t, w, http.StatusBadRequest, "InvalidRequest")
	f.assertNothingStored(t)
}

// signedStream sends data as a STREAMING-AWS4-HMAC-SHA256-PAYLOAD body, the
// chunks signed in a chain from the request's own signature. tamper, when set,
// rewrites the framed body after signing.
func (f *tenantFixture) signedStream(t *testing.T, target string, chunks []string, tamper func(string) string) *httptest.ResponseRecorder {
	t.Helper()
	size := 0
	for _, c := range chunks {
		size += len(c)
	}
	r := httptest.NewRequest(http.MethodPut, target, nil)
	r.Host = "cas.example.com"
	r.Header.Set("x-amz-content-sha256", streamingSigned)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("x-amz-decoded-content-length", strconv.Itoa(size))
	signAt(r, f.keyA, f.secretA, now(), "s3")

	parsed, ok := parseAuthHeader(r.Header.Get("Authorization"))
	if !ok {
		t.Fatal("signAt produced an unparseable Authorization header")
	}
	signer := &chunkSigner{
		key:     signingKey(f.secretA, parsed.dateStamp, parsed.region, parsed.service),
		amzDate: r.Header.Get("x-amz-date"),
		scope:   parsed.dateStamp + "/" + parsed.region + "/" + parsed.service + "/aws4_request",
		prev:    parsed.signature,
	}
	var body strings.Builder
	for _, c := range append(chunks, "") {
		sum := sha256.Sum256([]byte(c))
		sig := signer.chunkSignature(sum[:])
		signer.accept(sig, sig)
		body.WriteString(strconv.FormatInt(int64(len(c)), 16) + ";chunk-signature=" + sig + "\r\n" + c)
		if c != "" {
			body.WriteString("\r\n")
		}
	}
	body.WriteString("\r\n")

	framed := body.String()
	if tamper != nil {
		framed = tamper(framed)
	}
	r.Body = io.NopCloser(strings.NewReader(framed))
	w := httptest.NewRecorder()
	f.g.ServeHTTP(w, r)
	return w
}

func TestSignedStreamingUploadIsVerifiedChunkByChunk(t *testing.T) {
	f := newTenantFixture(t)

	w := f.signedStream(t, "/ns-a/doc.txt", []string{"ab", "c"}, func(s string) string {
		return strings.Replace(s, "\r\nab\r\n", "\r\nxy\r\n", 1)
	})
	mustCode(t, w, http.StatusForbidden, "SignatureDoesNotMatch")
	f.assertNothingStored(t)

	w = f.signedStream(t, "/ns-a/doc.txt", []string{"ab", "c"}, nil)
	mustCode(t, w, http.StatusOK, "")
	if got := w.Header().Get("ETag"); got != quotedETag(abcHash) {
		t.Errorf("ETag = %s, want %s", got, quotedETag(abcHash))
	}
}

// A body that does not match a checksum it was sent with is refused and leaves
// nothing behind, whether the checksum came as a header or a trailer; one that
// matches has it echoed back, as S3 does.
func TestChecksumMismatchStoresNothing(t *testing.T) {
	g := newGateway(t)
	createNS(t, g, "files")

	trailed := func(data string) string {
		return "3\r\n" + data + "\r\n0\r\nx-amz-checksum-crc32:" + abcCRC32 + "\r\n\r\n"
	}
	trailerHeaders := []string{
		"x-amz-content-sha256", streamingUnsignedTrailer,
		"x-amz-decoded-content-length", "3",
		"x-amz-trailer", "x-amz-checksum-crc32",
	}
	refused := []struct {
		name    string
		body    string
		headers []string
	}{
		{"Content-MD5", "abd", []string{"Content-MD5", abcMD5}},
		{"checksum header", "abd", []string{"x-amz-checksum-crc32", abcCRC32}},
		{"trailing checksum", trailed("abd"), trailerHeaders},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, g, http.MethodPut, "/files/doc.txt", tc.body, tc.headers...)
			mustStatus(t, w, http.StatusBadRequest)
			if code := errorCode(t, w); code != "BadDigest" {
				t.Errorf("code = %q, want BadDigest", code)
			}
			mustStatus(t, do(t, g, http.MethodGet, "/files/doc.txt", ""), http.StatusNotFound)
			assertNoBytesStored(t, g)
		})
	}

	w := do(t, g, http.MethodPut, "/files/doc.txt", trailed("abc"), trailerHeaders...)
	mustStatus(t, w, http.StatusOK)
	if got := w.Header().Get("x-amz-checksum-crc32"); got != abcCRC32 {
		t.Errorf("x-amz-checksum-crc32 on the response = %q, want %q", got, abcCRC32)
	}

	w = do(t, g, http.MethodPost, "/files/big.bin?uploads", "")
	var initiated initiateMultipartUploadResult
	decode(t, w, &initiated)
	part := "/files/big.bin?partNumber=1&uploadId=" + initiated.UploadID
	w = do(t, g, http.MethodPut, part, "abd", "x-amz-checksum-sha256", abcSHA256)
	mustStatus(t, w, http.StatusBadRequest)
	if code := errorCode(t, w); code != "BadDigest" {
		t.Errorf("part code = %q, want BadDigest", code)
	}
	w = do(t, g, http.MethodPut, part, "abc", "x-amz-checksum-sha256", abcSHA256)
	mustStatus(t, w, http.StatusOK)
	if got := w.Header().Get("x-amz-checksum-sha256"); got != abcSHA256 {
		t.Errorf("x-amz-checksum-sha256 on the part response = %q, want %q", got, abcSHA256)
	}
}
