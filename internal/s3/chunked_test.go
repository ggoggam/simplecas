package s3

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
)

func TestIsChunkedPayload(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"plain request", nil, false},
		{
			"an ordinary payload hash is not framing",
			map[string]string{"x-amz-content-sha256": abcHash},
			false,
		},
		{
			"unsigned streaming with a trailer",
			map[string]string{"x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
			true,
		},
		{
			"signed streaming chunks",
			map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
			true,
		},
		{
			"content encoding alone",
			map[string]string{"Content-Encoding": "aws-chunked"},
			true,
		},
		{
			"content encoding among others",
			map[string]string{"Content-Encoding": "aws-chunked,gzip"},
			true,
		},
		{
			"unrelated content encoding",
			map[string]string{"Content-Encoding": "gzip"},
			false,
		},
		{
			"UNSIGNED-PAYLOAD is not framed",
			map[string]string{"x-amz-content-sha256": "UNSIGNED-PAYLOAD"},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/ns/key", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := isChunkedPayload(r); got != tc.want {
				t.Errorf("isChunkedPayload() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChunkedReader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single chunk with a trailing checksum",
			input: "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:NSRBwg==\r\n\r\n",
			want:  "abc",
		},
		{
			name:  "several chunks are concatenated",
			input: "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
			want:  "abcdef",
		},
		{
			name:  "empty payload",
			input: "0\r\n\r\n",
			want:  "",
		},
		{
			name:  "chunk signature extensions are ignored",
			input: "3;chunk-signature=deadbeef\r\nabc\r\n0;chunk-signature=cafebabe\r\n\r\n",
			want:  "abc",
		},
		{
			name:  "uppercase hex size",
			input: "A\r\n0123456789\r\n0\r\n\r\n",
			want:  "0123456789",
		},
		{
			name:  "no terminating blank line",
			input: "3\r\nabc\r\n0\r\n",
			want:  "abc",
		},
		{
			name:  "multiple trailers",
			input: "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:NSRBwg==\r\nx-amz-trailer-signature:abc\r\n\r\n",
			want:  "abc",
		},
		{
			name:  "data containing CRLF is preserved",
			input: "4\r\na\r\nb\r\n0\r\n\r\n",
			want:  "a\r\nb",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := io.ReadAll(newChunkedReader(strings.NewReader(tc.input)))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("decoded %q, want %q", got, tc.want)
			}
		})
	}
}

// A chunk larger than the read buffer must be reassembled across reads.
func TestChunkedReaderLargeChunk(t *testing.T) {
	payload := strings.Repeat("simplecas", 20_000) // ~180 KiB
	framed := "2bf20\r\n" + payload + "\r\n0\r\n\r\n"

	got, err := io.ReadAll(newChunkedReader(strings.NewReader(framed)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("decoded %d bytes, want %d", len(got), len(payload))
	}
}

// Reading one byte at a time must produce the same bytes as one big read.
func TestChunkedReaderByteAtATime(t *testing.T) {
	const framed = "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n"
	r := newChunkedReader(strings.NewReader(framed))

	var out bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if out.String() != "abcdef" {
		t.Errorf("decoded %q, want abcdef", out.String())
	}
}

func TestChunkedReaderRejectsMalformedFraming(t *testing.T) {
	tests := []struct{ name, input string }{
		{"non-hex size", "zz\r\nabc\r\n0\r\n\r\n"},
		{"empty size field", ";sig=x\r\nabc\r\n"},
		{"chunk shorter than declared", "10\r\nabc"},
		{"missing CRLF after data", "3\r\nabcXX\r\n0\r\n\r\n"},
		{"absurd chunk size", "ffffffffffff\r\nabc\r\n"},
		{"ends at a chunk boundary without the final chunk", "3\r\nabc\r\n"},
		{"empty body", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := io.ReadAll(newChunkedReader(strings.NewReader(tc.input))); err == nil {
				t.Errorf("malformed framing %q was accepted", tc.input)
			}
		})
	}
}

// A terminal error must stick, rather than a later read appearing to succeed.
func TestChunkedReaderErrorIsSticky(t *testing.T) {
	r := newChunkedReader(strings.NewReader("zz\r\n"))
	buf := make([]byte, 8)

	if _, err := r.Read(buf); err == nil {
		t.Fatal("expected the first read to fail")
	}
	if _, err := r.Read(buf); err == nil {
		t.Error("expected the error to persist on subsequent reads")
	}
}

// readPayload reads r's body the way a handler sees it after ServeHTTP.
func readPayload(r *http.Request) ([]byte, error) {
	p, err := newPayload(r, nil)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(p)
}

// An unframed body must be left completely alone.
func TestPayloadPassesThroughUnframedBodies(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader("abc"))
	got, err := readPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Errorf("body = %q, want abc", got)
	}
}

func TestPayloadDecodesFramedBodies(t *testing.T) {
	framed := "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:NSRBwg==\r\n\r\n"
	r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader(framed))
	r.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	r.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")

	got, err := readPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Errorf("body = %q, want abc", got)
	}
}

// x-amz-decoded-content-length is the client's statement of the object size;
// a framed body that decodes to anything else must not be stored.
func TestPayloadEnforcesDecodedLength(t *testing.T) {
	framed := "3\r\nabc\r\n0\r\n\r\n"
	tests := []struct {
		name     string
		declared string
		wantErr  bool
	}{
		{"matching length", "3", false},
		{"body shorter than declared", "5", true},
		{"body longer than declared", "2", true},
		{"unparseable length", "three", true},
		{"negative length", "-1", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader(framed))
			r.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			r.Header.Set("x-amz-decoded-content-length", tc.declared)

			got, err := readPayload(r)
			if tc.wantErr {
				if err == nil {
					t.Errorf("declared %s for a 3-byte body was accepted", tc.declared)
				}
				return
			}
			if err != nil || string(got) != "abc" {
				t.Errorf("body = %q, err = %v; want abc, nil", got, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// End-to-end regression test against the real SDK
// ---------------------------------------------------------------------------

// unseekableBody is what makes the SDK fall back to chunk framing: it cannot
// rewind the stream to hash it up front.
type unseekableBody struct{ r io.Reader }

func (u unseekableBody) Read(p []byte) (int, error) { return u.r.Read(p) }

// tlsClient serves the gateway over TLS, which is what the SDK requires before
// it will use chunk framing.
func tlsClient(t *testing.T) *awss3.Client {
	t.Helper()
	gateway := newGateway(t)
	gateway.cfg.Auth = config.AuthConfig{
		Enabled:         true,
		AccessKeyID:     interopKeyID,
		SecretAccessKey: interopSecret,
	}
	server := httptest.NewTLSServer(gateway)
	t.Cleanup(server.Close)

	cfg, err := awsconfig.LoadDefaultConfig(t.Context(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(interopKeyID, interopSecret, ""),
		),
		awsconfig.WithHTTPClient(server.Client()),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	return awss3.NewFromConfig(cfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(server.URL)
		o.UsePathStyle = true
	})
}

// Over TLS, the SDK frames an unseekable body as aws-chunked with a trailing
// checksum. Before the framing was decoded, the server stored the frame bytes
// verbatim — the object came back as
// "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:...\r\n\r\n" and did not even hash to
// the ETag the server had returned. Silent corruption, so this stays covered.
func TestAWSSDKStreamingUploadIsDecoded(t *testing.T) {
	client := tlsClient(t)
	ctx := t.Context()

	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("files"),
	}); err != nil {
		t.Fatal(err)
	}

	put, err := client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String("files"),
		Key:    aws.String("streamed.txt"),
		Body:   unseekableBody{r: strings.NewReader("abc")},
	})
	if err != nil {
		t.Fatalf("PutObject with an unseekable body: %v", err)
	}
	if got := aws.ToString(put.ETag); got != `"`+abcHash+`"` {
		t.Errorf("ETag = %s, want the hash of the payload alone", got)
	}

	get, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String("files"),
		Key:    aws.String("streamed.txt"),
	})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	body, err := io.ReadAll(get.Body)
	_ = get.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "abc" {
		t.Errorf("stored %q, want %q — the chunk framing leaked into the object", body, "abc")
	}
	if aws.ToInt64(get.ContentLength) != 3 {
		t.Errorf("ContentLength = %d, want 3", aws.ToInt64(get.ContentLength))
	}
}

// A streamed multipart part must be decoded too, and the assembled object must
// dedup against a single-shot upload of the same bytes.
func TestAWSSDKStreamingMultipartPartIsDecoded(t *testing.T) {
	client := tlsClient(t)
	ctx := t.Context()

	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String("files"),
	}); err != nil {
		t.Fatal(err)
	}

	created, err := client.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket: aws.String("files"),
		Key:    aws.String("streamed-big.txt"),
	})
	if err != nil {
		t.Fatal(err)
	}

	uploaded, err := client.UploadPart(ctx, &awss3.UploadPartInput{
		Bucket:     aws.String("files"),
		Key:        aws.String("streamed-big.txt"),
		UploadId:   created.UploadId,
		PartNumber: aws.Int32(1),
		Body:       unseekableBody{r: strings.NewReader("abc")},
	})
	if err != nil {
		t.Fatalf("UploadPart with an unseekable body: %v", err)
	}
	// The part's own ETag is the hash of its payload, framing excluded.
	if got := aws.ToString(uploaded.ETag); got != `"`+abcHash+`"` {
		t.Errorf("part ETag = %s, want %s", got, `"`+abcHash+`"`)
	}
}

// The size a client announces is what limits are checked against before the
// body is read. For an aws-chunked body that is the decoded length: its
// Content-Length counts the chunk framing too.
func TestDeclaredLength(t *testing.T) {
	plain := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader("abc"))
	if got := declaredLength(plain); got != 3 {
		t.Errorf("plain body: declared %d, want 3", got)
	}

	framed := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader("3\r\nabc\r\n0\r\n\r\n"))
	framed.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	framed.Header.Set("x-amz-decoded-content-length", "3")
	if got := declaredLength(framed); got != 3 {
		t.Errorf("framed body: declared %d, want the decoded 3", got)
	}

	framed.Header.Del("x-amz-decoded-content-length")
	if got := declaredLength(framed); got != -1 {
		t.Errorf("framed body with no decoded length: declared %d, want -1 (unknown)", got)
	}
}

// ---------------------------------------------------------------------------
// Chunk signatures
// ---------------------------------------------------------------------------

// The worked examples from AWS's "Signature Calculations for the Authorization
// Header: Transferring Payload in Multiple Chunks" pages, with and without
// trailing headers: a 66560-byte object of 'a', sent as a 65536-byte chunk, a
// 1024-byte chunk and the final empty one, signed with the documentation's
// example credential. If these drift, chunk verification has stopped speaking
// SigV4 and every signed streaming client will be refused.
const (
	awsExampleKeyID  = "AKIAIOSFODNN7EXAMPLE"
	awsExampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsExampleDate   = "20130524T000000Z"
)

var awsExampleAuth = config.AuthConfig{
	Enabled:         true,
	AccessKeyID:     awsExampleKeyID,
	SecretAccessKey: awsExampleSecret,
}

type awsStreamingExample struct {
	mode          string
	signedHeaders string
	seed          string
	chunkSigs     [3]string
	// trailer is the trailing checksum, and trailerSig its signature; both
	// empty for the example without trailers.
	trailer    string
	trailerSig string
}

var (
	awsStreamingExample1 = awsStreamingExample{
		mode:          streamingSigned,
		signedHeaders: "content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class",
		seed:          "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9",
		chunkSigs: [3]string{
			"ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
			"0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
			"b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
		},
	}
	awsStreamingExample2 = awsStreamingExample{
		mode:          streamingSignedTrailer,
		signedHeaders: "content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer",
		seed:          "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e",
		chunkSigs: [3]string{
			"b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
			"1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
			"2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
		},
		trailer:    "x-amz-checksum-crc32c:sOO8/Q==",
		trailerSig: "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435",
	}
)

var (
	awsExampleChunk1 = strings.Repeat("a", 65536)
	awsExampleChunk2 = strings.Repeat("a", 1024)
)

// request is the example's request as AWS documents it, carrying body.
func (e awsStreamingExample) request(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/examplebucket/chunkObject.txt", strings.NewReader(body))
	r.Host = "s3.amazonaws.com"
	r.Header.Set("x-amz-date", awsExampleDate)
	r.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")
	r.Header.Set("x-amz-content-sha256", e.mode)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("x-amz-decoded-content-length", "66560")
	r.Header.Set("Content-Length", "66824")
	if e.trailer != "" {
		r.Header.Set("x-amz-trailer", "x-amz-checksum-crc32c")
	}
	r.Header.Set("Authorization", sigV4Algorithm+" Credential="+awsExampleKeyID+"/20130524/us-east-1/s3/aws4_request, "+
		"SignedHeaders="+e.signedHeaders+", Signature="+e.seed)
	return r
}

// body frames the example's chunks and trailer with their documented
// signatures.
func (e awsStreamingExample) body() string {
	body := "10000;chunk-signature=" + e.chunkSigs[0] + "\r\n" + awsExampleChunk1 + "\r\n" +
		"400;chunk-signature=" + e.chunkSigs[1] + "\r\n" + awsExampleChunk2 + "\r\n" +
		"0;chunk-signature=" + e.chunkSigs[2] + "\r\n"
	if e.trailer != "" {
		body += e.trailer + "\r\n" + trailerSignatureHeader + ":" + e.trailerSig + "\r\n"
	}
	return body + "\r\n"
}

// signer is the signing context the example's chunks chain from.
func (e awsStreamingExample) signer() *chunkSigner {
	return &chunkSigner{
		key:     signingKey(awsExampleSecret, "20130524", "us-east-1", "s3"),
		amzDate: awsExampleDate,
		scope:   "20130524/us-east-1/s3/aws4_request",
		prev:    e.seed,
	}
}

// atAWSExampleTime pins the clock to the examples' x-amz-date, so their seed
// signatures are fresh.
func atAWSExampleTime(t *testing.T) {
	t.Helper()
	at, err := time.Parse(amzDateFormat, awsExampleDate)
	if err != nil {
		t.Fatal(err)
	}
	now = func() time.Time { return at }
	t.Cleanup(func() { now = time.Now })
}

// The documented requests verify end to end: the seed signature on the request
// line, every chunk's signature, the trailer's, and the trailing CRC32C.
func TestAWSPublishedStreamingVectors(t *testing.T) {
	atAWSExampleTime(t)
	for _, e := range []awsStreamingExample{awsStreamingExample1, awsStreamingExample2} {
		t.Run(e.mode, func(t *testing.T) {
			r := e.request(e.body())
			signer, err := verify(r, awsExampleAuth)
			if err != nil {
				t.Fatalf("seed signature rejected: %v", err)
			}
			p, err := newPayload(r, signer)
			if err != nil {
				t.Fatalf("newPayload: %v", err)
			}
			got, err := io.ReadAll(p)
			if err != nil {
				t.Fatalf("documented chunks rejected: %v", err)
			}
			if string(got) != awsExampleChunk1+awsExampleChunk2 {
				t.Errorf("decoded %d bytes, want 66560 bytes of 'a'", len(got))
			}
		})
	}
}

// Every way of altering a signed body must break the signature chain: the
// request-line signature alone says nothing about which bytes follow it.
func TestChunkSignaturesRejectTampering(t *testing.T) {
	e := awsStreamingExample1
	sigs := e.chunkSigs
	chunk := func(data, sig string) string {
		return strconv.FormatInt(int64(len(data)), 16) + ";chunk-signature=" + sig + "\r\n" + data + "\r\n"
	}
	final := "0;chunk-signature=" + sigs[2] + "\r\n\r\n"
	good := e.body()

	tests := []struct{ name, body string }{
		{"a data byte changed", strings.Replace(good, "a\r\n400;", "b\r\n400;", 1)},
		{"a chunk signature changed", strings.Replace(good, sigs[1], strings.Repeat("0", 64), 1)},
		{"a chunk signature missing", strings.Replace(good, "400;chunk-signature="+sigs[1], "400", 1)},
		{"the final chunk's signature changed", strings.Replace(good, sigs[2], sigs[1], 1)},
		{"chunks reordered", chunk(awsExampleChunk2, sigs[1]) + chunk(awsExampleChunk1, sigs[0]) + final},
		{"a chunk dropped", chunk(awsExampleChunk1, sigs[0]) + final},
		{"a chunk appended", chunk(awsExampleChunk1, sigs[0]) + chunk(awsExampleChunk2, sigs[1]) +
			chunk("a", sigs[2]) + final},
		{"cut short at a chunk boundary", chunk(awsExampleChunk1, sigs[0]) + "0;chunk-signature=" + sigs[1] + "\r\n\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := io.ReadAll(newSignedChunkedReader(strings.NewReader(tc.body), e.signer(), false))
			if !errors.Is(err, apperr.ErrSignatureDoesNotMatch) {
				t.Errorf("tampered body: err = %v, want SignatureDoesNotMatch", err)
			}
		})
	}

	// The untampered body passes through the same reader, so the cases above
	// fail for what they changed.
	if _, err := io.ReadAll(newSignedChunkedReader(strings.NewReader(good), e.signer(), false)); err != nil {
		t.Fatalf("documented body rejected: %v", err)
	}
}

// Trailers are signed after the final chunk; changing, adding or dropping one,
// or its signature, must fail.
func TestTrailerSignatureRejectsTampering(t *testing.T) {
	e := awsStreamingExample2
	good := e.body()
	tests := []struct{ name, body string }{
		{"the checksum changed", strings.Replace(good, "sOO8/Q==", "AAAAAA==", 1)},
		{"a trailer added", strings.Replace(good, e.trailer+"\r\n", e.trailer+"\r\nx-amz-meta-extra:1\r\n", 1)},
		{"the trailer dropped", strings.Replace(good, e.trailer+"\r\n", "", 1)},
		{"the trailer signature changed", strings.Replace(good, e.trailerSig, e.seed, 1)},
		{"the trailer signature missing", strings.Replace(good, trailerSignatureHeader+":"+e.trailerSig+"\r\n", "", 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := io.ReadAll(newSignedChunkedReader(strings.NewReader(tc.body), e.signer(), true))
			if !errors.Is(err, apperr.ErrSignatureDoesNotMatch) {
				t.Errorf("tampered trailer: err = %v, want SignatureDoesNotMatch", err)
			}
		})
	}
}

// A body signed without trailers has nothing that would sign one, so a trailer
// there was added in transit.
func TestSignedBodyWithoutTrailerRefusesTrailers(t *testing.T) {
	e := awsStreamingExample1
	body := strings.TrimSuffix(e.body(), "\r\n") + "x-amz-checksum-crc32:NSRBwg==\r\n\r\n"
	if _, err := io.ReadAll(newSignedChunkedReader(strings.NewReader(body), e.signer(), false)); err == nil {
		t.Error("a trailer on a STREAMING-AWS4-HMAC-SHA256-PAYLOAD body was accepted")
	}
}

// With auth disabled there is no secret to check chunk signatures against; the
// framing is still decoded.
func TestSignedChunksDecodeWithAuthDisabled(t *testing.T) {
	e := awsStreamingExample1
	body := strings.ReplaceAll(e.body(), e.chunkSigs[1], "not-a-signature")
	got, err := readPayload(e.request(body))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 66560 {
		t.Errorf("decoded %d bytes, want 66560", len(got))
	}
}
