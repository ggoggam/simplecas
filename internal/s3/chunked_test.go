package s3

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

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

// bodyReader must leave an unframed body completely alone.
func TestBodyReaderPassesThroughUnframedBodies(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader("abc"))
	got, err := io.ReadAll(bodyReader(r))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Errorf("body = %q, want abc", got)
	}
}

func TestBodyReaderDecodesFramedBodies(t *testing.T) {
	framed := "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:NSRBwg==\r\n\r\n"
	r := httptest.NewRequest(http.MethodPut, "/ns/key", strings.NewReader(framed))
	r.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")

	got, err := io.ReadAll(bodyReader(r))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Errorf("body = %q, want abc", got)
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
