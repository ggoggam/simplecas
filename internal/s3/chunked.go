// Decoding of AWS chunked payloads.
//
// The AWS SDKs frame a request body when they cannot compute a payload hash up
// front — an unseekable stream, or a request that carries a trailing checksum.
// The body then arrives as application-level chunks:
//
//	<hex-size>[;chunk-signature=…]\r\n<data>\r\n
//	…
//	0[;chunk-signature=…]\r\n
//	[trailer-header: value\r\n]…
//	[x-amz-trailer-signature: …\r\n]
//	\r\n
//
// This is *inside* the HTTP body, so net/http's own chunked transfer decoding
// does not touch it. A server that ignored the framing would store it verbatim
// and silently corrupt the object — the stored bytes would not even hash to the
// ETag it returned.
//
// x-amz-content-sha256 says how the chunks are authenticated:
//
//   - STREAMING-AWS4-HMAC-SHA256-PAYLOAD: every chunk, the final empty one
//     included, carries a chunk-signature chained from the request's own (see
//     chunkSigner). A missing or wrong one fails the body with
//     SignatureDoesNotMatch. Trailers are refused: nothing would sign them.
//   - STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER: the same, and the trailers
//     end with an x-amz-trailer-signature chained from the final chunk's.
//   - STREAMING-UNSIGNED-PAYLOAD-TRAILER: no signatures. The body is held to
//     its trailing checksum instead (see payload.go). This is what the AWS CLI
//     and SDKs send over TLS.
//
// With auth disabled there is no secret to check signatures against, so chunk
// signatures go unchecked; checksums still apply.

package s3

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ggoggam/simplecas/internal/apperr"
)

// The x-amz-content-sha256 values that announce an aws-chunked body.
const (
	streamingSigned          = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamingSignedTrailer   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamingUnsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// trailerSignatureHeader closes a signed trailer.
const trailerSignatureHeader = "x-amz-trailer-signature"

// maxChunkHeaderLine bounds every line of the framing (a chunk header, the
// CRLF after chunk data, a trailer), terminator included, so a malformed body
// cannot make the reader buffer without limit. It is enforced as the line is
// read, not after: see readLine.
const maxChunkHeaderLine = 8 << 10

// errLineTooLong refuses a framing line longer than maxChunkHeaderLine.
var errLineTooLong = errors.New("aws-chunked: chunk header too long")

// maxChunkSizeDigits bounds the hex size field of a chunk header. Sixteen
// digits spell any int64; more can only be padding.
const maxChunkSizeDigits = 16

// maxChunkSize bounds a single declared chunk. The SDKs use 64KiB by default;
// this leaves generous headroom while rejecting an absurd length.
const maxChunkSize = 1 << 30

// maxTrailers bounds how many trailing headers a body may carry. S3 accepts a
// single checksum; the headroom is for whatever else a client adds.
const maxTrailers = 16

// maxTrailerLines and maxTrailerBytes bound the trailer section as it is read,
// before any of it is checked. Every line counts, a repeated name or a repeated
// x-amz-trailer-signature included, and so does every byte of them.
const (
	maxTrailerLines = maxTrailers + 1 // and the trailer signature
	maxTrailerBytes = 8 << 10
)

// isChunkedPayload reports whether the request body carries AWS chunk framing.
//
// Both signals are checked because they are set independently: the
// STREAMING- payload hashes describe how the request was signed, while
// Content-Encoding: aws-chunked describes the body.
func isChunkedPayload(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING-") {
		return true
	}
	for _, encoding := range r.Header.Values("Content-Encoding") {
		if strings.Contains(strings.ToLower(encoding), "aws-chunked") {
			return true
		}
	}
	return false
}

// declaredLength is the object size the client announced, or -1 if it did not:
// x-amz-decoded-content-length for an aws-chunked body, whose Content-Length
// counts the chunk framing too, and Content-Length otherwise.
func declaredLength(r *http.Request) int64 {
	if !isChunkedPayload(r) {
		return r.ContentLength
	}
	n, err := strconv.ParseInt(r.Header.Get("x-amz-decoded-content-length"), 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// lengthCheckedReader fails unless its source yields exactly the declared
// number of bytes.
type lengthCheckedReader struct {
	r         io.Reader
	remaining int64
}

func (l *lengthCheckedReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	if l.remaining < 0 {
		return n, errors.New("aws-chunked: body is longer than x-amz-decoded-content-length")
	}
	if errors.Is(err, io.EOF) && l.remaining > 0 {
		return n, fmt.Errorf("aws-chunked: body is %d bytes shorter than x-amz-decoded-content-length", l.remaining)
	}
	return n, err
}

// chunkedReader decodes AWS chunk framing into the underlying payload.
type chunkedReader struct {
	br *bufio.Reader
	// remaining is how many bytes are left in the chunk being read.
	remaining int64

	// signer, when set, checks every chunk's signature: chunkHash hashes the
	// chunk being read, and chunkSig is the signature its header declared.
	signer    *chunkSigner
	chunkHash hash.Hash
	chunkSig  string
	// allowTrailers says whether the framing may carry trailers at all, and
	// signedTrailers whether they must end in a valid trailer signature.
	allowTrailers  bool
	signedTrailers bool
	// trailers holds the trailing headers, by lowercased name, once read.
	trailers map[string]string

	// done is set once the terminating zero-length chunk and its trailers
	// have been consumed.
	done bool
	err  error
}

// newChunkedReader decodes an unsigned body (STREAMING-UNSIGNED-PAYLOAD-TRAILER).
func newChunkedReader(r io.Reader) *chunkedReader {
	// The buffer is the line limit: readLine refuses a line that fills it.
	br := bufio.NewReaderSize(r, maxChunkHeaderLine)
	return &chunkedReader{br: br, allowTrailers: true, trailers: map[string]string{}}
}

// newSignedChunkedReader decodes a STREAMING-AWS4-HMAC-SHA256-PAYLOAD body,
// with signed trailers when withTrailer is set. A nil signer (auth disabled)
// decodes the framing without checking any signature.
func newSignedChunkedReader(r io.Reader, signer *chunkSigner, withTrailer bool) *chunkedReader {
	c := newChunkedReader(r)
	c.allowTrailers = withTrailer
	if signer != nil {
		c.signer = signer
		c.chunkHash = sha256.New()
		c.signedTrailers = withTrailer
	}
	return c
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.done {
		return 0, io.EOF
	}

	// Start the next chunk when the current one is exhausted.
	if c.remaining == 0 {
		size, err := c.readChunkHeader()
		if errors.Is(err, io.EOF) {
			// The body ended between chunks without the terminating
			// zero-length chunk: the client stopped early, and what
			// arrived is a prefix of the object, not the object.
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return 0, c.fail(err)
		}
		if size == 0 {
			// The final chunk is signed too, over no data, so a signed body
			// cannot be cut short at a chunk boundary and still verify.
			if err := c.verifyChunk(); err != nil {
				return 0, c.fail(err)
			}
			if err := c.consumeTrailers(); err != nil {
				return 0, c.fail(err)
			}
			c.done = true
			return 0, io.EOF
		}
		c.remaining = size
	}

	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := io.ReadFull(c.br, p)
	c.remaining -= int64(n)
	if c.signer != nil {
		c.chunkHash.Write(p[:n])
	}
	if err != nil {
		// A truncated chunk means the client stopped mid-body.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return n, c.fail(io.ErrUnexpectedEOF)
		}
		return n, c.fail(err)
	}

	// Each chunk's data is followed by CRLF. The bytes already handed back are
	// unverified until here: a bad signature fails this read, and with it
	// everything the caller staged.
	if c.remaining == 0 {
		if err := c.expectCRLF(); err != nil {
			return n, c.fail(err)
		}
		if err := c.verifyChunk(); err != nil {
			return n, c.fail(err)
		}
	}
	return n, nil
}

// verifyChunk checks the signature of the chunk just read, when signed.
func (c *chunkedReader) verifyChunk() error {
	if c.signer == nil {
		return nil
	}
	if !c.signer.accept(c.signer.chunkSignature(c.chunkHash.Sum(nil)), c.chunkSig) {
		return apperr.ErrSignatureDoesNotMatch
	}
	return nil
}

// fail records a terminal error so subsequent reads report the same thing.
func (c *chunkedReader) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}

// readChunkHeader parses "<hex-size>[;ext=value…]" and returns the size. On a
// signed body it also takes the chunk-signature extension, which then has to be
// there.
func (c *chunkedReader) readChunkHeader() (int64, error) {
	line, err := c.readLine()
	if err != nil {
		return 0, err
	}
	// Chunk extensions (notably chunk-signature) follow a semicolon.
	sizeField, extension, _ := strings.Cut(line, ";")
	sizeField = strings.TrimSpace(sizeField)
	if sizeField == "" {
		return 0, errors.New("aws-chunked: empty chunk size")
	}
	if len(sizeField) > maxChunkSizeDigits {
		return 0, errors.New("aws-chunked: chunk size field too long")
	}

	size, err := strconv.ParseInt(sizeField, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("aws-chunked: bad chunk size %q", sizeField)
	}
	if size < 0 || size > maxChunkSize {
		return 0, fmt.Errorf("aws-chunked: chunk size %d out of range", size)
	}

	if c.signer != nil {
		signature, ok := strings.CutPrefix(strings.TrimSpace(extension), "chunk-signature=")
		if !ok {
			return 0, apperr.ErrSignatureDoesNotMatch
		}
		c.chunkSig = signature
		c.chunkHash.Reset()
	}
	return size, nil
}

// consumeTrailers reads the trailing headers that follow the final chunk, up to
// the terminating blank line, and keeps them for the checksum check. A body
// that simply ends here is also accepted: not every client sends the blank
// line.
//
// What a trailer signature covers is the headers before it, each as
// "name:value\n", hashed and chained from the final chunk's signature.
func (c *chunkedReader) consumeTrailers() error {
	var canonical strings.Builder
	var signature string
	lines, size := 0, 0
	for {
		line, err := c.readLine()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if !c.allowTrailers {
			return errors.New("aws-chunked: trailers on a body signed without them")
		}
		lines, size = lines+1, size+len(line)
		if lines > maxTrailerLines {
			return errors.New("aws-chunked: too many trailers")
		}
		if size > maxTrailerBytes {
			return errors.New("aws-chunked: trailers too long")
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("aws-chunked: malformed trailer %q", line)
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if name == trailerSignatureHeader {
			signature = value
			continue
		}
		if len(c.trailers) == maxTrailers {
			return errors.New("aws-chunked: too many trailers")
		}
		c.trailers[name] = value
		canonical.WriteString(name + ":" + value + "\n")
	}

	if c.signedTrailers {
		sum := sha256.Sum256([]byte(canonical.String()))
		if !c.signer.accept(c.signer.trailerSignature(sum[:]), signature) {
			return apperr.ErrSignatureDoesNotMatch
		}
	}
	return nil
}

// expectCRLF consumes the CRLF that terminates a chunk's data.
func (c *chunkedReader) expectCRLF() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	if line != "" {
		return fmt.Errorf("aws-chunked: expected CRLF after chunk data, got %q", line)
	}
	return nil
}

// readLine reads one CRLF-terminated line, returning it without the terminator.
//
// The line is read in place in the reader's buffer, which is maxChunkHeaderLine
// long: a line that has not ended by the time the buffer is full is refused
// there, so no more than the limit is ever read or held for one line. This runs
// before any chunk signature is checked, so it cannot trust the sender.
func (c *chunkedReader) readLine() (string, error) {
	line, err := c.br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxChunkHeaderLine {
		return "", errLineTooLong
	}
	if err != nil {
		// A final line without a terminator is still usable.
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return strings.TrimRight(string(line), "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}
