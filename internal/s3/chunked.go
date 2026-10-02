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
//	\r\n
//
// This is *inside* the HTTP body, so net/http's own chunked transfer decoding
// does not touch it. A server that ignored the framing would store it verbatim
// and silently corrupt the object — the stored bytes would not even hash to the
// ETag it returned.
//
// Chunk signatures are not verified. The signature covers the same credential
// already checked on the request line, and the previous implementation did not
// support this framing at all, so decoding without per-chunk verification is
// the conservative step. Callers on the streaming-signed path therefore get
// their bytes stored correctly rather than rejected.

package s3

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxChunkHeaderLine bounds a chunk header, so a malformed body cannot make the
// reader buffer without limit.
const maxChunkHeaderLine = 8 << 10

// maxChunkSize bounds a single declared chunk. The SDKs use 64KiB by default;
// this leaves generous headroom while rejecting an absurd length.
const maxChunkSize = 1 << 30

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

// bodyReader returns the request body, unwrapping AWS chunk framing when
// present so the caller always sees the object's real bytes.
//
// A framed body is also held to x-amz-decoded-content-length when the client
// sends it (the SDKs always do), so a body that decodes cleanly but to the
// wrong length fails instead of being stored short.
func bodyReader(r *http.Request) io.Reader {
	if !isChunkedPayload(r) {
		return r.Body
	}
	decoded := newChunkedReader(r.Body)
	raw := r.Header.Get("x-amz-decoded-content-length")
	if raw == "" {
		return decoded
	}
	want, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || want < 0 {
		return errReader{fmt.Errorf("aws-chunked: bad x-amz-decoded-content-length %q", raw)}
	}
	return &lengthCheckedReader{r: decoded, remaining: want}
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

// errReader fails every read with err.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// chunkedReader decodes AWS chunk framing into the underlying payload.
type chunkedReader struct {
	br *bufio.Reader
	// remaining is how many bytes are left in the chunk being read.
	remaining int64
	// done is set once the terminating zero-length chunk and its trailers
	// have been consumed.
	done bool
	err  error
}

func newChunkedReader(r io.Reader) *chunkedReader {
	return &chunkedReader{br: bufio.NewReader(r)}
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
	if err != nil {
		// A truncated chunk means the client stopped mid-body.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return n, c.fail(io.ErrUnexpectedEOF)
		}
		return n, c.fail(err)
	}

	// Each chunk's data is followed by CRLF.
	if c.remaining == 0 {
		if err := c.expectCRLF(); err != nil {
			return n, c.fail(err)
		}
	}
	return n, nil
}

// fail records a terminal error so subsequent reads report the same thing.
func (c *chunkedReader) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}

// readChunkHeader parses "<hex-size>[;ext=value…]" and returns the size.
func (c *chunkedReader) readChunkHeader() (int64, error) {
	line, err := c.readLine()
	if err != nil {
		return 0, err
	}
	// Chunk extensions (notably chunk-signature) follow a semicolon.
	sizeField, _, _ := strings.Cut(line, ";")
	sizeField = strings.TrimSpace(sizeField)
	if sizeField == "" {
		return 0, errors.New("aws-chunked: empty chunk size")
	}

	size, err := strconv.ParseInt(sizeField, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("aws-chunked: bad chunk size %q", sizeField)
	}
	if size < 0 || size > maxChunkSize {
		return 0, fmt.Errorf("aws-chunked: chunk size %d out of range", size)
	}
	return size, nil
}

// consumeTrailers reads the trailing headers that follow the final chunk, up to
// the terminating blank line. A body that simply ends here is also accepted:
// not every client sends the blank line.
func (c *chunkedReader) consumeTrailers() error {
	for {
		line, err := c.readLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			return nil
		}
	}
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
func (c *chunkedReader) readLine() (string, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		// A final line without a terminator is still usable.
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	if len(line) > maxChunkHeaderLine {
		return "", errors.New("aws-chunked: chunk header too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}
