// Payload integrity.
//
// A SigV4 signature covers a request's headers, and the headers only make
// claims about the body: x-amz-content-sha256, Content-MD5, x-amz-checksum-*.
// Every claim a request makes is checked here, against the bytes as they are
// read — the digests are fed by the same read that writes the staging file, so
// nothing buffers a body or reads it twice. A body that fails a check fails the
// read that reaches its end, before the caller ever sees EOF: staging discards
// what it wrote, and nothing is committed (no object row, no blob reference, no
// part).
//
// ServeHTTP swaps every request body for one of these, so the XML bodies of
// DeleteObjects and CompleteMultipartUpload are held to their payload hash as
// much as an upload is. A body nobody reads is never checked, but then nothing
// was done with it either.
//
// UNSIGNED-PAYLOAD is accepted as on S3: the client chose not to sign the body,
// and only its checksums, if it sent any, hold it to anything.

package s3

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ggoggam/simplecas/internal/apperr"
)

const unsignedPayload = "UNSIGNED-PAYLOAD"

// crc64NVME is the CRC-64/NVME table: the reflected polynomial
// 0x9a6c9329ac4bc9b5 with all-ones init and final XOR, which is how hash/crc64
// runs every table. The AWS CLI sends this checksum by default.
var crc64NVME = crc64.MakeTable(0x9a6c9329ac4bc9b5)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// checksumAlgorithm is one of S3's additional checksums, sent base64-encoded
// as x-amz-checksum-<name>, as a header or an aws-chunked trailer.
type checksumAlgorithm struct {
	header string
	size   int
	new    func() hash.Hash
}

var checksumAlgorithms = []checksumAlgorithm{
	{"x-amz-checksum-crc32", crc32.Size, func() hash.Hash { return crc32.NewIEEE() }},
	{"x-amz-checksum-crc32c", crc32.Size, func() hash.Hash { return crc32.New(castagnoli) }},
	{"x-amz-checksum-crc64nvme", crc64.Size, func() hash.Hash { return crc64.New(crc64NVME) }},
	{"x-amz-checksum-sha1", sha1.Size, sha1.New},
	{"x-amz-checksum-sha256", sha256.Size, sha256.New},
}

func checksumByHeader(name string) (checksumAlgorithm, bool) {
	for _, alg := range checksumAlgorithms {
		if alg.header == name {
			return alg, true
		}
	}
	return checksumAlgorithm{}, false
}

// decode parses a base64 checksum value of the algorithm's size.
func (a checksumAlgorithm) decode(value string) ([]byte, error) {
	want, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(want) != a.size {
		return nil, apperr.InvalidRequest("value for %s is not a valid checksum", a.header)
	}
	return want, nil
}

// digest is one claim about the body, checked once it has all been read.
type digest struct {
	h        hash.Hash
	want     []byte
	mismatch error
	// checksum is the x-amz-checksum-* header this came from, echoed back on
	// the response with value once verified; empty for the other claims.
	checksum string
	value    string
}

// payload is a request body held to the claims its headers make.
type payload struct {
	raw io.ReadCloser
	// r is the body as the handler sees it, decoded when aws-chunked.
	r       io.Reader
	chunked *chunkedReader
	digests []*digest
	sink    io.Writer
	// trailer is the checksum x-amz-trailer announced, whose expected value
	// only arrives after the last chunk.
	trailer *digest
	// verified is set once every claim has been checked against the whole
	// body; err makes any failure, or the end of the body, sticky.
	verified bool
	err      error
}

// newPayload wraps r's body in the checks its headers call for. signer is the
// request's signing context, nil when auth is disabled. Headers that are
// malformed in themselves are refused here, before any of the body is read.
func newPayload(r *http.Request, signer *chunkSigner) (*payload, error) {
	raw := r.Body
	if raw == nil {
		raw = http.NoBody
	}
	p := &payload{raw: raw, r: raw}
	chunked := isChunkedPayload(r)

	// The payload hash comes first: it is the claim the signature covers.
	switch mode := r.Header.Get("x-amz-content-sha256"); mode {
	case "", unsignedPayload:
		// Unsigned. An absent header only gets this far with auth disabled:
		// verify requires it otherwise.
	case streamingSigned, streamingSignedTrailer:
		cr := newSignedChunkedReader(raw, signer, mode == streamingSignedTrailer)
		p.chunked, p.r = cr, cr
	case streamingUnsignedTrailer:
		p.chunked = newChunkedReader(raw)
		p.r = p.chunked
	default:
		want, err := hex.DecodeString(mode)
		if err != nil || len(want) != sha256.Size {
			return nil, apperr.InvalidArgument("x-amz-content-sha256 must be UNSIGNED-PAYLOAD, " +
				"a supported STREAMING- value, or the hex SHA-256 of the body")
		}
		// The digest would be of the framed bytes, which is not what any
		// client signs: an aws-chunked body is signed per chunk instead.
		if chunked {
			return nil, apperr.InvalidArgument("an aws-chunked body needs a STREAMING- x-amz-content-sha256")
		}
		p.digests = append(p.digests, &digest{h: sha256.New(), want: want, mismatch: apperr.ErrContentSHA256Mismatch})
	}
	// Content-Encoding: aws-chunked under an unsigned payload hash is decoded
	// as unsigned framing.
	if chunked && p.chunked == nil {
		p.chunked = newChunkedReader(raw)
		p.r = p.chunked
	}
	if p.chunked != nil {
		if declared := r.Header.Get("x-amz-decoded-content-length"); declared != "" {
			want, err := strconv.ParseInt(declared, 10, 64)
			if err != nil || want < 0 {
				return nil, apperr.InvalidArgument("bad x-amz-decoded-content-length %q", declared)
			}
			p.r = &lengthCheckedReader{r: p.r, remaining: want}
		}
	}

	if values := r.Header.Values("Content-MD5"); len(values) > 0 {
		want, err := base64.StdEncoding.DecodeString(values[0])
		if len(values) > 1 || err != nil || len(want) != md5.Size {
			return nil, apperr.InvalidDigest("the Content-MD5 you specified is not valid")
		}
		p.digests = append(p.digests, &digest{h: md5.New(), want: want,
			mismatch: apperr.BadDigest("the Content-MD5 you specified did not match what was received")})
	}

	for _, alg := range checksumAlgorithms {
		value := r.Header.Get(alg.header)
		if value == "" {
			continue
		}
		want, err := alg.decode(value)
		if err != nil {
			return nil, err
		}
		p.digests = append(p.digests, alg.digest(want, value))
	}

	if declared := r.Header.Get("x-amz-trailer"); declared != "" && p.chunked != nil {
		alg, ok := checksumByHeader(strings.ToLower(strings.TrimSpace(declared)))
		if !ok {
			return nil, apperr.InvalidArgument("unsupported x-amz-trailer %q", declared)
		}
		p.trailer = alg.digest(nil, "")
		p.digests = append(p.digests, p.trailer)
	}

	sinks := make([]io.Writer, 0, len(p.digests))
	for _, d := range p.digests {
		sinks = append(sinks, d.h)
	}
	p.sink = io.MultiWriter(sinks...)
	return p, nil
}

func (a checksumAlgorithm) digest(want []byte, value string) *digest {
	return &digest{
		h:        a.new(),
		want:     want,
		mismatch: apperr.BadDigest("the body does not match the %s the request was sent with", a.header),
		checksum: a.header,
		value:    value,
	}
}

func (p *payload) Read(b []byte) (int, error) {
	if p.err != nil {
		return 0, p.err
	}
	n, err := p.r.Read(b)
	// A hash.Hash never fails a write.
	_, _ = p.sink.Write(b[:n])
	if errors.Is(err, io.EOF) {
		if verr := p.check(); verr != nil {
			err = verr
		} else {
			p.verified = true
		}
	}
	if err != nil {
		p.err = err
	}
	return n, err
}

// check holds the whole body, now read, to every claim made about it.
func (p *payload) check() error {
	if p.chunked != nil {
		if err := p.takeTrailer(); err != nil {
			return err
		}
	}
	for _, d := range p.digests {
		if !bytes.Equal(d.h.Sum(nil), d.want) {
			return d.mismatch
		}
	}
	return nil
}

// takeTrailer fills in the announced trailer's expected value. A checksum
// trailer that was not announced is refused rather than ignored: its algorithm
// was not known while the body streamed, so nothing hashed the body for it.
func (p *payload) takeTrailer() error {
	for name := range p.chunked.trailers {
		if _, ok := checksumByHeader(name); ok && (p.trailer == nil || name != p.trailer.checksum) {
			return apperr.InvalidRequest("trailer %s was not declared in x-amz-trailer", name)
		}
	}
	if p.trailer == nil {
		return nil
	}
	value, ok := p.chunked.trailers[p.trailer.checksum]
	if !ok {
		return apperr.InvalidRequest("the body ended without the %s trailer x-amz-trailer declared", p.trailer.checksum)
	}
	alg, _ := checksumByHeader(p.trailer.checksum)
	want, err := alg.decode(value)
	if err != nil {
		return err
	}
	p.trailer.want, p.trailer.value = want, value
	return nil
}

func (p *payload) Close() error { return p.raw.Close() }

// setChecksumHeaders echoes the x-amz-checksum-* values a fully read and
// verified body carried, as S3 does on PutObject and UploadPart.
func setChecksumHeaders(w http.ResponseWriter, r *http.Request) {
	p, ok := r.Body.(*payload)
	if !ok || !p.verified {
		return
	}
	for _, d := range p.digests {
		if d.checksum != "" {
			w.Header().Set(d.checksum, d.value)
		}
	}
}
