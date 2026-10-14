package cas

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/seal"
	"github.com/ggoggam/simplecas/internal/storage"
)

// Encryption at rest
//
// With storage.encryption_keys set, what is written to the backend is sealed
// with AES-256-GCM: the chunks in xorbs, and the staging files that hold
// uploads and multipart parts until they are committed. The one exception is
// a blob stored whole before chunking, whose file is rewritten in the clear,
// as it was stored, when an upload of its content needs it (promoteWhole). Someone who can
// read the backend, but not the server's configuration, learns the sizes of
// what is stored and nothing else.
//
// Dedup is global, so a chunk stored once may belong to any number of teams,
// and its key cannot be any one team's. Each chunk is sealed under a key
// derived from the server key and the chunk's hash, which is convergent
// encryption keyed with a server secret: anyone who can read the content can
// find its key, but only with the server key. Keying per chunk rather than
// sealing every chunk under the server key itself keeps the use of each GCM
// key to the copies of one chunk, so the random nonces never come near their
// collision bound however much is stored; one key for everything would reach
// NIST's limit of 2^32 messages at about 256 TiB of chunks. It also means a
// sealed chunk moved to another chunk's place fails to open.
//
// A sealed chunk is
//
//	header (8, version 1) | key ID length (1) | key ID | nonce (12) | sealed data
//
// where the sealed data is the chunk's data, compressed as the header says,
// with the GCM tag after it, and the header is authenticated with it. Each
// chunk names its key, so xorbs written under different keys, and xorbs
// stored in the clear before encryption was turned on, are read side by
// side, and compaction can copy a chunk without opening it.
//
// A sealed staging file is named with a ".sealed" suffix and is
//
//	version (1) | key ID length (1) | key ID | salt (32) | segments
//
// sealed under a key derived from the server key, the salt and the file's
// name, as the STREAM construction does: each segment is 64 KiB of the content with its tag, the
// last one shorter (perhaps empty) and flagged as last, and each segment's
// nonce is its number. A file cut short, with segments reordered, or copied
// over another staging file's name, does not open: someone who can write to
// the bucket cannot have the server read one upload's staged bytes as
// another's.

const (
	nonceLen = 12
	tagLen   = 16

	// maxSealOverhead is the most sealing adds to a chunk's stored length.
	maxSealOverhead = 1 + seal.MaxKeyIDLen + nonceLen + tagLen

	// Subkeys are derived for one of these purposes, followed by the chunk
	// hash or the staging file's salt.
	chunkKeyInfo   = "simplecas chunk v1 "
	stagingKeyInfo = "simplecas staging v1 "

	stagingFormatVersion = 1
	stagingSaltLen       = 32
	stagingSegment       = 64 << 10

	// sealedStagingSuffix ends the name of a sealed staging file, so that
	// staging written in the clear before encryption was turned on is still
	// read as it was written.
	sealedStagingSuffix = ".sealed"
)

// errMissingKey is a sealed chunk or staging file whose key the keyring does
// not hold. It is a configuration problem, not damage: the bytes may be
// perfectly sound.
var errMissingKey = errors.New("sealed under a key storage.encryption_keys does not hold")

// missingKeyError is errMissingKey for the key named id. The id is read from
// stored bytes before anything authenticates them, so it may be damage
// itself; see Store.verifyChunk.
type missingKeyError struct{ id string }

func (e *missingKeyError) Error() string        { return fmt.Sprintf("%v (%q)", errMissingKey, e.id) }
func (e *missingKeyError) Is(target error) bool { return target == errMissingKey }

func missingKey(id string) error { return &missingKeyError{id: id} }

// chunkOverhead is how many bytes, at most, a chunk takes in a xorb beyond
// its compressed data.
func chunkOverhead(keys *seal.Keyring) int64 {
	if keys == nil {
		return chunkHeaderLen
	}
	return chunkHeaderLen + maxSealOverhead
}

// appendSealedChunk writes, at dst[start:], the header of a chunk whose
// compressed data is data, followed by the data sealed under the current key.
// dst holds the header's 8 bytes from start on, to be overwritten.
func appendSealedChunk(dst []byte, start int, data []byte, scheme byte, size int, hash string, keys *seal.Keyring) ([]byte, error) {
	id := keys.Current()
	aead, err := keys.Derive(id, chunkKeyInfo+hash)
	if err != nil {
		return dst, err
	}
	stored := 1 + len(id) + nonceLen + len(data) + aead.Overhead()
	putChunkHeader(dst[start:], chunkSealedVersion, stored, scheme, size)
	var header [chunkHeaderLen]byte
	copy(header[:], dst[start:])

	dst = append(dst, byte(len(id)))
	dst = append(dst, id...)
	at := len(dst)
	dst = append(dst, make([]byte, nonceLen)...)
	if _, err := rand.Read(dst[at:]); err != nil {
		return dst, fmt.Errorf("chunk nonce: %w", err)
	}
	return aead.Seal(dst, dst[at:at+nonceLen], data, header[:]), nil
}

// openSealedChunk opens the sealed data of a chunk whose header is header,
// under the key derived for hash. A chunk that does not authenticate has
// been altered, or is not the chunk hash names.
func openSealedChunk(header, sealed []byte, hash string, keys *seal.Keyring) ([]byte, error) {
	id, rest, ok := splitKeyID(sealed)
	if !ok || len(rest) < nonceLen+tagLen {
		return nil, fmt.Errorf("sealed chunk is too short")
	}
	if keys == nil || !keys.Has(id) {
		return nil, missingKey(id)
	}
	aead, err := keys.Derive(id, chunkKeyInfo+hash)
	if err != nil {
		return nil, err
	}
	data, err := aead.Open(nil, rest[:nonceLen], rest[nonceLen:], header)
	if err != nil {
		return nil, fmt.Errorf("sealed chunk does not authenticate")
	}
	return data, nil
}

// splitKeyID reads the length-prefixed key ID at the start of b.
func splitKeyID(b []byte) (id string, rest []byte, ok bool) {
	if len(b) < 1 || int(b[0]) > seal.MaxKeyIDLen || len(b) < 1+int(b[0]) {
		return "", nil, false
	}
	return string(b[1 : 1+b[0]]), b[1+b[0]:], true
}

// chunkKeyID reports the key a stored chunk is sealed under, and sealed=false
// for one stored in the clear.
func chunkKeyID(b []byte) (id string, sealed bool) {
	if len(b) <= chunkHeaderLen || b[0] != chunkSealedVersion {
		return "", false
	}
	id, _, ok := splitKeyID(b[chunkHeaderLen:])
	return id, ok
}

// currentKeyID is the key new content is sealed under, or "" when content is
// stored in the clear.
func currentKeyID(keys *seal.Keyring) string {
	if keys == nil {
		return ""
	}
	return keys.Current()
}

// segmentNonce is the nonce of segment n of a sealed staging file.
func segmentNonce(n uint64, last bool) []byte {
	nonce := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(nonce[3:11], n)
	if last {
		nonce[11] = 1
	}
	return nonce
}

// sealedWriter seals what is written to it as a staging file.
type sealedWriter struct {
	w    io.WriteCloser
	aead cipher.AEAD
	n    uint64
	buf  []byte // the segment being filled
	out  []byte
	err  error
}

// stagingKey derives the key of the sealed staging file name, from its salt.
func stagingKey(keys *seal.Keyring, id, name string, salt []byte) (cipher.AEAD, error) {
	return keys.Derive(id, stagingKeyInfo+hex.EncodeToString(salt)+" "+name)
}

func newSealedWriter(w io.WriteCloser, keys *seal.Keyring, name string) (*sealedWriter, error) {
	id := keys.Current()
	salt := make([]byte, stagingSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("staging salt: %w", err)
	}
	aead, err := stagingKey(keys, id, name, salt)
	if err != nil {
		return nil, err
	}
	header := append([]byte{stagingFormatVersion, byte(len(id))}, id...)
	header = append(header, salt...)
	if _, err := w.Write(header); err != nil {
		return nil, err
	}
	return &sealedWriter{w: w, aead: aead, buf: make([]byte, 0, stagingSegment)}, nil
}

func (w *sealedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n := 0
	for len(p) > 0 {
		// A full segment is sealed only once more bytes follow it, since
		// the last one has to be sealed as last.
		if len(w.buf) == stagingSegment {
			if w.err = w.seal(false); w.err != nil {
				return n, w.err
			}
		}
		k := copy(w.buf[len(w.buf):stagingSegment], p)
		w.buf = w.buf[:len(w.buf)+k]
		p = p[k:]
		n += k
	}
	return n, nil
}

func (w *sealedWriter) seal(last bool) error {
	w.out = w.aead.Seal(w.out[:0], segmentNonce(w.n, last), w.buf, nil)
	w.n++
	w.buf = w.buf[:0]
	_, err := w.w.Write(w.out)
	return err
}

// Close seals the last segment and closes the file, which on an object store
// is what completes the upload.
func (w *sealedWriter) Close() error {
	err := w.err
	if err == nil {
		err = w.seal(true)
	}
	return errors.Join(err, w.w.Close())
}

// sealedReader opens a sealed staging file as it is read.
type sealedReader struct {
	r    *bufio.Reader
	c    io.Closer
	aead cipher.AEAD
	n    uint64
	seg  []byte
	cur  []byte
	done bool
	err  error
}

func newSealedReader(rc io.ReadCloser, keys *seal.Keyring, name string) (*sealedReader, error) {
	r := bufio.NewReaderSize(rc, stagingSegment+tagLen)
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("sealed staging header: %w", err)
	}
	if head[0] != stagingFormatVersion || int(head[1]) > seal.MaxKeyIDLen {
		return nil, fmt.Errorf("sealed staging header: unknown format")
	}
	rest := make([]byte, int(head[1])+stagingSaltLen)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("sealed staging header: %w", err)
	}
	id, salt := string(rest[:head[1]]), rest[head[1]:]
	if keys == nil || !keys.Has(id) {
		return nil, missingKey(id)
	}
	aead, err := stagingKey(keys, id, name, salt)
	if err != nil {
		return nil, err
	}
	return &sealedReader{r: r, c: rc, aead: aead, seg: make([]byte, stagingSegment+tagLen)}, nil
}

func (r *sealedReader) Read(p []byte) (int, error) {
	for len(r.cur) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		r.err = r.next()
	}
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	return n, nil
}

// next opens the next segment. Only a segment that ends the file can be the
// last, so a full one is last exactly when nothing follows it.
func (r *sealedReader) next() error {
	n, err := io.ReadFull(r.r, r.seg)
	last := false
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		last = true
	case errors.Is(err, io.EOF):
		return fmt.Errorf("sealed staging file ends before its last segment: %w", io.ErrUnexpectedEOF)
	case err != nil:
		return err
	default:
		if _, perr := r.r.Peek(1); errors.Is(perr, io.EOF) {
			last = true
		} else if perr != nil {
			return perr
		}
	}
	plain, err := r.aead.Open(r.seg[:0], segmentNonce(r.n, last), r.seg[:n], nil)
	if err != nil {
		return fmt.Errorf("sealed staging segment %d does not authenticate", r.n)
	}
	r.n++
	r.cur, r.done = plain, last
	return nil
}

func (r *sealedReader) Close() error { return r.c.Close() }

// createStaging starts a new staging file, sealed if the store has keys, and
// returns its key.
func (s *Store) createStaging(ctx context.Context) (string, io.WriteCloser, error) {
	if s.keys == nil {
		key := storage.StagingPath(uuid.NewString())
		w, err := s.blob.NewWriter(ctx, key, nil)
		if err != nil {
			return "", nil, apperr.Internal(err)
		}
		return key, w, nil
	}
	key := storage.StagingPath(uuid.NewString() + sealedStagingSuffix)
	w, err := s.blob.NewWriter(ctx, key, nil)
	if err != nil {
		return "", nil, apperr.Internal(err)
	}
	sw, err := newSealedWriter(w, s.keys, key)
	if err != nil {
		_ = w.Close()
		s.DiscardStaging(ctx, key)
		return "", nil, apperr.Internal(err)
	}
	return key, sw, nil
}

// openStaging reads a staging file back as it was written, opening it if it
// was sealed.
func (s *Store) openStaging(ctx context.Context, key string) (io.ReadCloser, error) {
	r, err := s.blob.NewReader(ctx, key, nil)
	if err != nil || !strings.HasSuffix(key, sealedStagingSuffix) {
		return r, err
	}
	sr, err := newSealedReader(r, s.keys, key)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return sr, nil
}

// CheckKeys refuses a configuration whose encryption keys cannot read what is
// stored. It runs at startup, before anything is served.
//
// Each key's fingerprint is recorded under its id the first time any
// instance starts with it, and a key whose id is on record with another
// fingerprint is refused: instances given different keys under one name
// would each write content the others cannot open, and a chunk that does not
// open under the key it names looks just like a damaged one.
//
// Then content sealed under a key storage.encryption_keys no longer lists,
// or any sealed content once the setting is removed, is refused too. Reads
// of it would fail one request at a time, and are not taken for damage (see
// verifyChunk), but nothing could read it until the key came back. This
// checks xorbs. A staging file names its key too, but lives only until its
// upload is committed or expires, which is why a key is kept for a multipart
// expiry after it is no longer first.
func (s *Store) CheckKeys(ctx context.Context) error {
	if s.keys != nil {
		mine := make(map[string]string)
		for _, id := range s.keys.IDs() {
			fp, err := s.keys.Fingerprint(id)
			if err != nil {
				return err
			}
			mine[id] = fp
		}
		recorded, err := s.db.RecordStorageKeys(ctx, mine)
		if err != nil {
			return err
		}
		for _, id := range s.keys.IDs() {
			if recorded[id] != mine[id] {
				return fmt.Errorf("storage.encryption_keys holds a key named %q that is not the key first used "+
					"under that name: every instance needs the same key under it, and a new key needs a new name", id)
			}
		}
	}

	stored, err := s.db.StoredKeys(ctx)
	if err != nil {
		return err
	}
	var missing []string
	for _, id := range stored {
		if s.keys == nil || !s.keys.Has(id) {
			missing = append(missing, fmt.Sprintf("%q", id))
		}
	}
	switch {
	case len(missing) == 0:
		return nil
	case s.keys == nil:
		return fmt.Errorf("stored content is encrypted under %s, but storage.encryption_keys is not set: "+
			"restore the keys it was encrypted under", strings.Join(missing, ", "))
	default:
		return fmt.Errorf("stored content is encrypted under %s, which storage.encryption_keys no longer lists: "+
			"add those keys back after the current one", strings.Join(missing, ", "))
	}
}

// keyRecorded reports whether some instance has been configured with the key
// id: whether storage_keys holds it. Recorded keys are never removed, so a
// yes is remembered.
func (s *Store) keyRecorded(ctx context.Context, id string) (bool, error) {
	if _, ok := s.recordedKeys.Load(id); ok {
		return true, nil
	}
	ok, err := s.db.StorageKeyRecorded(ctx, id)
	if ok {
		s.recordedKeys.Store(id, true)
	}
	return ok, err
}
