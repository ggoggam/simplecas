package cas

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/seal"
	"github.com/ggoggam/simplecas/internal/storage"
	"github.com/ggoggam/simplecas/internal/testblob"
)

// keyring builds a keyring of the given ids, each key filled with the digit
// its id ends in, so that keyrings naming the same id hold the same key, as
// testblob.TestKeys's t1 and t2 do.
func keyring(t *testing.T, ids ...string) *seal.Keyring {
	t.Helper()
	entries := make([]string, len(ids))
	for i, id := range ids {
		entries[i] = id + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{id[len(id)-1] - '0'}, seal.KeyBytes))
	}
	k, err := seal.Parse(entries)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// withKeys is the fixture's store over the same database and bucket, with
// other encryption keys (nil: none), as another instance, or the same one
// restarted with a new configuration, would be.
func (f *fixture) withKeys(keys *seal.Keyring) *Store {
	return New(f.db, f.bucket, keys, f.store.gc, f.store.limits, f.store.log)
}

func TestSealedChunkRoundTrips(t *testing.T) {
	keys := keyring(t, "k1")
	for _, tc := range []struct {
		name   string
		data   []byte
		scheme byte
	}{
		{"compressible", bytes.Repeat([]byte("simplecas "), 6000), schemeLZ4},
		{"incompressible", pseudoRandom("noise", 60000), schemeNone},
		{"empty", nil, schemeNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hash := chunkHash(tc.data)
			b, err := appendChunk([]byte("prefix"), tc.data, hash, keys)
			if err != nil {
				t.Fatal(err)
			}
			chunk := b[len("prefix"):]
			if chunk[0] != chunkSealedVersion || chunk[4] != tc.scheme {
				t.Errorf("header = %x, want version %d and scheme %d", chunk[:chunkHeaderLen], chunkSealedVersion, tc.scheme)
			}
			if id, sealed := chunkKeyID(chunk); !sealed || id != "k1" {
				t.Errorf("chunk is sealed under %q (%v), want k1", id, sealed)
			}
			if len(tc.data) > 0 && bytes.Contains(chunk, tc.data[:64]) {
				t.Error("the sealed chunk holds its plaintext")
			}
			if n := int64(len(chunk)) - int64(len(tc.data)); tc.scheme == schemeNone && n > chunkOverhead(keys) {
				t.Errorf("sealing added %d bytes, more than the %d allowed for", n, chunkOverhead(keys))
			}
			got, err := decodeChunk(chunk, len(tc.data), hash, keys)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Error("opened bytes differ")
			}
		})
	}
}

// A sealed chunk that was altered in any way, header included, or that is
// read as some other chunk, does not open. None of that is a missing key.
func TestSealedChunkRefusesTampering(t *testing.T) {
	keys := keyring(t, "k1")
	data := pseudoRandom("tamper", 5000)
	hash := chunkHash(data)
	chunk, err := appendChunk(nil, data, hash, keys)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		b := bytes.Clone(chunk)
		b[i] ^= 0x01
		return b
	}
	for name, tc := range map[string]struct {
		b    []byte
		hash string
	}{
		"ciphertext":         {flip(len(chunk) - 100), hash},
		"tag":                {flip(len(chunk) - 1), hash},
		"nonce":              {flip(chunkHeaderLen + 1 + len("k1")), hash},
		"scheme in header":   {flip(4), hash},
		"read as some other": {chunk, chunkHash([]byte("other"))},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeChunk(tc.b, len(data), tc.hash, keys)
			if err == nil {
				t.Fatal("decoded")
			}
			if errors.Is(err, errMissingKey) {
				t.Errorf("err = %v, want damage rather than a missing key", err)
			}
		})
	}
}

// A chunk sealed under a key the keyring does not hold, or read with no
// keyring at all, is a missing key, not damage.
func TestSealedChunkUnderAnUnknownKey(t *testing.T) {
	data := []byte("some chunk")
	hash := chunkHash(data)
	chunk, err := appendChunk(nil, data, hash, keyring(t, "k1"))
	if err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string]*seal.Keyring{"other keys": keyring(t, "k2"), "no keys": nil} {
		if _, err := decodeChunk(chunk, len(data), hash, keys); !errors.Is(err, errMissingKey) {
			t.Errorf("%s: err = %v, want errMissingKey", name, err)
		}
	}
	// A keyring holding the key anywhere opens it.
	if got, err := decodeChunk(chunk, len(data), hash, keyring(t, "k2", "k1")); err != nil || !bytes.Equal(got, data) {
		t.Errorf("after rotation: %q, %v", got, err)
	}
}

// stagingName is the name the staging tests seal their files under.
const stagingName = "staging/test.sealed"

func sealStaging(t *testing.T, keys *seal.Keyring, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := newSealedWriter(nopCloser{&out}, keys, stagingName)
	if err != nil {
		t.Fatal(err)
	}
	// In odd-sized writes, so segments do not line up with them.
	for rest := data; len(rest) > 0; {
		n := min(len(rest), 7777)
		if _, err := w.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func openStagingBytes(keys *seal.Keyring, b []byte) ([]byte, error) {
	return openStagingAs(keys, b, stagingName)
}

func openStagingAs(keys *seal.Keyring, b []byte, name string) ([]byte, error) {
	r, err := newSealedReader(io.NopCloser(bytes.NewReader(b)), keys, name)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func TestSealedStagingRoundTrips(t *testing.T) {
	keys := keyring(t, "k1")
	for _, n := range []int{0, 1, stagingSegment - 1, stagingSegment, stagingSegment + 1, 3 * stagingSegment, 3*stagingSegment + 5} {
		data := pseudoRandom("staging", n)
		sealed := sealStaging(t, keys, data)
		if n >= 64 && bytes.Contains(sealed, data[:64]) {
			t.Errorf("%d bytes: the sealed file holds its plaintext", n)
		}
		got, err := openStagingBytes(keys, sealed)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%d bytes: opened %d bytes that differ", n, len(got))
		}
	}
}

// A sealed staging file cut short, at a segment boundary or not, with its
// segments reordered or altered, or copied over another staging file's name,
// fails to read rather than reading short or as another upload.
func TestSealedStagingRefusesTruncationAndReordering(t *testing.T) {
	keys := keyring(t, "k1")
	data := pseudoRandom("staging", 2*stagingSegment)
	sealed := sealStaging(t, keys, data)
	header := 2 + len("k1") + stagingSaltLen
	seg := stagingSegment + tagLen
	if len(sealed) != header+2*seg {
		t.Fatalf("setup: %d sealed bytes, want two full segments", len(sealed))
	}
	swapped := slices.Concat(sealed[:header], sealed[header+seg:], sealed[header:header+seg])
	altered := bytes.Clone(sealed)
	altered[header+10] ^= 1
	for name, b := range map[string][]byte{
		"a byte short":       sealed[:len(sealed)-1],
		"last segment cut":   sealed[:header+seg],
		"only the header":    sealed[:header],
		"segments reordered": swapped,
		"altered":            altered,
	} {
		if got, err := openStagingBytes(keys, b); err == nil {
			t.Errorf("%s: read %d bytes", name, len(got))
		}
	}
	if got, err := openStagingAs(keys, sealed, "staging/another.sealed"); err == nil {
		t.Errorf("under another name: read %d bytes", len(got))
	}
	if _, err := openStagingBytes(keyring(t, "k2"), sealed); !errors.Is(err, errMissingKey) {
		t.Errorf("under other keys: err = %v, want errMissingKey", err)
	}
}

// listAll reads every object under prefix.
func (f *fixture) listAll(t *testing.T, prefix string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	it := f.bucket.List(&blob.ListOptions{Prefix: prefix})
	for {
		obj, err := it.Next(t.Context())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, err := f.bucket.ReadAll(t.Context(), obj.Key)
		if err != nil {
			t.Fatal(err)
		}
		out[obj.Key] = b
	}
}

// With keys set, nothing an upload leaves in the backend, staging included,
// holds any of its plaintext; the xorbs are recorded under the current key,
// and everything reads back.
func TestEncryptedStoreKeepsNoPlaintext(t *testing.T) {
	f := newFixture(t, defaultGC())
	f.store = f.withKeys(testblob.TestKeys(t))
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	data := pseudoRandom("secret", 3<<20)
	if _, err := f.store.Commit(ctx, nsID, "whole", "application/octet-stream", mustStage(t, f, data)); err != nil {
		t.Fatal(err)
	}
	// A part, left staged.
	upload := f.multipart(t, nsID, "parts")
	if _, err := f.store.PutPart(ctx, upload, 1, bytes.NewReader(data[:1<<20]), -1); err != nil {
		t.Fatal(err)
	}

	stored := f.listAll(t, "")
	if len(stored) < 2 {
		t.Fatalf("setup: %d objects stored", len(stored))
	}
	for key, b := range stored {
		for at := 0; at+4096 <= len(data); at += 1 << 20 {
			if bytes.Contains(b, data[at:at+64]) {
				t.Errorf("%s holds plaintext from offset %d", key, at)
			}
		}
		if strings.HasPrefix(key, storage.StagingPrefix) && !strings.HasSuffix(key, sealedStagingSuffix) {
			t.Errorf("staging file %s is not named as sealed", key)
		}
	}
	var keyIDs []string
	rows, err := f.pool.Query(ctx, "SELECT COALESCE(key_id, '') FROM xorbs")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		keyIDs = append(keyIDs, id)
	}
	if len(keyIDs) == 0 || slices.ContainsFunc(keyIDs, func(id string) bool { return id != "t2" }) {
		t.Errorf("xorbs are recorded under %q, want all under t2", keyIDs)
	}

	if got, err := f.readRange(t, hashOf(string(data)), 1000, 2<<20); err != nil || !bytes.Equal(got, data[1000:1000+2<<20]) {
		t.Errorf("read back %d bytes, %v", len(got), err)
	}
	parts, err := f.db.ListParts(ctx, upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CompleteMultipart(ctx, upload, parts); err != nil {
		t.Fatal(err)
	}
	if got, err := f.readRange(t, hashOf(string(data[:1<<20])), 0, 1<<20); err != nil || !bytes.Equal(got, data[:1<<20]) {
		t.Errorf("read the completed upload back as %d bytes, %v", len(got), err)
	}
}

// Content stored in the clear before keys were set, and under a key since
// rotated out of first place, reads back beside content sealed under the
// current key: each chunk and staging file says how it was stored.
func TestEncryptedStoreReadsWhatCameBefore(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	clear, old, current := f.withKeys(nil), f.withKeys(keyring(t, "t1")), f.withKeys(testblob.TestKeys(t))

	var contents [][]byte
	for i, s := range []*Store{clear, old, current} {
		f.store = s
		data := pseudoRandom(string(rune('a'+i)), 1<<20)
		if _, err := s.Commit(ctx, nsID, string(rune('a'+i)), "application/octet-stream", mustStage(t, f, data)); err != nil {
			t.Fatal(err)
		}
		contents = append(contents, data)
	}
	// A part staged in the clear and one sealed under the old key, completed
	// under the current one.
	upload := f.multipart(t, nsID, "mixed")
	if _, err := clear.PutPart(ctx, upload, 1, bytes.NewReader(contents[0][:5<<20/10]), -1); err != nil {
		t.Fatal(err)
	}
	if _, err := old.PutPart(ctx, upload, 2, bytes.NewReader(contents[1]), -1); err != nil {
		t.Fatal(err)
	}
	parts, err := f.db.ListParts(ctx, upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.CompleteMultipart(ctx, upload, parts); err != nil {
		t.Fatal(err)
	}

	f.store = current
	for i, data := range contents {
		if got, err := f.readRange(t, hashOf(string(data)), 0, int64(len(data))); err != nil || !bytes.Equal(got, data) {
			t.Errorf("content %d read back as %d bytes, %v", i, len(got), err)
		}
	}
	mixed := slices.Concat(contents[0][:5<<20/10], contents[1])
	if got, err := f.readRange(t, hashOf(string(mixed)), 0, int64(len(mixed))); err != nil || !bytes.Equal(got, mixed) {
		t.Errorf("the mixed upload read back as %d bytes, %v", len(got), err)
	}
	if err := current.CheckKeys(ctx); err != nil {
		t.Errorf("CheckKeys with every key: %v", err)
	}
}

// Content sealed under a key an instance does not hold fails to read, but is
// not taken for damage: not by a read, nor by a scrub, which gives it back to
// be checked by an instance that can.
func TestAMissingKeyIsNotDamage(t *testing.T) {
	f := newFixture(t, scrubNow())
	f.store = f.withKeys(testblob.TestKeys(t))
	ctx := t.Context()
	if err := f.store.CheckKeys(ctx); err != nil {
		t.Fatal(err)
	}
	nsID := f.namespace(t, "ns", nil)
	data := pseudoRandom("locked", 1<<20)
	staged := mustStage(t, f, data)
	if _, err := f.store.Commit(ctx, nsID, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	xorb, _ := f.storedChunks(t, staged.Hash)

	f.store = f.withKeys(keyring(t, "t1"))
	if _, err := f.readRange(t, staged.Hash, 0, int64(len(data))); err == nil {
		t.Fatal("read content sealed under a key the store does not hold")
	}
	if _, err := f.pool.Exec(ctx, "UPDATE xorbs SET verified_at = NULL"); err != nil {
		t.Fatal(err)
	}
	f.store.scrubPass(ctx, &pacer{})
	if damaged, verified := f.damage(t, "xorbs", xorb); damaged || verified {
		t.Errorf("damaged=%v verified=%v, want neither: the scrub could not check it", damaged, verified)
	}
}

// Startup refuses keys that cannot read what is stored.
func TestCheckKeys(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	if err := f.withKeys(nil).CheckKeys(ctx); err != nil {
		t.Errorf("an empty store, no keys: %v", err)
	}
	f.store = f.withKeys(nil)
	if _, err := f.store.Commit(ctx, nsID, "clear", "application/octet-stream", mustStage(t, f, pseudoRandom("c", 1<<20))); err != nil {
		t.Fatal(err)
	}
	// Started with keys, as the server always checks them before writing.
	f.store = f.withKeys(testblob.TestKeys(t))
	if err := f.store.CheckKeys(ctx); err != nil {
		t.Fatalf("the first start with keys: %v", err)
	}
	if _, err := f.store.Commit(ctx, nsID, "sealed", "application/octet-stream", mustStage(t, f, pseudoRandom("s", 1<<20))); err != nil {
		t.Fatal(err)
	}

	// Another key under a name already on record.
	impostor, err := seal.Parse([]string{"t2:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, seal.KeyBytes))})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		keys *seal.Keyring
		ok   bool
	}{
		{"another key named t2", impostor, false},
		{"the same keys", testblob.TestKeys(t), true},
		{"rotated, old key kept", keyring(t, "t3", "t2"), true},
		{"rotated, old key dropped", keyring(t, "t3"), false},
		{"no keys", nil, false},
	} {
		err := f.withKeys(tc.keys).CheckKeys(ctx)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		} else if err != nil && !strings.Contains(err.Error(), `"t2"`) {
			t.Errorf("%s: err = %v, want it to name t2", tc.name, err)
		}
	}
}

// xorbKeyID is the key a xorb's row records, "" for one in the clear, and
// the keys its stored chunks name.
func (f *fixture) xorbKeyID(t *testing.T, xorb string) (recorded string, chunks []string) {
	t.Helper()
	ctx := t.Context()
	if err := f.pool.QueryRow(ctx, "SELECT COALESCE(key_id, '') FROM xorbs WHERE hash = $1", xorb).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	stored, err := f.db.XorbChunks(ctx, xorb, 0, maxXorbChunks)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.bucket.ReadAll(ctx, storage.XorbPath(xorb))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range stored {
		id, _ := chunkKeyID(b[c.Offset : c.Offset+int64(c.Length)])
		chunks = append(chunks, id)
	}
	return recorded, chunks
}

// Compaction rewrites a xorb wholly under the current key, whatever its
// chunks were stored under, so turning encryption on, or rotating its key,
// moves forward as xorbs are compacted.
func TestCompactionSealsUnderTheCurrentKey(t *testing.T) {
	f := newFixture(t, compactNow())
	f.store = f.withKeys(nil)
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	data, blob, old := f.sparse(t, nsID, 1)

	f.store = f.withKeys(testblob.TestKeys(t))
	f.store.compactXorbs(ctx)

	xorbs := f.xorbsOf(t, blob)
	if slices.Contains(xorbs, old) {
		t.Fatal("setup: the sparse xorb was not compacted")
	}
	// The blob now uses the xorb compaction wrote, and its own new one,
	// written in the clear before the keys were set.
	sealed := 0
	for _, x := range xorbs {
		recorded, chunks := f.xorbKeyID(t, x)
		for i, id := range chunks {
			if id != recorded {
				t.Errorf("xorb %s is recorded under %q, but chunk %d is under %q", x, recorded, i, id)
			}
		}
		switch recorded {
		case "t2":
			sealed++
		case "":
		default:
			t.Errorf("xorb %s is recorded under %q", x, recorded)
		}
	}
	if sealed != 1 {
		t.Errorf("%d of the blob's xorbs are under the current key, want the compacted one", sealed)
	}
	if got, err := f.readRange(t, blob, 0, int64(len(data))); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back %d bytes, %v", len(got), err)
	}
}

// A chunk whose key name rotted, naming a key no instance was ever given, is
// damage, not a missing key: reads fall back to a sound copy, and the scrub
// marks it.
func TestARottedKeyNameIsDamage(t *testing.T) {
	f := newFixture(t, scrubNow())
	f.store = f.withKeys(testblob.TestKeys(t))
	ctx := t.Context()
	if err := f.store.CheckKeys(ctx); err != nil {
		t.Fatal(err)
	}
	a, b := f.namespace(t, "a", nil), f.namespace(t, "b", nil)
	data := pseudoRandom("rotted name", 1<<20)
	staged := mustStage(t, f, data)
	if _, err := f.store.Commit(ctx, a, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	xorb, chunks := f.storedChunks(t, staged.Hash)
	// "t2" becomes "u2" in the first chunk.
	f.rewriteXorb(t, xorb, func(x []byte) []byte {
		at := chunks[0].Offset + chunkHeaderLen + 1
		if string(x[at:at+2]) != "t2" {
			t.Fatalf("setup: key name is %q", x[at:at+2])
		}
		x[at] = 'u'
		return x
	})
	if _, err := f.readRange(t, staged.Hash, 0, int64(len(data))); err == nil {
		t.Fatal("read a chunk whose key name rotted, with no other copy")
	}
	if damaged, _ := f.damage(t, "xorbs", xorb); !damaged {
		t.Error("the read did not mark the xorb damaged")
	}

	// With a sound copy in another xorb, the read is served from it. Other
	// content holding the same chunks makes one: the damaged xorb is left out
	// of dedup, so that upload writes the chunks again.
	longer := append(bytes.Clone(data), pseudoRandom("tail", 1<<20)...)
	if _, err := f.store.Commit(ctx, b, "k", "application/octet-stream", mustStage(t, f, longer)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.readRange(t, staged.Hash, 0, int64(len(data))); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back %d bytes, %v; want the sound copy", len(got), err)
	}
	if _, err := f.pool.Exec(ctx, "UPDATE xorbs SET damaged_at = NULL, verified_at = NULL WHERE hash = $1", xorb); err != nil {
		t.Fatal(err)
	}
	f.store.scrubPass(ctx, &pacer{})
	if damaged, _ := f.damage(t, "xorbs", xorb); !damaged {
		t.Error("the scrub did not mark the xorb damaged")
	}
}

// Completing an upload checks each staged part against what was uploaded, so
// a part file swapped for other bytes is refused rather than committed.
func TestCompletionRefusesASwappedPart(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)
	mine, other := f.multipart(t, nsID, "mine"), f.multipart(t, nsID, "other")
	if _, err := f.store.PutPart(ctx, mine, 1, strings.NewReader(strings.Repeat("a", 4096)), -1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PutPart(ctx, other, 1, strings.NewReader(strings.Repeat("b", 4096)), -1); err != nil {
		t.Fatal(err)
	}
	mineParts, err := f.db.ListParts(ctx, mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	otherParts, err := f.db.ListParts(ctx, other.ID)
	if err != nil {
		t.Fatal(err)
	}
	stolen, err := f.bucket.ReadAll(ctx, otherParts[0].StagingKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bucket.WriteAll(ctx, mineParts[0].StagingKey, stolen, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CompleteMultipart(ctx, mine, mineParts); err == nil {
		t.Fatal("completed an upload whose part was swapped for another's")
	}
}
