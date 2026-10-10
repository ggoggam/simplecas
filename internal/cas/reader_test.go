package cas

import (
	"bytes"
	"io"
	"testing"

	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// readRange reads [start, start+length) of hash through Open.
func (f *fixture) readRange(t *testing.T, hash string, start, length int64) ([]byte, error) {
	t.Helper()
	r, err := f.store.Open(t.Context(), hash, start, length)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

func TestOpenReadsRangesAcrossChunks(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	data := pseudoRandom("ranges", 3<<20)
	staged, err := f.store.Stage(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(staged.Chunks) < 4 {
		t.Fatalf("setup: %d chunks, want several", len(staged.Chunks))
	}
	if _, err := f.store.Commit(ctx, nsID, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}

	second := staged.Chunks[1]
	size := int64(len(data))
	for _, tc := range []struct {
		name          string
		start, length int64
	}{
		{"whole object", 0, size},
		{"first byte", 0, 1},
		{"last byte", size - 1, 1},
		{"exactly one chunk", second.Pos, int64(second.Size)},
		{"straddles a boundary", second.Pos - 10, 20},
		{"spans several chunks", 1000, size - 2000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.readRange(t, staged.Hash, tc.start, tc.length)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data[tc.start:tc.start+tc.length]) {
				t.Errorf("read %d bytes that differ from the stored range of %d", len(got), tc.length)
			}
		})
	}
}

// storedChunks returns where a blob's single xorb holds each of its chunks.
func (f *fixture) storedChunks(t *testing.T, blob string) (string, []db.XorbChunk) {
	t.Helper()
	xorbs := f.xorbsOf(t, blob)
	if len(xorbs) != 1 {
		t.Fatalf("setup: blob uses %d xorbs, want 1", len(xorbs))
	}
	chunks, err := f.db.XorbChunks(t.Context(), xorbs[0], 0, maxXorbChunks)
	if err != nil {
		t.Fatal(err)
	}
	return xorbs[0], chunks
}

// rewriteXorb replaces a stored xorb with what edit makes of its bytes.
func (f *fixture) rewriteXorb(t *testing.T, xorb string, edit func([]byte) []byte) {
	t.Helper()
	ctx := t.Context()
	b, err := f.bucket.ReadAll(ctx, storage.XorbPath(xorb))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bucket.WriteAll(ctx, storage.XorbPath(xorb), edit(b), nil); err != nil {
		t.Fatal(err)
	}
}

// A range touches only the chunks it overlaps: the others can be ruined
// altogether and the read still succeeds.
func TestOpenFetchesOnlyTheChunksARangeOverlaps(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	data := pseudoRandom("only overlapped", 2<<20)
	staged, err := f.store.Stage(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	xorb, stored := f.storedChunks(t, staged.Hash)
	f.rewriteXorb(t, xorb, func(b []byte) []byte {
		for i := stored[1].Offset; i < int64(len(b)); i++ {
			b[i] ^= 0xff
		}
		return b
	})

	first := staged.Chunks[0]
	got, err := f.readRange(t, staged.Hash, 5, int64(first.Size)-5)
	if err != nil {
		t.Fatalf("a range inside the first chunk needs no other chunk: %v", err)
	}
	if !bytes.Equal(got, data[5:first.Size]) {
		t.Error("the range read back differs from what was stored")
	}
	if _, err := f.readRange(t, staged.Hash, 0, int64(len(data))); err == nil {
		t.Error("a read of the whole object should fail on its ruined chunks")
	}
}

// Every chunk is checked against its hash before it is served, so bytes that
// rot in the backend fail the read rather than reach the client.
func TestOpenRefusesAChunkThatNoLongerMatchesItsHash(t *testing.T) {
	f := newFixture(t, defaultGC())
	ctx := t.Context()
	nsID := f.namespace(t, "ns", nil)

	// Compressible, so a flipped bit lands in LZ4 data, not just raw bytes.
	data := bytes.Repeat(pseudoRandom("rot", 4096), 256)
	staged, err := f.store.Stage(ctx, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Commit(ctx, nsID, "k", "application/octet-stream", staged); err != nil {
		t.Fatal(err)
	}
	xorb, stored := f.storedChunks(t, staged.Hash)
	pristine, err := f.bucket.ReadAll(ctx, storage.XorbPath(xorb))
	if err != nil {
		t.Fatal(err)
	}

	// The first chunk rots: Open itself fails, before a status is sent.
	f.rewriteXorb(t, xorb, func(b []byte) []byte {
		b[stored[0].Offset+chunkHeaderLen+5] ^= 0x01
		return b
	})
	if _, err := f.store.Open(ctx, staged.Hash, 0, int64(len(data))); err == nil {
		t.Error("Open served a chunk that does not match its hash")
	}

	// The xorb is truncated: the read fails partway.
	last := stored[len(stored)-1]
	f.rewriteXorb(t, xorb, func([]byte) []byte { return bytes.Clone(pristine[:last.Offset+10]) })
	if _, err := f.readRange(t, staged.Hash, 0, int64(len(data))); err == nil {
		t.Error("a truncated xorb was served as if it were whole")
	}
}

// Content stored before chunking is one file under blobs/, and stays
// readable.
func TestOpenReadsWholeFileBlobs(t *testing.T) {
	f := newFixture(t, defaultGC())
	nsID := f.namespace(t, "ns", nil)

	f.putWholeFile(t, nsID, "old", "stored before chunking")
	got, err := f.readRange(t, hashOf("stored before chunking"), 7, 6)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "before" {
		t.Errorf("read %q, want %q", got, "before")
	}
}

func TestOpenOfAnEmptyRangeReadsNothing(t *testing.T) {
	f := newFixture(t, defaultGC())
	got, err := f.readRange(t, hashABC, 0, 0)
	if err != nil || len(got) != 0 {
		t.Errorf("read %q, %v; want nothing, without looking the blob up", got, err)
	}
}
