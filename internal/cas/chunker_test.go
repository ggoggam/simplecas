package cas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/zeebo/blake3"

	"github.com/ggoggam/simplecas/internal/db"
)

// pseudoRandom returns n bytes that look random to the chunker but are the
// same on every run, so the boundaries cut from them can be pinned.
func pseudoRandom(seed string, n int) []byte {
	out := make([]byte, n)
	d := blake3.New()
	_, _ = d.WriteString(seed)
	_, _ = io.ReadFull(d.Digest(), out)
	return out
}

func chunkAll(data []byte, writeSize int) []db.ChunkRef {
	c := newChunker()
	for len(data) > 0 {
		n := min(writeSize, len(data))
		_, _ = c.Write(data[:n])
		data = data[n:]
	}
	return c.finish()
}

func TestChunkerCutsWithinBoundsAndCoversTheContent(t *testing.T) {
	data := pseudoRandom("bounds", 32<<20)
	chunks := chunkAll(data, 1<<16)

	var pos int64
	for i, c := range chunks {
		if c.Pos != pos {
			t.Fatalf("chunk %d starts at %d, want %d", i, c.Pos, pos)
		}
		last := i == len(chunks)-1
		if c.Size > maxChunk || (c.Size < minChunk && !last) {
			t.Errorf("chunk %d is %d bytes, outside [%d, %d]", i, c.Size, minChunk, maxChunk)
		}
		if chunkHash(data[c.Pos:c.Pos+int64(c.Size)]) != c.Hash {
			t.Errorf("chunk %d hash does not match its bytes", i)
		}
		pos += int64(c.Size)
	}
	if pos != int64(len(data)) {
		t.Errorf("chunks cover %d bytes, want %d", pos, len(data))
	}

	// Xet's target is 64 KiB on average.
	avg := len(data) / len(chunks)
	if avg < 56<<10 || avg > 80<<10 {
		t.Errorf("average chunk is %d KiB over %d chunks, want about 64", avg>>10, len(chunks))
	}
}

// The chunker sees the body in whatever pieces the network delivers, so the
// boundaries must not depend on them.
func TestChunkerIgnoresHowTheBytesAreSplitIntoWrites(t *testing.T) {
	data := pseudoRandom("splits", 4<<20)
	want := chunkAll(data, len(data))
	for _, size := range []int{1, 7, 4096, minChunk - 1, minChunk + 1, maxChunk + 3} {
		if got := chunkAll(data, size); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("writes of %d bytes cut %d chunks, want the same %d as one write", size, len(got), len(want))
		}
	}
}

// The point of content-defined chunking: an insertion near the front moves
// the boundaries next to it and leaves the chunks after it as they were.
func TestChunkerKeepsChunksAfterAnEdit(t *testing.T) {
	data := pseudoRandom("edit", 16<<20)
	edited := append(append(append([]byte{}, data[:1<<20]...), []byte("inserted bytes")...), data[1<<20:]...)

	before := map[string]bool{}
	for _, c := range chunkAll(data, 1<<16) {
		before[c.Hash] = true
	}
	after := chunkAll(edited, 1<<16)
	var shared int
	for _, c := range after {
		if before[c.Hash] {
			shared++
		}
	}
	if shared < len(after)-3 {
		t.Errorf("%d of %d chunks survive a 14-byte insertion, want all but a few", shared, len(after))
	}
}

func TestChunkerEdgeCases(t *testing.T) {
	if got := chunkAll(nil, 1); len(got) != 0 {
		t.Errorf("empty content cut into %d chunks, want none", len(got))
	}
	small := chunkAll([]byte("abc"), 1)
	if len(small) != 1 || small[0].Hash != chunkHash([]byte("abc")) || small[0].Size != 3 {
		t.Errorf("content under the minimum = %+v, want one chunk of it all", small)
	}
	// Content with no boundary at all (all zero bytes keep the gear hash
	// constant) is cut at the maximum.
	zeros := chunkAll(make([]byte, 3*maxChunk+5), 1<<16)
	if len(zeros) != 4 || zeros[0].Size != maxChunk || zeros[3].Size != 5 {
		t.Errorf("zeros cut into %d chunks (first %d bytes), want 3 at the maximum and the rest", len(zeros), zeros[0].Size)
	}
	if zeros[0].Hash != zeros[1].Hash {
		t.Error("identical runs of bytes should cut into identical chunks")
	}
}

// The boundaries are part of the storage format: if they moved, new uploads
// would stop deduplicating against everything stored before. This pins them
// for a fixed input; a change here needs a migration plan, not a new value.
func TestChunkerBoundariesArePinned(t *testing.T) {
	var cuts bytes.Buffer
	for _, c := range chunkAll(pseudoRandom("pinned", 8<<20), 1<<16) {
		fmt.Fprintf(&cuts, "%d,", c.Size)
	}
	sum := sha256.Sum256(cuts.Bytes())
	const want = "71c54fcd162b8282813bc2b8dedef439193c6851b1308341b268695ba7326702"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("chunk boundaries changed: digest %s, want %s (sizes %s)", got, want, cuts.String())
	}
}

func BenchmarkChunker(b *testing.B) {
	data := pseudoRandom("bench", 64<<20)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		chunkAll(data, 1<<16)
	}
}
