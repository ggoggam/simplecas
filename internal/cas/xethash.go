package cas

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/zeebo/blake3"
)

// Chunks and xorbs are hashed as the Xet protocol hashes them
// (https://huggingface.co/docs/xet/hashing), so a chunk or xorb hash here is
// the one any Xet implementation computes for the same bytes.
//
// A blob is still named by the plain BLAKE3 digest of its content: that is
// what the PWA hashes before an upload to ask whether it can link instead.

// Keys of the keyed BLAKE3 hashes the protocol uses.
var (
	dataKey = [32]byte{
		102, 151, 245, 119, 91, 149, 80, 222, 49, 53, 203, 172, 165, 151, 24, 28,
		157, 228, 33, 16, 155, 235, 43, 88, 180, 208, 176, 75, 147, 173, 242, 41,
	}
	internalNodeKey = [32]byte{
		1, 126, 197, 199, 165, 71, 41, 150, 253, 148, 102, 102, 180, 138, 2, 230,
		93, 221, 83, 111, 55, 199, 109, 210, 248, 99, 82, 230, 74, 83, 113, 63,
	}
)

// xetHex is a 32-byte hash as Xet writes it: each 8-byte group read as a
// little-endian integer and printed as 16 hex digits. It is not the plain hex
// of the bytes.
func xetHex(sum [32]byte) string {
	var b [32]byte
	for g := 0; g < 32; g += 8 {
		binary.BigEndian.PutUint64(b[g:], binary.LittleEndian.Uint64(sum[g:]))
	}
	return hex.EncodeToString(b[:])
}

// parseXetHex is the inverse of xetHex.
func parseXetHex(s string) ([32]byte, error) {
	var sum [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return sum, fmt.Errorf("invalid xet hash %q", s)
	}
	for g := 0; g < 32; g += 8 {
		binary.LittleEndian.PutUint64(sum[g:], binary.BigEndian.Uint64(b[g:]))
	}
	return sum, nil
}

// chunkHasher computes chunk hashes: BLAKE3 keyed with the data key.
type chunkHasher struct{ h *blake3.Hasher }

func newChunkHasher() *chunkHasher {
	h, err := blake3.NewKeyed(dataKey[:])
	if err != nil {
		panic(err) // the key is a fixed 32 bytes
	}
	return &chunkHasher{h: h}
}

func (c *chunkHasher) write(p []byte) { _, _ = c.h.Write(p) }
func (c *chunkHasher) reset()         { c.h.Reset() }

func (c *chunkHasher) sum() string {
	var sum [32]byte
	c.h.Sum(sum[:0])
	return xetHex(sum)
}

// chunkHash is the Xet hash of one chunk's bytes.
func chunkHash(data []byte) string {
	h := newChunkHasher()
	h.write(data)
	return h.sum()
}

// hashedSize is a chunk, or a subtree of chunks, in the Merkle tree: its hash
// and how many bytes it covers.
type hashedSize struct {
	hash [32]byte
	size uint64
}

// meanBranching is the tree's average fan-out: a node ends after a child
// whose hash is a multiple of it, with at least 2 and at most 9 children.
const meanBranching = 4

// xorbHash is the Xet hash of a xorb holding chunks, given as Xet hex
// hashes and sizes: the root of the protocol's Merkle tree over them. A
// single chunk is its own root.
func xorbHash(chunks []hashedSize) [32]byte {
	if len(chunks) == 0 {
		return [32]byte{}
	}
	level := append([]hashedSize(nil), chunks...)
	for len(level) > 1 {
		var next []hashedSize
		for start := 0; start < len(level); {
			end := start + nextMergeCut(level[start:])
			next = append(next, mergeNode(level[start:end]))
			start = end
		}
		level = next
	}
	return level[0].hash
}

// fileHash is the Xet file hash of content cut into chunks: the Merkle root
// of its chunks, hashed again with an all-zero key.
func fileHash(chunks []hashedSize) [32]byte {
	if len(chunks) == 0 {
		return [32]byte{}
	}
	root := xorbHash(chunks)
	var zero [32]byte
	h, err := blake3.NewKeyed(zero[:])
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(root[:])
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}

// nextMergeCut is how many of nodes the next parent takes: up to and
// including the first from the third on whose hash is a multiple of
// meanBranching, at most 2*meanBranching+1, and all of them when two or fewer
// are left.
func nextMergeCut(nodes []hashedSize) int {
	if len(nodes) <= 2 {
		return len(nodes)
	}
	end := min(2*meanBranching+1, len(nodes))
	for i := 2; i < end; i++ {
		if binary.LittleEndian.Uint64(nodes[i].hash[24:])%meanBranching == 0 {
			return i + 1
		}
	}
	return end
}

// mergeNode hashes children into their parent: one line per child of
// "<xet hex> : <size>\n", hashed with the internal node key.
func mergeNode(children []hashedSize) hashedSize {
	buf := make([]byte, 0, len(children)*88)
	var total uint64
	for _, c := range children {
		buf = append(buf, xetHex(c.hash)...)
		buf = append(buf, " : "...)
		buf = strconv.AppendUint(buf, c.size, 10)
		buf = append(buf, '\n')
		total += c.size
	}
	h, err := blake3.NewKeyed(internalNodeKey[:])
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(buf)
	var sum [32]byte
	h.Sum(sum[:0])
	return hashedSize{hash: sum, size: total}
}
