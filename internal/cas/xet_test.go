package cas

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Reference values from the Xet protocol's reference files (see
// testdata/xet/README.md).
const (
	refXorbHash = "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632"
	refFileHash = "118a53328412787fee04011dcf82fdc4acf3a4a1eddec341c910d30a306aaf97"
	refCSV      = "Electric_Vehicle_Population_Data_20250917.csv"
)

// refChunks reads the reference file's chunks: Xet hex hash and length.
func refChunks(t *testing.T) []hashedSize {
	t.Helper()
	f, err := os.Open("testdata/xet/reference.chunks")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []hashedSize
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		hash, size, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			t.Fatalf("bad line %q", sc.Text())
		}
		sum, err := parseXetHex(hash)
		if err != nil {
			t.Fatal(err)
		}
		n, err := strconv.ParseUint(size, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, hashedSize{hash: sum, size: n})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Chunk, xorb and file hashes are the protocol's: any Xet implementation
// computes the same ones.
func TestXetHashesMatchTheReference(t *testing.T) {
	name := "099cb228194fe640e36a6c7d274ee5ed3a714ccd557a0951d9b6b43a7292b5d1"
	data, err := os.ReadFile(filepath.Join("testdata/xet", name+".chunk"))
	if err != nil {
		t.Fatal(err)
	}
	if got := chunkHash(data); got != name {
		t.Errorf("chunk hash = %s, want %s", got, name)
	}

	chunks := refChunks(t)
	if got := xetHex(xorbHash(chunks)); got != refXorbHash {
		t.Errorf("xorb hash = %s, want %s", got, refXorbHash)
	}
	if got := xetHex(fileHash(chunks)); got != refFileHash {
		t.Errorf("file hash = %s, want %s", got, refFileHash)
	}
	// A single chunk is its own root.
	if got := xorbHash(chunks[:1]); got != chunks[0].hash {
		t.Errorf("a one-chunk xorb hash = %s, want the chunk's own %s", xetHex(got), xetHex(chunks[0].hash))
	}
}

func TestXetHexReversesEachEightByteGroup(t *testing.T) {
	var sum [32]byte
	for i := range sum {
		sum[i] = byte(i)
	}
	// The protocol's own example of this drops byte 0x10 from the third
	// group; this is the full 64 digits.
	const want = "07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
	if got := xetHex(sum); got != want {
		t.Errorf("xetHex = %s, want %s", got, want)
	}
	back, err := parseXetHex(want)
	if err != nil || back != sum {
		t.Errorf("parseXetHex = %v, %v; want the bytes back", back, err)
	}
}

// With the reference file at hand, the chunker cuts it exactly as Xet does,
// and the reference xorb decodes back to it.
func TestXetReferenceFile(t *testing.T) {
	dir := os.Getenv("SIMPLECAS_XET_REFERENCE_DIR")
	if dir == "" {
		t.Skip("SIMPLECAS_XET_REFERENCE_DIR not set; see testdata/xet/README.md")
	}
	data, err := os.ReadFile(filepath.Join(dir, refCSV))
	if err != nil {
		t.Fatal(err)
	}
	want := refChunks(t)
	got := chunkAll(data, 77777)
	if len(got) != len(want) {
		t.Fatalf("cut %d chunks, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.Hash != xetHex(want[i].hash) || uint64(c.Size) != want[i].size {
			t.Fatalf("chunk %d = %s (%d bytes), want %s (%d)", i, c.Hash, c.Size, xetHex(want[i].hash), want[i].size)
		}
	}

	xorb, err := os.ReadFile(filepath.Join(dir, refXorbHash+".xorb"))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	off := 0
	for i, c := range got {
		stored := int(xorb[off+1]) | int(xorb[off+2])<<8 | int(xorb[off+3])<<16
		raw, err := decodeChunk(xorb[off:off+chunkHeaderLen+stored], int(c.Size))
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		out.Write(raw)
		off += chunkHeaderLen + stored
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Error("the reference xorb does not decode to the reference file")
	}
}

func TestChunkSerializationRoundTrips(t *testing.T) {
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
			b := appendChunk([]byte("prefix"), tc.data)
			chunk := b[len("prefix"):]
			if chunk[4] != tc.scheme {
				t.Errorf("scheme = %d, want %d", chunk[4], tc.scheme)
			}
			if tc.scheme == schemeNone && len(chunk) != chunkHeaderLen+len(tc.data) {
				t.Errorf("stored %d bytes, want the data as it is behind its header", len(chunk))
			}
			got, err := decodeChunk(chunk, len(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Error("decoded bytes differ")
			}
			if _, err := decodeChunk(chunk, len(tc.data)+1); err == nil {
				t.Error("a chunk of the wrong size decoded")
			}
			if _, err := decodeChunk(chunk[:len(chunk)-1], len(tc.data)); err == nil && len(chunk) > chunkHeaderLen {
				t.Error("a truncated chunk decoded")
			}
		})
	}
}

// Byte grouping is read even though it is never written, so xorbs any Xet
// client writes can be read.
func TestDecodeChunkReadsByteGrouping(t *testing.T) {
	for _, n := range []int{0, 1, 5, 4096, 4099} {
		data := pseudoRandom("bg4", n)
		if back := bg4Regroup(bg4Split(data)); !bytes.Equal(back, data) {
			t.Fatalf("bg4 of %d bytes does not round-trip", n)
		}
	}
	data := bytes.Repeat([]byte{1, 2, 3, 4, 5}, 1000)
	lz4ed := appendChunk(nil, bg4Split(data))
	if lz4ed[4] != schemeLZ4 {
		t.Fatal("setup: grouped data should compress")
	}
	lz4ed[4] = schemeBG4LZ4
	lz4ed[5], lz4ed[6], lz4ed[7] = byte(len(data)), byte(len(data)>>8), byte(len(data)>>16)
	got, err := decodeChunk(lz4ed, len(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("a byte-grouped chunk decoded wrong")
	}
	if g := bg4Split([]byte{1, 2, 3, 4, 5, 6}); hex.EncodeToString(g) != "010502060304" {
		t.Errorf("bg4Split = %x, want the spec's grouping 010502060304", g)
	}
}
