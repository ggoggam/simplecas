package cas

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/pierrec/lz4/v4"
)

// Xorbs are serialized in the Xet protocol's format
// (https://huggingface.co/docs/xet/xorb): each chunk is an 8-byte header
// followed by its data, compressed or not, and a xorb is its chunks one after
// another. The header is a version byte (0), the stored length (3 bytes,
// little-endian), the compression scheme (1 byte) and the length once
// decompressed (3 bytes, little-endian).
const (
	chunkHeaderLen     = 8
	chunkFormatVersion = 0

	// A xorb holds at most maxXorbBytes as stored and maxXorbChunks chunks.
	maxXorbBytes  = 64 << 20
	maxXorbChunks = 8 << 10
)

// Compression schemes a chunk header names.
const (
	schemeNone   = 0
	schemeLZ4    = 1
	schemeBG4LZ4 = 2 // byte grouping in 4 groups, then LZ4
)

// worstCaseStored is the most bytes chunks of rawBytes in total can take in a
// xorb: a chunk that does not shrink is stored as it is, behind its header.
func worstCaseStored(rawBytes int64, chunks int) int64 {
	return rawBytes + int64(chunks)*chunkHeaderLen
}

// LZ4 data is in the LZ4 frame format, as the reference implementation's
// lz4_flex FrameEncoder writes it: 64 KiB independent blocks with no
// checksums, which a chunk's own hash makes redundant.
var lz4Writers = sync.Pool{New: func() any {
	w := lz4.NewWriter(nil)
	if err := w.Apply(lz4.BlockSizeOption(lz4.Block64Kb), lz4.ChecksumOption(false),
		lz4.BlockChecksumOption(false), lz4.ConcurrencyOption(1)); err != nil {
		panic(err)
	}
	return w
}}

var lz4Readers = sync.Pool{New: func() any { return lz4.NewReader(nil) }}

// appendChunk appends raw to dst as a xorb chunk, LZ4-compressed unless that
// would not make it smaller.
//
// The protocol leaves the choice of scheme to the writer. Byte grouping helps
// arrays of numbers, and the reference implementation picks it by a heuristic;
// every scheme is read here, but only LZ4 is written.
func appendChunk(dst, raw []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, chunkHeaderLen)...)

	w := lz4Writers.Get().(*lz4.Writer)
	buf := bytes.NewBuffer(dst)
	w.Reset(buf)
	_, werr := w.Write(raw)
	cerr := w.Close()
	lz4Writers.Put(w)
	dst = buf.Bytes()

	scheme := byte(schemeLZ4)
	if werr != nil || cerr != nil || len(dst)-start-chunkHeaderLen >= len(raw) {
		dst = append(dst[:start+chunkHeaderLen], raw...)
		scheme = schemeNone
	}
	putChunkHeader(dst[start:], len(dst)-start-chunkHeaderLen, scheme, len(raw))
	return dst
}

func putChunkHeader(h []byte, stored int, scheme byte, size int) {
	h[0] = chunkFormatVersion
	h[1], h[2], h[3] = byte(stored), byte(stored>>8), byte(stored>>16)
	h[4] = scheme
	h[5], h[6], h[7] = byte(size), byte(size>>8), byte(size>>16)
}

// decodeChunk decodes one serialized chunk, which must take exactly all of b,
// and checks that it decompresses to size bytes.
func decodeChunk(b []byte, size int) ([]byte, error) {
	if len(b) < chunkHeaderLen || b[0] != chunkFormatVersion {
		return nil, fmt.Errorf("not a chunk header")
	}
	stored := int(b[1]) | int(b[2])<<8 | int(b[3])<<16
	unpacked := int(b[5]) | int(b[6])<<8 | int(b[7])<<16
	if stored != len(b)-chunkHeaderLen || unpacked != size {
		return nil, fmt.Errorf("chunk header says %d bytes stored, %d unpacked; want %d and %d",
			stored, unpacked, len(b)-chunkHeaderLen, size)
	}
	data := b[chunkHeaderLen:]
	var raw []byte
	switch b[4] {
	case schemeNone:
		raw = data
	case schemeLZ4, schemeBG4LZ4:
		r := lz4Readers.Get().(*lz4.Reader)
		r.Reset(bytes.NewReader(data))
		raw = make([]byte, 0, size)
		out := bytes.NewBuffer(raw)
		_, err := io.Copy(out, io.LimitReader(r, int64(size)+1))
		lz4Readers.Put(r)
		if err != nil {
			return nil, fmt.Errorf("decompress chunk: %w", err)
		}
		raw = out.Bytes()
		if b[4] == schemeBG4LZ4 {
			raw = bg4Regroup(raw)
		}
	default:
		return nil, fmt.Errorf("unknown chunk compression scheme %d", b[4])
	}
	if len(raw) != size {
		return nil, fmt.Errorf("chunk decompressed to %d bytes, want %d", len(raw), size)
	}
	return raw, nil
}

// bg4Split groups data by byte position modulo 4: every first byte, then
// every second, and so on. The groups of a length that is not a multiple of
// 4 are one byte longer, first to last, for the bytes left over.
func bg4Split(data []byte) []byte {
	out := make([]byte, len(data))
	starts := bg4Starts(len(data))
	for i, b := range data {
		g := i % 4
		out[starts[g]+i/4] = b
	}
	return out
}

// bg4Regroup is the inverse of bg4Split.
func bg4Regroup(grouped []byte) []byte {
	out := make([]byte, len(grouped))
	starts := bg4Starts(len(grouped))
	for i := range out {
		out[i] = grouped[starts[i%4]+i/4]
	}
	return out
}

func bg4Starts(n int) (starts [4]int) {
	base, extra := n/4, n%4
	pos := 0
	for g := range starts {
		starts[g] = pos
		pos += base
		if g < extra {
			pos++
		}
	}
	return starts
}
