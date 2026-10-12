package cas

import (
	"context"
	"io"
	"strings"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// readAhead is how many fetches a read keeps in flight ahead of the bytes it
// is serving.
const readAhead = 4

// readGroup caps how many stored bytes one fetch reads. Neighbouring chunks
// of a xorb are fetched together, as the Xet download protocol coalesces
// them, in one ranged request of up to this much.
const readGroup = 8 << 20

// termPage is how many terms a read looks up at a time, so a read of a large
// object does not load all of its terms up front.
const termPage = 256

// Open returns the bytes [start, start+length) of the blob hash.
//
// A chunked blob is read term by term, fetching only the chunks the range
// overlaps, each run of neighbouring chunks in one ranged request. Each chunk
// is decoded and checked against its hash before any of it is served, so a
// chunk that rotted or was truncated in the backend fails the read instead of
// reaching the client; a failure after the first fetch surfaces as an error
// from Read. A blob stored before chunking is read straight from its file,
// unchecked.
//
// Open waits for the first fetch, so a read that cannot start at all fails
// here, before the caller has committed to a response.
func (s *Store) Open(ctx context.Context, hash string, start, length int64) (io.ReadCloser, error) {
	if length <= 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	chunked, err := s.db.BlobChunked(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !chunked {
		r, err := s.blob.NewRangeReader(ctx, storage.BlobPath(hash), start, length, nil)
		if err != nil {
			return nil, apperr.Internalf("open blob: %w", err)
		}
		return r, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	r := &chunkReader{ctx: ctx, queue: make(chan chan fetched, readAhead), cancel: cancel, left: length}
	go r.produce(ctx, s, hash, start, start+length)
	if r.err = r.next(); r.err != nil {
		_ = r.Close()
		return nil, r.err
	}
	return r, nil
}

// fetched is the bytes of one fetch that fall in the range being read, or why
// they could not be had.
type fetched struct {
	data []byte
	err  error
}

// chunkReader serves a range of a chunked blob. A producer goroutine walks the
// blob's terms and starts a fetch per run of chunks, queueing a result slot
// for each in order; the queue's capacity is the read-ahead. Read takes the
// slots in order, so bytes are served in order however their fetches finish.
type chunkReader struct {
	ctx    context.Context
	queue  chan chan fetched
	cancel context.CancelFunc
	cur    []byte
	left   int64 // bytes of the range not yet served
	err    error
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.cur) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.err = r.next()
	}
	n := copy(p, r.cur)
	r.cur = r.cur[n:]
	r.left -= int64(n)
	return n, nil
}

// next waits for the next fetch in order. Once the producer is done it is
// io.EOF if the whole range was served, and an error otherwise: a cancelled
// read must not look like a short object.
func (r *chunkReader) next() error {
	slot, ok := <-r.queue
	if !ok {
		if r.left == 0 {
			return io.EOF
		}
		if err := r.ctx.Err(); err != nil {
			return err
		}
		return io.ErrUnexpectedEOF
	}
	f := <-slot
	if f.err != nil {
		return f.err
	}
	r.cur = f.data
	return nil
}

// Close stops the producer and any fetches in flight. Their result slots are
// buffered, so nothing is left blocked on a reader that went away.
func (r *chunkReader) Close() error {
	r.cancel()
	return nil
}

// span is a chunk to fetch and the part of it, [lo, hi), the range wants.
type span struct {
	db.XorbChunk
	lo, hi int64
}

// produce queues a fetch for every run of chunks overlapping [from, to), in
// order. The terms are contiguous, so each has to start where the last ended;
// a gap, or terms that end early, means the blob was collected under the
// read, and fails it rather than serving a short body as if it were whole.
func (r *chunkReader) produce(ctx context.Context, s *Store, hash string, from, to int64) {
	defer close(r.queue)
	fail := func(err error) {
		slot := make(chan fetched, 1)
		slot <- fetched{err: err}
		select {
		case r.queue <- slot:
		case <-ctx.Done():
		}
	}

	var (
		group     []span
		groupXorb string
		groupLen  int64
	)
	flush := func() bool {
		if len(group) == 0 {
			return true
		}
		slot := make(chan fetched, 1)
		select {
		case r.queue <- slot:
		case <-ctx.Done():
			return false
		}
		g, x := group, groupXorb
		go func() { slot <- s.fetchRun(ctx, x, g) }()
		group, groupLen = nil, 0
		return true
	}

	pos := from
	for pos < to {
		before := pos
		terms, err := s.db.BlobTerms(ctx, hash, pos, to, termPage)
		if err == nil && (len(terms) == 0 || terms[0].Pos > pos) {
			err = apperr.Internalf("blob %s has no term at offset %d", hash, pos)
		}
		if err != nil {
			fail(err)
			return
		}
		for _, t := range terms {
			if t.Pos > pos {
				fail(apperr.Internalf("blob %s has no term at offset %d", hash, pos))
				return
			}
			chunks, err := s.db.XorbChunks(ctx, t.Xorb, t.Start, t.End)
			if err == nil && len(chunks) != int(t.End-t.Start) {
				err = apperr.Internalf("xorb %s is missing chunks of a term of blob %s", t.Xorb, hash)
			}
			if err != nil {
				fail(err)
				return
			}
			// The chunks must add up to the term, as the protocol checks a
			// term's unpacked length.
			var total int64
			for _, c := range chunks {
				total += int64(c.Size)
			}
			if total != t.Size {
				fail(apperr.Internalf("term at %d of blob %s holds %d bytes, want %d", t.Pos, hash, total, t.Size))
				return
			}

			at := t.Pos
			for _, c := range chunks {
				end := at + int64(c.Size)
				if end > pos && at < to {
					sp := span{XorbChunk: c, lo: max(pos, at) - at, hi: min(to, end) - at}
					adjacent := len(group) > 0 && groupXorb == t.Xorb &&
						group[len(group)-1].Offset+int64(group[len(group)-1].Length) == c.Offset
					if !adjacent || groupLen+int64(c.Length) > readGroup {
						if !flush() {
							return
						}
						groupXorb = t.Xorb
					}
					group = append(group, sp)
					groupLen += int64(c.Length)
					pos = min(to, end)
				}
				at = end
			}
			if pos >= to {
				break
			}
		}
		if pos == before {
			fail(apperr.Internalf("blob %s has no bytes at offset %d", hash, pos))
			return
		}
	}
	flush()
}

// fetchRun reads a run of neighbouring chunks of a xorb in one ranged
// request, decodes each and checks it against its hash, and returns the
// bytes of them the range wants.
func (s *Store) fetchRun(ctx context.Context, xorb string, run []span) fetched {
	first, last := run[0], run[len(run)-1]
	start := first.Offset
	length := last.Offset + int64(last.Length) - start
	rr, err := s.blob.NewRangeReader(ctx, storage.XorbPath(xorb), start, length, nil)
	if err != nil {
		return fetched{err: apperr.Internalf("read xorb %s: %w", xorb, err)}
	}
	stored, err := io.ReadAll(rr)
	_ = rr.Close()
	if err != nil {
		return fetched{err: apperr.Internalf("read xorb %s: %w", xorb, err)}
	}
	if int64(len(stored)) != length {
		return fetched{err: s.corrupt(xorb, "short read", len(stored), length)}
	}

	var out []byte
	for _, sp := range run {
		b := stored[sp.Offset-start : sp.Offset-start+int64(sp.Length)]
		raw, err := decodeChunk(b, int(sp.Size))
		if err != nil {
			return fetched{err: s.corrupt(xorb, err.Error(), sp.Offset, sp.Hash)}
		}
		if chunkHash(raw) != sp.Hash {
			return fetched{err: s.corrupt(xorb, "chunk does not match its hash", sp.Offset, sp.Hash)}
		}
		if len(run) == 1 {
			return fetched{data: raw[sp.lo:sp.hi]}
		}
		out = append(out, raw[sp.lo:sp.hi]...)
	}
	return fetched{data: out}
}

// corrupt logs stored bytes that failed verification and returns the error
// the read fails with.
func (s *Store) corrupt(xorb, why string, at, want any) error {
	s.log.Error("stored xorb failed verification", "xorb", xorb, "why", why, "at", at, "want", want)
	return apperr.Internalf("xorb %s failed verification", xorb)
}
