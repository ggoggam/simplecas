package cas

import (
	"context"
	"errors"
	"io"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// minDedupRun is the fewest chunks in a row a new blob reuses from a stored
// xorb. Reusing shorter runs saves a little space and scatters the blob over
// many xorbs, which costs a request per run on every read; the Xet protocol
// recommends at least 8 (https://huggingface.co/docs/xet/deduplication).
const minDedupRun = 8

// route is what a commit does with one chunk of the content.
type route uint8

const (
	// routeNew stores the chunk in one of the commit's new xorbs.
	routeNew route = iota
	// routeReuse points at a stored xorb that already holds the chunk.
	routeReuse
	// routeDecoy points at a stored xorb too, but still writes the chunk,
	// to a scratch object deleted after the commit, so the upload takes as
	// long as if the chunk were new: see commit.
	routeDecoy
)

// commitPlan is what a commit writes and how the blob's terms point at it.
type commitPlan struct {
	// attach is set when the plan expects to create the blob row, with
	// terms. A plan made for content already stored has no terms.
	attach bool
	routes []route
	// xorbOf and indexIn say, for a chunk routed to a new xorb, which one
	// and where in it.
	xorbOf  []int
	indexIn []int32
	xorbs   []plannedXorb
	terms   []db.Term
	decoys  [][]int // chunk indexes per scratch object
}

// plannedXorb is a new xorb: the chunks of the content it holds, in order.
type plannedXorb struct {
	hash   string
	chunks []int
	raw    int64
}

// writes reports whether carrying the plan out writes anything.
func (p *commitPlan) writes() bool { return len(p.xorbs) > 0 || len(p.decoys) > 0 }

// plan decides what committing staged to the namespace writes, the way a Xet
// client does before an upload: chunks some live xorb holds in runs of at
// least minDedupRun are reused, and the rest go into new xorbs in content
// order, so each new xorb holds long runs of the blob.
//
// Dedup is global, so a commit must not take less time because other
// namespaces store the content (see commit). Chunks reused from runs this
// namespace already has are skipped outright; any other reused run is written
// anyway, as a decoy that is deleted once the commit is done.
func (s *Store) plan(ctx context.Context, staged StagedBlob, namespaceID int64) (*commitPlan, error) {
	p := &commitPlan{}
	if len(staged.Chunks) == 0 {
		p.attach = true
		return p, nil
	}
	exists, held, err := s.db.BlobPlacement(ctx, staged.Hash, namespaceID)
	if err != nil {
		return nil, err
	}
	if held {
		return p, nil
	}
	if exists {
		// Stored for someone else: written in full, then thrown away.
		p.decoys = groupForXorbs(staged.Chunks, allIndexes(len(staged.Chunks)))
		return p, nil
	}

	p.attach = true
	p.routes = make([]route, len(staged.Chunks))
	p.xorbOf = make([]int, len(staged.Chunks))
	p.indexIn = make([]int32, len(staged.Chunks))
	locs := make([]db.ChunkLocation, len(staged.Chunks))

	runs, err := s.reusableRuns(ctx, staged.Chunks)
	if err != nil {
		return nil, err
	}
	runTerms := make([]db.Term, len(runs))
	for i, r := range runs {
		runTerms[i] = db.Term{Xorb: r.loc.Xorb, Start: r.loc.Index, End: r.loc.Index + int32(r.end-r.start)}
	}
	heldRuns, err := s.db.TermsHeldInNamespace(ctx, namespaceID, runTerms)
	if err != nil {
		return nil, err
	}
	var newChunks, decoyChunks []int
	reused := make([]bool, len(staged.Chunks))
	for i, r := range runs {
		rt := routeReuse
		if !heldRuns[i] {
			rt = routeDecoy
		}
		for c := r.start; c < r.end; c++ {
			reused[c] = true
			p.routes[c] = rt
			locs[c] = db.ChunkLocation{Xorb: r.loc.Xorb, Index: r.loc.Index + int32(c-r.start)}
			if rt == routeDecoy {
				decoyChunks = append(decoyChunks, c)
			}
		}
	}
	for c := range staged.Chunks {
		if !reused[c] {
			newChunks = append(newChunks, c)
		}
	}

	for x, chunks := range groupForXorbs(staged.Chunks, newChunks) {
		px := plannedXorb{chunks: chunks}
		nodes := make([]hashedSize, len(chunks))
		for i, c := range chunks {
			ref := staged.Chunks[c]
			sum, err := parseXetHex(ref.Hash)
			if err != nil {
				return nil, apperr.Internal(err)
			}
			nodes[i] = hashedSize{hash: sum, size: uint64(ref.Size)}
			px.raw += int64(ref.Size)
			p.routes[c] = routeNew
			p.xorbOf[c] = x
			p.indexIn[c] = int32(i)
		}
		px.hash = xetHex(xorbHash(nodes))
		for i, c := range chunks {
			locs[c] = db.ChunkLocation{Xorb: px.hash, Index: int32(i)}
		}
		p.xorbs = append(p.xorbs, px)
	}
	p.decoys = groupForXorbs(staged.Chunks, decoyChunks)

	// Terms: consecutive chunks at consecutive places in one xorb.
	for c, ref := range staged.Chunks {
		loc := locs[c]
		if n := len(p.terms); n > 0 {
			t := &p.terms[n-1]
			if t.Xorb == loc.Xorb && t.End == loc.Index {
				t.End++
				t.Size += int64(ref.Size)
				continue
			}
		}
		p.terms = append(p.terms, db.Term{Pos: ref.Pos, Xorb: loc.Xorb, Start: loc.Index, End: loc.Index + 1, Size: int64(ref.Size)})
	}
	return p, nil
}

// run is chunks [start, end) of the content, held in a stored xorb from loc
// on.
type run struct {
	start, end int
	loc        db.ChunkLocation
}

// reusableRuns finds the runs of chunks stored xorbs already hold that are
// long enough to reuse: minDedupRun chunks, or the whole content.
func (s *Store) reusableRuns(ctx context.Context, chunks []db.ChunkRef) ([]run, error) {
	hashes := make([]string, 0, len(chunks))
	seen := make(map[string]bool, len(chunks))
	for _, c := range chunks {
		if !seen[c.Hash] {
			seen[c.Hash] = true
			hashes = append(hashes, c.Hash)
		}
	}
	found, err := s.db.LocateChunks(ctx, hashes)
	if err != nil {
		return nil, err
	}

	var runs []run
	keep := func(r run) {
		if n := r.end - r.start; n >= minDedupRun || n == len(chunks) {
			runs = append(runs, r)
		}
	}
	var cur *run
	for i, c := range chunks {
		locs := found[c.Hash]
		if cur != nil {
			next := db.ChunkLocation{Xorb: cur.loc.Xorb, Index: cur.loc.Index + int32(i-cur.start)}
			if containsLoc(locs, next) {
				cur.end = i + 1
				continue
			}
			keep(*cur)
			cur = nil
		}
		if len(locs) == 0 {
			continue
		}
		// Start where the next chunk can follow, if anywhere.
		start := locs[0]
		if i+1 < len(chunks) {
			for _, l := range locs {
				if containsLoc(found[chunks[i+1].Hash], db.ChunkLocation{Xorb: l.Xorb, Index: l.Index + 1}) {
					start = l
					break
				}
			}
		}
		cur = &run{start: i, end: i + 1, loc: start}
	}
	if cur != nil {
		keep(*cur)
	}
	return runs, nil
}

func containsLoc(locs []db.ChunkLocation, l db.ChunkLocation) bool {
	for _, x := range locs {
		if x == l {
			return true
		}
	}
	return false
}

func allIndexes(n int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	return idx
}

// groupForXorbs splits the chunks at indexes, in order, into groups that each
// fit one xorb.
func groupForXorbs(chunks []db.ChunkRef, indexes []int) [][]int {
	var (
		groups [][]int
		cur    []int
		raw    int64
	)
	for _, c := range indexes {
		size := int64(chunks[c].Size)
		if len(cur) > 0 && (len(cur) == maxXorbChunks || worstCaseStored(raw+size, len(cur)+1) > maxXorbBytes) {
			groups = append(groups, cur)
			cur, raw = nil, 0
		}
		cur = append(cur, c)
		raw += size
	}
	if len(cur) > 0 {
		groups = append(groups, cur)
	}
	return groups
}

// xorbUploads is how many finished xorbs a commit uploads while it fills the
// next. On an object store a writer buffers its whole object in memory to
// send it in one request, so each costs up to a xorb's worth of memory.
const xorbUploads = 1

// written is what carrying out a plan stored: the new xorbs, as the database
// records them, and the scratch objects to delete afterwards.
type written struct {
	xorbs  []db.NewXorb
	decoys []string
}

// carryOut writes a plan's xorbs and decoys, reading the staging file once,
// front to back. Each chunk is hashed again on the way, so bytes that changed
// in staging since they were hashed are refused rather than stored under the
// wrong address. A xorb already in the backend is left as it is: its bytes
// may be serialized differently from this commit's, and other blobs' offsets
// describe them.
func (s *Store) carryOut(ctx context.Context, staged StagedBlob, p *commitPlan) (w written, err error) {
	w.xorbs = make([]db.NewXorb, len(p.xorbs))
	for i, x := range p.xorbs {
		w.xorbs[i] = db.NewXorb{Hash: x.hash, Chunks: make([]db.XorbChunk, 0, len(x.chunks))}
	}
	if !p.writes() {
		return w, nil
	}
	defer func() {
		if err != nil {
			s.discardDecoys(context.WithoutCancel(ctx), w.decoys)
		}
	}()

	r, err := s.blob.NewReader(ctx, staged.StagingKey, nil)
	if err != nil {
		return w, apperr.Internalf("open staged upload: %w", err)
	}
	defer func() { _ = r.Close() }()

	decoyOf := make(map[int]int)
	for d, chunks := range p.decoys {
		for _, c := range chunks {
			decoyOf[c] = d
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(xorbUploads)

	// Each chunk goes to at most one object: the new xorb or the decoy it
	// belongs to. Both kinds are filled in content order, so one of each is
	// open at a time, and each is sent whole once it is full.
	var xorbOut, decoyOut *objectWriter
	finish := func(o *objectWriter, x *db.NewXorb) {
		g.Go(func() error {
			existed, err := o.close()
			if err != nil {
				return err
			}
			if x != nil {
				x.Size, x.Existed = o.n, existed
			}
			return nil
		})
	}

	var scratch []byte
	xorbAt, decoyAt := -1, -1
	for c, ref := range staged.Chunks {
		if gctx.Err() != nil {
			break
		}
		raw := make([]byte, ref.Size)
		if _, err := io.ReadFull(r, raw); err != nil {
			return w, errors.Join(apperr.Internalf("read staged chunk at %d: %w", ref.Pos, err), g.Wait())
		}
		rt := routeReuse
		if p.routes != nil {
			rt = p.routes[c]
		} else if _, ok := decoyOf[c]; ok {
			rt = routeDecoy
		}
		if rt == routeReuse {
			continue
		}
		if chunkHash(raw) != ref.Hash {
			return w, errors.Join(apperr.Internalf("staged chunk at %d no longer matches its hash", ref.Pos), g.Wait())
		}
		scratch = appendChunk(scratch[:0], raw)

		var out *objectWriter
		switch rt {
		case routeNew:
			if x := p.xorbOf[c]; x != xorbAt {
				if xorbOut != nil {
					finish(xorbOut, &w.xorbs[xorbAt])
				}
				px := p.xorbs[x]
				xorbOut, err = s.openObject(gctx, storage.XorbPath(px.hash), worstCaseStored(px.raw, len(px.chunks)), true)
				if err != nil {
					return w, errors.Join(err, g.Wait())
				}
				xorbAt = x
			}
			x := &w.xorbs[xorbAt]
			x.Chunks = append(x.Chunks, db.XorbChunk{
				Hash: ref.Hash, Offset: xorbOut.n, Length: int32(len(scratch)), Size: ref.Size,
			})
			out = xorbOut
		case routeDecoy:
			if d := decoyOf[c]; d != decoyAt {
				if decoyOut != nil {
					finish(decoyOut, nil)
				}
				var raw int64
				for _, dc := range p.decoys[d] {
					raw += int64(staged.Chunks[dc].Size)
				}
				key := storage.StagingPath(uuid.NewString())
				w.decoys = append(w.decoys, key)
				decoyOut, err = s.openObject(gctx, key, worstCaseStored(raw, len(p.decoys[d])), false)
				if err != nil {
					return w, errors.Join(err, g.Wait())
				}
				decoyAt = d
			}
			out = decoyOut
		}
		if err := out.write(scratch); err != nil {
			return w, errors.Join(err, g.Wait())
		}
	}
	// Objects cut short by a failure are not sent at all.
	if gctx.Err() == nil {
		if xorbOut != nil {
			finish(xorbOut, &w.xorbs[xorbAt])
		}
		if decoyOut != nil {
			finish(decoyOut, nil)
		}
	}
	if err := g.Wait(); err != nil {
		return w, err
	}
	// A cancelled request can stop the loop between uploads, with every
	// upload so far a success; that is still a failure.
	return w, ctx.Err()
}

// objectWriter is one object a commit is filling, buffered whole so it can be
// sent in one request.
type objectWriter struct {
	s     *Store
	ctx   context.Context
	key   string
	buf   []byte
	n     int64
	ifNew bool
}

// openObject starts an object of at most maxSize bytes. With ifNew, an object
// already at key is left alone.
func (s *Store) openObject(ctx context.Context, key string, maxSize int64, ifNew bool) (*objectWriter, error) {
	return &objectWriter{s: s, ctx: ctx, key: key, buf: make([]byte, 0, maxSize), ifNew: ifNew}, nil
}

func (o *objectWriter) write(p []byte) error {
	o.buf = append(o.buf, p...)
	o.n += int64(len(p))
	return nil
}

// close sends the object. existed reports an ifNew object that was already
// there, and so was not written.
func (o *objectWriter) close() (existed bool, err error) {
	err = o.s.blob.PutOnce(o.ctx, o.key, o.buf, o.ifNew)
	o.buf = nil
	if errors.Is(err, storage.ErrExists) {
		return true, nil
	}
	if err != nil {
		return false, apperr.Internalf("write %s: %w", o.key, err)
	}
	return false, nil
}

// discardDecoys deletes a commit's scratch objects. Best-effort: the staging
// sweeper collects any left behind.
func (s *Store) discardDecoys(ctx context.Context, keys []string) {
	for _, key := range keys {
		s.DiscardStaging(ctx, key)
	}
}

// xorbBytes gives db.AttachTerms access to xorbs in the backend.
type xorbBytes struct{ s *Store }

func (x xorbBytes) Present(ctx context.Context, hash string) (bool, error) {
	ok, err := x.s.blob.Exists(ctx, storage.XorbPath(hash))
	if err != nil {
		return false, apperr.Internalf("check xorb: %w", err)
	}
	return ok, nil
}

func (x xorbBytes) Discard(ctx context.Context, hash string) error {
	if err := x.s.deleteIfPresent(ctx, storage.XorbPath(hash)); err != nil {
		return apperr.Internalf("discard xorb: %w", err)
	}
	return nil
}

// errStale is db.ErrStaleXorbs.
var errStale = db.ErrStaleXorbs

func isStale(err error) bool { return errors.Is(err, errStale) }
