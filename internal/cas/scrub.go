package cas

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zeebo/blake3"
	"gocloud.dev/gcerrors"

	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// scrubBatch is how many pieces of content one scrub claim takes. Small, so
// that content claimed by an instance that then stops waits a whole interval
// only in small numbers.
const scrubBatch = 4

// RunScrub reads stored content back and checks it against its hashes until
// ctx is cancelled: every live xorb, chunk by chunk, and every live blob
// stored whole before chunking. Each is checked once per
// [gc] scrub_interval_secs, those never checked first, at no more than
// [gc] scrub_bytes_per_sec. With scrub_interval_secs at 0 it returns at once.
//
// Content that fails its check is marked damaged and logged as an error.
// Dedup stops reusing the chunks of a damaged xorb, so new uploads do not
// take on its damage, and compaction rewrites it from sound copies of its
// chunks where other xorbs hold them; reads already fall back to those copies
// (see Open). A whole-file blob is repaired by uploading its content again.
//
// It runs apart from RunGC, because a pass can take as long as reading a
// whole-file blob of several terabytes at the scrub rate, and reclamation
// must not wait on that.
func (s *Store) RunScrub(ctx context.Context) {
	if s.gc.ScrubIntervalSecs <= 0 {
		return
	}
	idle := time.Duration(s.gc.IntervalSecs) * time.Second
	if idle < minGCInterval {
		idle = minGCInterval
	}
	p := &pacer{rate: s.gc.ScrubBytesPerSec}
	for {
		if s.scrubPass(ctx, p) > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(idle):
		}
	}
}

// scrubPass checks one batch of content that is due, and returns how much it
// claimed.
func (s *Store) scrubPass(ctx context.Context, p *pacer) int {
	due, err := s.db.ClaimScrub(ctx, s.gc.ScrubIntervalSecs, scrubBatch)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("scrub could not claim content", "err", err)
		}
		return 0
	}
	for i, t := range due {
		if ctx.Err() != nil {
			for _, t := range due[i:] {
				s.requeueScrub(ctx, t)
			}
			break
		}
		s.scrub(ctx, p, t)
	}
	return len(due)
}

// errGone is content a check found missing from the backend.
var errGone = errors.New("not in the backend")

// scrub checks one piece of content and records how it went.
func (s *Store) scrub(ctx context.Context, p *pacer, t db.ScrubTarget) {
	var (
		why string
		err error
	)
	if t.Xorb {
		why, err = s.checkXorb(ctx, p, t)
	} else {
		why, err = s.checkWholeBlob(ctx, p, t)
	}
	if errors.Is(err, errGone) {
		live, lerr := s.db.ContentLive(ctx, t)
		switch {
		case lerr != nil:
			err = lerr
		case !live:
			// Collected while it was being checked: nothing to record.
			return
		default:
			why, err = "missing from the backend", nil
		}
	}
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("scrub could not check content", "hash", t.Hash, "xorb", t.Xorb, "err", err)
		}
		s.requeueScrub(ctx, t)
		return
	}

	if why != "" {
		s.log.Error("stored content failed its scrub", "hash", t.Hash, "xorb", t.Xorb, "why", why)
	}
	if err := s.db.RecordScrub(context.WithoutCancel(ctx), t, why == ""); err != nil {
		s.log.Warn("scrub could not record a check", "hash", t.Hash, "err", err)
		return
	}
	if why != "" {
		if dmg, err := s.db.CountDamage(ctx); err == nil {
			s.log.Error("stored content is damaged", "xorbs", dmg.Xorbs, "blobs", dmg.Blobs, "objects", dmg.Objects)
		}
	}
}

func (s *Store) requeueScrub(ctx context.Context, t db.ScrubTarget) {
	if err := s.db.RequeueScrub(context.WithoutCancel(ctx), t); err != nil {
		s.log.Warn("scrub could not give back a claim", "hash", t.Hash, "err", err)
	}
}

// checkXorb reads a xorb whole and checks everything its rows say about it:
// its size, that its chunks sit end to end from the start, that each decodes
// to its size and matches its hash, and that those hashes are the ones the
// xorb is named by. why says what is wrong, or is "" if nothing is; err is a
// check that could not be made.
func (s *Store) checkXorb(ctx context.Context, p *pacer, t db.ScrubTarget) (why string, err error) {
	chunks, err := s.db.XorbChunks(ctx, t.Hash, 0, maxXorbChunks)
	if err != nil {
		return "", err
	}
	if err := p.wait(ctx, t.Size); err != nil {
		return "", err
	}
	b, err := s.blob.ReadAll(ctx, storage.XorbPath(t.Hash))
	if gcerrors.Code(err) == gcerrors.NotFound {
		return "", errGone
	}
	if err != nil {
		return "", err
	}
	if int64(len(b)) != t.Size {
		return fmt.Sprintf("%d bytes stored, want %d", len(b), t.Size), nil
	}

	var (
		at    int64
		bad   int
		first string
		nodes = make([]hashedSize, len(chunks))
	)
	for i, c := range chunks {
		if c.Offset != at || c.Offset+int64(c.Length) > int64(len(b)) {
			return fmt.Sprintf("chunk %d is recorded at %d+%d, want it at %d", i, c.Offset, c.Length, at), nil
		}
		_, why, err := s.verifyChunk(ctx, b[c.Offset:c.Offset+int64(c.Length)], c)
		if err != nil {
			return "", err
		}
		if why != "" {
			if bad == 0 {
				first = fmt.Sprintf("chunk %d at %d: %s", i, c.Offset, why)
			}
			bad++
		}
		at += int64(c.Length)
		sum, err := parseXetHex(c.Hash)
		if err != nil {
			return fmt.Sprintf("chunk %d: %v", i, err), nil
		}
		nodes[i] = hashedSize{hash: sum, size: uint64(c.Size)}
	}
	if bad > 0 {
		return fmt.Sprintf("%d of %d chunks are unsound, first %s", bad, len(chunks), first), nil
	}
	if at != int64(len(b)) {
		return fmt.Sprintf("chunks end at %d of %d bytes", at, len(b)), nil
	}
	if len(chunks) == 0 || xetHex(xorbHash(nodes)) != t.Hash {
		return "its chunks do not hash to its name", nil
	}
	return "", nil
}

// checkWholeBlob reads a blob stored whole before chunking and checks its
// size and BLAKE3 digest, which is its name.
func (s *Store) checkWholeBlob(ctx context.Context, p *pacer, t db.ScrubTarget) (why string, err error) {
	r, err := s.blob.NewReader(ctx, storage.BlobPath(t.Hash), nil)
	if gcerrors.Code(err) == gcerrors.NotFound {
		return "", errGone
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()

	h := blake3.New()
	n, err := io.Copy(h, &pacedReader{ctx: ctx, r: r, p: p})
	if err != nil {
		return "", err
	}
	if n != t.Size {
		return fmt.Sprintf("%d bytes stored, want %d", n, t.Size), nil
	}
	if hex.EncodeToString(h.Sum(nil)) != t.Hash {
		return "content does not match its hash", nil
	}
	return "", nil
}

// pacer holds reads to a rate in bytes per second. A read of n bytes may
// start once the reads before it have had their time, so the rate holds over
// any stretch, and time spent idle earns no burst.
type pacer struct {
	rate int64 // 0 or less: unpaced
	next time.Time
}

// wait blocks until n more bytes may be read.
func (p *pacer) wait(ctx context.Context, n int64) error {
	if p.rate <= 0 {
		return nil
	}
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	start := p.next
	p.next = p.next.Add(time.Duration(float64(n) / float64(p.rate) * float64(time.Second)))
	if d := time.Until(start); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return nil
}

// pacedReader is a reader held to a pacer's rate.
type pacedReader struct {
	ctx context.Context
	r   io.Reader
	p   *pacer
}

// pacedBlock caps one read, so the pace is kept at a fine grain.
const pacedBlock = 1 << 20

func (r *pacedReader) Read(b []byte) (int, error) {
	if len(b) > pacedBlock {
		b = b[:pacedBlock]
	}
	if err := r.p.wait(r.ctx, int64(len(b))); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
