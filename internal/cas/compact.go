package cas

import (
	"context"
	"errors"
	"fmt"

	"gocloud.dev/gcerrors"

	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// compactLooks caps how many xorbs one GC tick looks at for compaction. A
// look is a query or two; most xorbs it finds are still dense enough to keep.
const compactLooks = 64

// compactBatch caps how many xorbs one GC tick rewrites. Each costs a read of
// up to a xorb's worth of bytes and a write of under half that.
const compactBatch = 8

// errNoSoundCopy is a damaged live chunk with no sound copy to rewrite the
// xorb from. Retrying soon would find none either; the next scrub of the xorb
// marks it for another try.
var errNoSoundCopy = errors.New("damaged chunk has no sound copy")

// compactXorbs rewrites xorbs that have become mostly dead chunks, and
// damaged xorbs whose damage it can leave behind (see compactXorb). Only
// xorbs that lost a blob at least a grace period ago are looked at.
func (s *Store) compactXorbs(ctx context.Context) {
	if s.gc.CompactBelowPercent <= 0 {
		return
	}
	hashes, err := s.db.ClaimCompaction(ctx, s.gc.GraceSecs, compactLooks)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("compaction could not claim xorbs", "err", err)
		}
		return
	}

	var (
		compacted int
		freed     int64
	)
	requeue := func(hash string) {
		if err := s.db.RequeueCompaction(context.WithoutCancel(ctx), hash); err != nil {
			s.log.Warn("could not requeue xorb for compaction", "xorb", hash, "err", err)
		}
	}
	for i, hash := range hashes {
		if compacted == compactBatch || ctx.Err() != nil {
			// Enough rewriting for one tick; the rest wait for the next.
			for _, hash := range hashes[i:] {
				requeue(hash)
			}
			break
		}
		n, err := s.compactXorb(ctx, hash)
		switch {
		case errors.Is(err, errNoSoundCopy):
			s.log.Warn("damaged xorb cannot be repaired by compaction; left as it is", "xorb", hash, "err", err)
			continue
		case err != nil:
			if ctx.Err() == nil && !isStale(err) {
				s.log.Warn("could not compact xorb", "xorb", hash, "err", err)
			}
			requeue(hash)
			continue
		}
		if n >= 0 {
			compacted++
			freed += n
		}
	}
	if compacted > 0 {
		s.log.Info("gc: compacted xorbs", "xorbs", compacted, "freed_bytes", freed)
	}
}

// compactXorb rewrites the xorb hash with only the chunks some blob still
// uses, and moves every term onto the new xorb. It reports how many stored
// bytes that frees once the old xorb is collected, or -1 when it leaves the
// xorb as it is.
//
// A xorb is rewritten when its live chunks take up less than
// [gc] compact_below_percent of its bytes. A damaged one is rewritten
// whenever some of its chunks are dead, since dropping them may drop the
// damage: each live chunk is checked as it is copied, and one that fails is
// taken from a sound copy in another xorb instead. A damaged xorb with no
// dead chunks would be rewritten as itself, and is left; reads of it fall
// back to other copies of its chunks where there are any.
//
// Stored bytes are copied as they are, header and all, so nothing is
// recompressed. The new xorb is written before the terms move, as a commit
// writes its xorbs before claiming them, and a failure after the write
// leaves it for the orphan sweep.
func (s *Store) compactXorb(ctx context.Context, hash string) (freed int64, err error) {
	use, ok, err := s.db.XorbUse(ctx, hash)
	if err != nil || !ok {
		return -1, err
	}
	live := use.LiveBytes()
	allLive := live > 0
	for _, l := range use.Live {
		allLive = allLive && l
	}
	switch {
	case live == 0:
		// Referenced, yet no term uses it: the refcount has drifted, and
		// the xorb sweep, which checks the terms, will not take it either.
		return -1, nil
	case allLive:
		if use.Damaged {
			s.log.Warn("damaged xorb has no dead chunks to drop, so compaction cannot rewrite it", "xorb", hash)
		}
		return -1, nil
	case !use.Damaged && live*100 >= use.Size*s.gc.CompactBelowPercent:
		return -1, nil
	}

	// Read whole: a candidate is mostly dead chunks, but one request for
	// all of it costs less than one per live run. If it cannot be read,
	// every chunk is taken from elsewhere or the compaction fails.
	stored, err := s.blob.ReadAll(ctx, storage.XorbPath(hash))
	if err != nil && gcerrors.Code(err) != gcerrors.NotFound {
		return -1, fmt.Errorf("read xorb: %w", err)
	}

	var (
		buf       []byte
		chunks    []db.XorbChunk
		nodes     []hashedSize
		repaired  int
		index     = make([]int32, len(use.Chunks))
		elsewhere map[string][]db.ChunkLocation
	)
	for i, c := range use.Chunks {
		index[i] = -1
		if !use.Live[i] {
			continue
		}
		start := int64(len(buf))
		end := c.Offset + int64(c.Length)
		var why string
		if end > int64(len(stored)) {
			why = "past the end of the stored bytes"
		} else if _, why = verifyChunk(stored[c.Offset:end], c); why == "" {
			buf = append(buf, stored[c.Offset:end]...)
		}
		if why != "" {
			if elsewhere == nil {
				if elsewhere, err = s.locateLive(ctx, use); err != nil {
					return -1, err
				}
			}
			raw, ok := s.soundCopy(ctx, c, elsewhere[c.Hash], hash)
			if !ok {
				return -1, fmt.Errorf("%w: chunk %d, %s", errNoSoundCopy, i, why)
			}
			buf = appendChunk(buf, raw)
			repaired++
		}
		sum, err := parseXetHex(c.Hash)
		if err != nil {
			return -1, err
		}
		nodes = append(nodes, hashedSize{hash: sum, size: uint64(c.Size)})
		index[i] = int32(len(chunks))
		chunks = append(chunks, db.XorbChunk{Hash: c.Hash, Offset: start, Length: int32(int64(len(buf)) - start), Size: c.Size})
	}

	to := db.NewXorb{Hash: xetHex(xorbHash(nodes)), Size: int64(len(buf)), Chunks: chunks}
	if err := s.blob.PutOnce(ctx, storage.XorbPath(to.Hash), buf, true); err != nil {
		if !errors.Is(err, storage.ErrExists) {
			return -1, fmt.Errorf("write compacted xorb: %w", err)
		}
		to.Existed = true
	}
	moved, err := s.db.MoveTerms(ctx, hash, to, index, xorbBytes{s})
	if err != nil {
		return -1, err
	}
	if repaired > 0 {
		s.log.Info("repaired a damaged xorb from sound copies of its chunks",
			"xorb", hash, "into", to.Hash, "chunks", repaired)
	}
	s.log.Debug("compacted xorb", "xorb", hash, "into", to.Hash, "blobs", moved,
		"chunks", len(chunks), "of", len(use.Chunks))
	return use.Size - to.Size, nil
}

// locateLive finds where else the live chunks of a xorb are held.
func (s *Store) locateLive(ctx context.Context, use db.XorbUse) (map[string][]db.ChunkLocation, error) {
	var hashes []string
	for i, c := range use.Chunks {
		if use.Live[i] {
			hashes = append(hashes, c.Hash)
		}
	}
	return s.db.LocateChunks(ctx, hashes)
}
