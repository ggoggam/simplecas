package cas

import (
	"context"
	"crypto/md5"
	"errors"
	"io"
	"time"

	"gocloud.dev/blob"

	"github.com/ggoggam/simplecas/internal/storage"
)

// gcBatch caps how many blobs one sweep collects, so a large backlog is worked
// through over several passes instead of holding locks for a long time.
const gcBatch = 1000

// minGCInterval floors the configured interval; a tighter loop would spend more
// time querying than reclaiming.
const minGCInterval = 5 * time.Second

// orphanPage is how many listed blobs the orphan sweep checks against the
// blobs table in one query.
const orphanPage = 1000

// etagBatch caps how many blobs one ETag backfill pass reads, so a large
// store stored before ETags were recorded is worked through over many ticks.
const etagBatch = 16

// RunGC reclaims space until ctx is cancelled: unreferenced blobs and xorbs,
// orphaned staging files, abandoned multipart uploads, and expired sign-in
// sessions on every tick, and stored bytes no row accounts for every orphan
// interval.
// Each tick also records ETags for some objects stored before they were.
// Every pass is best-effort — a failure is logged and retried on the next tick
// rather than ending the loop, because a transient database or backend blip
// must not silently stop reclamation for the lifetime of the process.
func (s *Store) RunGC(ctx context.Context) {
	interval := time.Duration(s.gc.IntervalSecs) * time.Second
	if interval < minGCInterval {
		interval = minGCInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	orphanInterval := time.Duration(s.gc.OrphanIntervalSecs) * time.Second
	var lastOrphanSweep time.Time

	for {
		// Sleep first, matching the previous behaviour: startup is busy
		// enough without a sweep racing the first requests.
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Blobs first: collecting one drops its xorbs' references, and the
		// xorb sweep then finds those that reached zero on the same tick
		// once their grace period is up.
		s.sweepBlobs(ctx)
		s.sweepXorbs(ctx)
		s.sweepStaging(ctx)
		s.sweepMultipart(ctx)
		s.sweepSessions(ctx)
		s.backfillETags(ctx)
		if time.Since(lastOrphanSweep) >= orphanInterval {
			s.sweepOrphanBlobs(ctx)
			s.sweepOrphanXorbs(ctx)
			lastOrphanSweep = time.Now()
		}
	}
}

// sweepBlobs deletes the rows of blobs that have stayed unreferenced past the
// grace period, with the bytes of those stored whole before chunking.
func (s *Store) sweepBlobs(ctx context.Context) {
	swept, err := s.db.GCSweep(ctx, s.gc.GraceSecs, gcBatch, func(ctx context.Context, hash string) error {
		return s.deleteIfPresent(ctx, storage.BlobPath(hash))
	})
	// A failure on some blobs does not stop the sweep reclaiming the others,
	// so the count is reported either way.
	if err != nil && ctx.Err() == nil {
		s.log.Warn("gc sweep failed", "swept", swept, "err", err)
	}
	if swept > 0 {
		s.log.Info("gc: removed unreferenced blobs", "swept", swept)
	}
}

// sweepXorbs deletes the bytes and rows of xorbs no blob has used for the
// grace period.
func (s *Store) sweepXorbs(ctx context.Context) {
	swept, err := s.db.GCSweepXorbs(ctx, s.gc.GraceSecs, gcBatch, func(ctx context.Context, hash string) error {
		return s.deleteIfPresent(ctx, storage.XorbPath(hash))
	})
	if err != nil && ctx.Err() == nil {
		s.log.Warn("xorb gc sweep failed", "swept", swept, "err", err)
	}
	if swept > 0 {
		s.log.Info("gc: removed unreferenced xorbs", "swept", swept)
	}
}

// backfillETags gives objects stored before ETags were recorded their MD5
// ETag, reading each blob whose MD5 is not known yet. Until then such an
// object is served with its BLAKE3 digest, which global dedup makes worth
// hiding (see the package comment).
func (s *Store) backfillETags(ctx context.Context) {
	pending, err := s.db.ETagsToBackfill(ctx, etagBatch)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("etag backfill failed", "err", err)
		}
		return
	}

	var filled int
	for _, p := range pending {
		sum := p.MD5
		if sum == "" {
			if sum, err = s.blobMD5(ctx, p.Hash, p.Size); err != nil {
				if ctx.Err() == nil {
					s.log.Warn("etag backfill could not read blob", "hash", p.Hash, "err", err)
				}
				continue
			}
		}
		if err := s.db.RecordBlobMD5(ctx, p.Hash, sum); err != nil {
			if ctx.Err() == nil {
				s.log.Warn("etag backfill could not record md5", "hash", p.Hash, "err", err)
			}
			continue
		}
		filled++
	}

	if filled > 0 {
		s.log.Info("gc: recorded etags for blobs stored before them", "blobs", filled)
	}
}

// blobMD5 reads a stored blob and returns its hex MD5.
func (s *Store) blobMD5(ctx context.Context, hash string, size int64) (string, error) {
	r, err := s.Open(ctx, hash, 0, size)
	if err != nil {
		return "", err
	}
	defer func() { _ = r.Close() }()
	h := md5.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hexSum(h), nil
}

// sweepStaging deletes staging files older than the grace period that no live
// multipart part still references.
//
// The part check is what makes a slow multi-hour multipart upload safe: its
// staged parts are older than the grace period long before it completes, and
// only the multipart expiry sweep may reclaim them.
func (s *Store) sweepStaging(ctx context.Context) {
	cutoff := time.Now().Add(-time.Duration(s.gc.GraceSecs) * time.Second)

	var removed int
	it := s.blob.List(&blob.ListOptions{Prefix: storage.StagingPrefix})
	for {
		obj, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("staging sweep failed", "err", err)
			}
			return
		}
		if obj.IsDir {
			continue
		}

		if !s.olderThan(ctx, obj, cutoff) {
			continue
		}

		referenced, err := s.db.StagingKeyReferenced(ctx, obj.Key)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("staging sweep could not check part references", "key", obj.Key, "err", err)
			}
			return
		}
		if referenced {
			continue
		}

		if err := s.deleteIfPresent(ctx, obj.Key); err != nil {
			s.log.Warn("could not delete stale staging file", "key", obj.Key, "err", err)
			continue
		}
		removed++
	}

	if removed > 0 {
		s.log.Info("gc: removed stale staging files", "removed", removed)
	}
}

// sweepMultipart abandons inactive multipart uploads and frees their parts.
func (s *Store) sweepMultipart(ctx context.Context) {
	swept, err := s.db.SweepMultipart(ctx, s.gc.MultipartExpirySecs)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("multipart sweep failed", "err", err)
		}
		return
	}
	if swept.Uploads == 0 {
		return
	}

	for _, key := range swept.StagingKeys {
		s.DiscardStaging(ctx, key)
	}
	s.log.Info("gc: removed abandoned multipart uploads",
		"uploads", swept.Uploads, "parts", len(swept.StagingKeys))
}

// sweepSessions deletes expired sign-in sessions. Revoking a session deletes
// its row there and then, so expired ones are all that is left to clear. With
// OIDC off there are none, and this is one empty index scan.
func (s *Store) sweepSessions(ctx context.Context) {
	swept, err := s.db.SweepSessions(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("session sweep failed", "err", err)
		}
		return
	}
	if swept > 0 {
		s.log.Info("gc: removed expired sessions", "swept", swept)
	}
}

// sweepOrphanBlobs deletes stored blobs that no blob row accounts for and that
// are older than the grace period. A commit that copied its bytes into place
// and then failed to commit — a quota refusal, a lost connection, a crash —
// leaves exactly that behind, and GCSweep, which works from the rows, can
// never find them.
//
// The listing is checked against the table a page at a time, so the cost is
// one query per page; only blobs with no row go on to ReclaimOrphanBlob, which
// decides under the same lock a commit takes. The grace period is not what
// keeps an in-flight commit safe — that lock is — but it spares the lock for
// the fresh bytes of commits that are bound to succeed.
func (s *Store) sweepOrphanBlobs(ctx context.Context) {
	s.sweepOrphans(ctx, orphanKind{
		what:    "blob",
		prefix:  storage.BlobPrefix,
		parse:   storage.HashFromBlobPath,
		path:    storage.BlobPath,
		unknown: s.db.UnknownBlobs,
		reclaim: s.db.ReclaimOrphanBlob,
	})
}

// sweepOrphanXorbs is sweepOrphanBlobs for xorbs, which a failed commit
// leaves behind the same way.
func (s *Store) sweepOrphanXorbs(ctx context.Context) {
	s.sweepOrphans(ctx, orphanKind{
		what:    "xorb",
		prefix:  storage.XorbPrefix,
		parse:   storage.HashFromXorbPath,
		path:    storage.XorbPath,
		unknown: s.db.UnknownXorbs,
		reclaim: s.db.ReclaimOrphanXorb,
	})
}

// orphanKind is what sweepOrphans needs to know about one kind of stored
// content: where it lives, and how its rows are checked and claimed.
type orphanKind struct {
	what    string
	prefix  string
	parse   func(key string) (string, bool)
	path    func(hash string) string
	unknown func(ctx context.Context, hashes []string) ([]string, error)
	reclaim func(ctx context.Context, hash string, deleteBytes func(ctx context.Context, hash string) error) (bool, error)
}

func (s *Store) sweepOrphans(ctx context.Context, kind orphanKind) {
	cutoff := time.Now().Add(-time.Duration(s.gc.GraceSecs) * time.Second)

	var removed int
	page := make([]string, 0, orphanPage)
	it := s.blob.List(&blob.ListOptions{Prefix: kind.prefix})
	for {
		obj, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() == nil {
				s.log.Warn("orphan sweep failed", "kind", kind.what, "err", err)
			}
			return
		}
		if obj.IsDir {
			continue
		}
		hash, ok := kind.parse(obj.Key)
		if !ok || !s.olderThan(ctx, obj, cutoff) {
			continue
		}

		page = append(page, hash)
		if len(page) < orphanPage {
			continue
		}
		n, ok := s.reclaimOrphans(ctx, kind, page)
		removed += n
		if !ok {
			return
		}
		page = page[:0]
	}
	if len(page) > 0 {
		n, _ := s.reclaimOrphans(ctx, kind, page)
		removed += n
	}

	if removed > 0 {
		s.log.Info("gc: removed orphaned "+kind.what+"s", "removed", removed)
	}
}

// reclaimOrphans deletes those of hashes that have no row. ok is false when
// the table could not be consulted at all, which ends the pass.
func (s *Store) reclaimOrphans(ctx context.Context, kind orphanKind, hashes []string) (removed int, ok bool) {
	unknown, err := kind.unknown(ctx, hashes)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("orphan sweep could not check rows", "kind", kind.what, "err", err)
		}
		return 0, false
	}
	for _, hash := range unknown {
		reclaimed, err := kind.reclaim(ctx, hash, func(ctx context.Context, hash string) error {
			return s.deleteIfPresent(ctx, kind.path(hash))
		})
		if err != nil {
			if ctx.Err() != nil {
				return removed, false
			}
			s.log.Warn("could not delete orphaned bytes", "kind", kind.what, "hash", hash, "err", err)
			continue
		}
		if reclaimed {
			removed++
		}
	}
	return removed, true
}

// olderThan reports whether a listed file was last modified before cutoff.
// Backends that omit timestamps from listings get a stat; if even that has
// none, the answer is no, because nothing is ever deleted on an unknown age.
func (s *Store) olderThan(ctx context.Context, obj *blob.ListObject, cutoff time.Time) bool {
	modified := obj.ModTime
	if modified.IsZero() {
		attrs, err := s.blob.Attributes(ctx, obj.Key)
		if err != nil {
			return false
		}
		modified = attrs.ModTime
	}
	return !modified.IsZero() && modified.Before(cutoff)
}
