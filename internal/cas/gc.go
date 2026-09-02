package cas

import (
	"context"
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

// RunGC reclaims space until ctx is cancelled: unreferenced blobs, orphaned
// staging files, and abandoned multipart uploads. Every pass is best-effort —
// a failure is logged and retried on the next tick rather than ending the loop,
// because a transient database or backend blip must not silently stop
// reclamation for the lifetime of the process.
func (s *Store) RunGC(ctx context.Context) {
	interval := time.Duration(s.gc.IntervalSecs) * time.Second
	if interval < minGCInterval {
		interval = minGCInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// Sleep first, matching the previous behaviour: startup is busy
		// enough without a sweep racing the first requests.
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		s.sweepBlobs(ctx)
		s.sweepStaging(ctx)
		s.sweepMultipart(ctx)
	}
}

// sweepBlobs deletes the bytes and rows of blobs that have stayed unreferenced
// past the grace period.
func (s *Store) sweepBlobs(ctx context.Context) {
	swept, err := s.db.GCSweep(ctx, s.gc.GraceSecs, gcBatch, func(ctx context.Context, hash string) error {
		return s.deleteIfPresent(ctx, storage.BlobPath(hash))
	})
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("gc sweep failed", "err", err)
		}
		return
	}
	if swept > 0 {
		s.log.Info("gc: removed unreferenced blobs", "swept", swept)
	}
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

		modified := obj.ModTime
		if modified.IsZero() {
			// Backends that omit timestamps from listings get a stat. If even
			// that has none, skip: never delete on an unknown age.
			attrs, err := s.blob.Attributes(ctx, obj.Key)
			if err != nil {
				continue
			}
			modified = attrs.ModTime
		}
		if modified.IsZero() || modified.After(cutoff) {
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
