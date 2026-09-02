// Package cas is the content-addressed write path shared by the S3 gateway's
// single PUT, multipart completion, and the admin API.
//
// The upload protocol is written to be safe with N stateless servers and a
// concurrent garbage collector:
//
//  1. Stream the body to staging/<uuid> while feeding a blake3 hasher.
//  2. In one Postgres transaction, claim a blob reference (which row-locks the
//     blob: refcount++ or insert at 1). If the row is new, copy staging into
//     blobs/… *before* the commit, so a committed row always has bytes behind it.
//  3. Point the object row at the blob, releasing any blob it overwrote, and commit.
//  4. Delete the staging file. Best-effort — stale staging is swept later.
//
// A dedup hit therefore costs one staging write plus one delete. Simple beats
// clever here: hashing before writing would need either full buffering or a
// second client round trip.
package cas

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/zeebo/blake3"
	"gocloud.dev/gcerrors"

	"github.com/ggoggam/simplecas/internal/apperr"
	"github.com/ggoggam/simplecas/internal/config"
	"github.com/ggoggam/simplecas/internal/db"
	"github.com/ggoggam/simplecas/internal/storage"
)

// Store performs content-addressed writes against the metadata store and the
// blob backend together.
type Store struct {
	db   *db.DB
	blob *storage.Bucket
	gc   config.GcConfig
	log  *slog.Logger
}

// New returns a Store over the given database and blob backend.
func New(database *db.DB, bucket *storage.Bucket, gc config.GcConfig, log *slog.Logger) *Store {
	return &Store{db: database, blob: bucket, gc: gc, log: log}
}

// StagedBlob is an upload buffered in staging, with the hash and size measured
// while it streamed past.
type StagedBlob struct {
	StagingKey string
	Hash       string
	Size       int64
}

// taggedReader remembers whether a failure came from the source, so a client
// that hangs up mid-body is reported as a bad request rather than a server
// fault. io.Copy alone cannot tell the two apart.
type taggedReader struct {
	r   io.Reader
	err error
}

func (t *taggedReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

// Stage streams r into a fresh staging file, hashing as it goes. The staging
// file is removed if anything fails, so a failed upload leaves nothing behind.
func (s *Store) Stage(ctx context.Context, r io.Reader) (StagedBlob, error) {
	key := storage.StagingPath(uuid.NewString())

	w, err := s.blob.NewWriter(ctx, key, nil)
	if err != nil {
		return StagedBlob{}, apperr.Internal(err)
	}

	src := &taggedReader{r: r}
	hasher := blake3.New()
	size, copyErr := io.Copy(io.MultiWriter(w, hasher), src)

	// Close finalises the write (and, on object stores, completes the upload),
	// so its error matters as much as the copy's.
	closeErr := w.Close()

	switch {
	case src.err != nil:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.InvalidArgument("body read: %v", src.err)
	case copyErr != nil:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.Internalf("stage upload: %w", copyErr)
	case closeErr != nil:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.Internalf("finalise staged upload: %w", closeErr)
	}

	return StagedBlob{
		StagingKey: key,
		Hash:       hex.EncodeToString(hasher.Sum(nil)),
		Size:       size,
	}, nil
}

// Commit publishes a staged blob as namespace/key and returns the blob hash,
// which is the object's ETag.
func (s *Store) Commit(ctx context.Context, namespaceID int64, key, contentType string, staged StagedBlob) (string, error) {
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		isNew, err := db.ClaimBlob(ctx, tx, staged.Hash, staged.Size)
		if err != nil {
			return err
		}
		if isNew {
			// The bytes have to land before the commit: a committed blob row
			// with no bytes behind it would be handed out to readers.
			if err := s.blob.Copy(ctx, storage.BlobPath(staged.Hash), staged.StagingKey, nil); err != nil {
				return apperr.Internalf("promote staged blob: %w", err)
			}
		}
		return db.UpsertObject(ctx, tx, namespaceID, key, staged.Hash, staged.Size, contentType)
	})
	if err != nil {
		// Leave the staging file for the sweeper: on a lost race it may be the
		// only copy of bytes a retry can reuse.
		return "", err
	}

	s.DiscardStaging(ctx, staged.StagingKey)
	return staged.Hash, nil
}

// CopyObject implements copy semantics under content addressing: no bytes move,
// the destination simply claims another reference to the source blob.
func (s *Store) CopyObject(ctx context.Context, src db.ObjectMeta, dstNamespaceID int64, dstKey string) (string, error) {
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		isNew, err := db.ClaimBlob(ctx, tx, src.BlobHash, src.Size)
		if err != nil {
			return err
		}
		if isNew {
			// The blob row vanished between reading the source object and
			// claiming it — GC won the race after the source was deleted.
			// Without bytes there is nothing to copy.
			return apperr.ErrNoSuchKey
		}
		return db.UpsertObject(ctx, tx, dstNamespaceID, dstKey, src.BlobHash, src.Size, src.ContentType)
	})
	if err != nil {
		return "", err
	}
	return src.BlobHash, nil
}

// LinkBlob points key at content that is already stored, transferring no bytes.
// It reports linked=false when the blob is not present — or not visible to this
// tenant — so the caller can fall back to a real upload. This is what turns a
// client-side hash match into a zero-byte upload.
//
// tenantScope bounds visibility: when non-nil, the link succeeds only if the
// blob is already referenced inside that tenant, so the endpoint cannot be used
// to confirm the existence of another tenant's content. A nil scope links
// against any stored blob, which is correct only for a superuser caller or an
// unowned namespace — pass the namespace's own TenantID and it is always right.
func (s *Store) LinkBlob(ctx context.Context, namespaceID int64, key, hash, contentType string, tenantScope *int64) (size int64, linked bool, err error) {
	err = s.db.InTx(ctx, func(tx pgx.Tx) error {
		if tenantScope != nil {
			visible, err := db.BlobReferencedInTenant(ctx, tx, hash, *tenantScope)
			if err != nil {
				return err
			}
			if !visible {
				return nil
			}
		}

		stored, ok, err := db.ClaimExistingBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}

		size, linked = stored, true
		return db.UpsertObject(ctx, tx, namespaceID, key, hash, stored, contentType)
	})
	if err != nil {
		return 0, false, err
	}
	return size, linked, nil
}

// CompleteMultipart concatenates the parts into one staged blob, hashing the
// whole so the finished object dedups like any other upload, commits it, and
// then drops the parts.
func (s *Store) CompleteMultipart(ctx context.Context, upload db.MultipartUpload, parts []db.PartMeta) (string, error) {
	staged, err := s.stageParts(ctx, parts)
	if err != nil {
		return "", err
	}

	etag, err := s.Commit(ctx, upload.NamespaceID, upload.Key, upload.ContentType, staged)
	if err != nil {
		return "", err
	}

	keys, err := s.db.RemoveMultipart(ctx, upload.ID)
	if err != nil {
		// The object is committed; failing to tidy the parts is not worth
		// failing the request over, and the expiry sweep will catch them.
		s.log.Warn("could not remove multipart rows after completion",
			"upload", upload.ID, "err", err)
		return etag, nil
	}
	for _, key := range keys {
		s.DiscardStaging(ctx, key)
	}
	return etag, nil
}

// stageParts streams every part into a single staging file, hashing the
// concatenation.
func (s *Store) stageParts(ctx context.Context, parts []db.PartMeta) (StagedBlob, error) {
	key := storage.StagingPath(uuid.NewString())

	w, err := s.blob.NewWriter(ctx, key, nil)
	if err != nil {
		return StagedBlob{}, apperr.Internal(err)
	}

	hasher := blake3.New()
	sink := io.MultiWriter(w, hasher)
	var size int64

	for _, part := range parts {
		r, err := s.blob.NewReader(ctx, part.StagingKey, nil)
		if err != nil {
			_ = w.Close()
			s.DiscardStaging(ctx, key)
			return StagedBlob{}, apperr.Internalf("open part %d: %w", part.PartNumber, err)
		}
		n, copyErr := io.Copy(sink, r)
		closeErr := r.Close()
		size += n
		if copyErr != nil || closeErr != nil {
			_ = w.Close()
			s.DiscardStaging(ctx, key)
			if copyErr == nil {
				copyErr = closeErr
			}
			return StagedBlob{}, apperr.Internalf("read part %d: %w", part.PartNumber, copyErr)
		}
	}

	if err := w.Close(); err != nil {
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.Internalf("finalise assembled upload: %w", err)
	}

	return StagedBlob{
		StagingKey: key,
		Hash:       hex.EncodeToString(hasher.Sum(nil)),
		Size:       size,
	}, nil
}

// DiscardStaging removes a staging file. Failures are logged and swallowed: the
// object is already durable by the time this runs, and the staging sweeper is
// the backstop for anything left behind.
func (s *Store) DiscardStaging(ctx context.Context, key string) {
	if err := s.deleteIfPresent(ctx, key); err != nil {
		s.log.Warn("could not delete staging file", "key", key, "err", err)
	}
}

// deleteIfPresent deletes key, treating an already-absent key as success.
// Deletion has to be idempotent: both the GC sweep and the staging sweep can
// legitimately race another instance to the same key.
func (s *Store) deleteIfPresent(ctx context.Context, key string) error {
	err := s.blob.Delete(ctx, key)
	if err != nil && gcerrors.Code(err) != gcerrors.NotFound {
		return err
	}
	return nil
}

// ManifestPart is one entry of a client's "these are the parts to assemble"
// manifest, in whichever wire format it arrived in.
type ManifestPart struct {
	PartNumber int32
	// ETag, when non-nil, is checked against the staged part's digest.
	ETag *string
}

// ResolveManifest validates a completion manifest against what was actually
// staged and returns the parts in assembly order.
//
// Part numbers must ascend strictly: they define the byte order of the finished
// object, so an out-of-order or duplicated manifest has no single meaning.
// Both the S3 gateway and the admin API funnel through here so their two wire
// formats cannot drift apart in what they accept.
func ResolveManifest(requested []ManifestPart, stored []db.PartMeta) ([]db.PartMeta, error) {
	if len(requested) == 0 {
		return nil, apperr.InvalidPart("no parts in request")
	}

	byNumber := make(map[int32]db.PartMeta, len(stored))
	for _, p := range stored {
		byNumber[p.PartNumber] = p
	}

	ordered := make([]db.PartMeta, 0, len(requested))
	var last int32
	for _, want := range requested {
		if want.PartNumber <= last {
			return nil, apperr.InvalidPart("part numbers must be ascending")
		}
		last = want.PartNumber

		part, ok := byNumber[want.PartNumber]
		if !ok {
			return nil, apperr.InvalidPart("part %d not uploaded", want.PartNumber)
		}
		if want.ETag != nil && strings.Trim(*want.ETag, `"`) != part.ETag {
			return nil, apperr.InvalidPart("etag mismatch on part %d", want.PartNumber)
		}
		ordered = append(ordered, part)
	}
	return ordered, nil
}
