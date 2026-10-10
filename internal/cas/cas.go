// Package cas is the content-addressed write path shared by the S3 gateway's
// single PUT, multipart completion, and the admin API.
//
// The upload protocol is written to be safe with N stateless servers and a
// concurrent garbage collector:
//
//  1. Stream the body to staging/<uuid> while feeding a blake3 hasher and the
//     chunker, which cuts the content into chunks as the Xet protocol does
//     (see chunker.go) and hashes each one. The S3 gateway's body reader
//     checks the client's own digests (payload hash, Content-MD5, checksums)
//     in the same pass and fails the read at the end of a body that does not
//     match them, which discards the staging file.
//  2. Plan the write as a Xet client would (see plan.go): reuse runs of
//     chunks stored xorbs already hold, and pack the rest into new xorbs.
//     Write the new xorbs from staging, each in one request, *before* the
//     transaction, so no row lock is held while bytes move.
//  3. In one Postgres transaction, claim a blob reference (which row-locks the
//     blob: refcount++ or insert at 1). A new blob row gets its terms, which
//     claim each xorb they use and check, under its row lock, that a xorb GC
//     might have taken is still there; a committed reference always has
//     bytes behind it. Point the object row at the blob, releasing any blob
//     it overwrote, and commit.
//  4. Delete the staging file. Best-effort — stale staging is swept later.
//
// Dedup is global, and works on two levels: identical content is one blob,
// and blobs that share runs of chunks share the xorbs that hold them. A dedup
// hit within a namespace costs one staging write plus one delete; a hit on
// content only another namespace holds costs as much as a new blob, so upload
// timing says nothing about other tenants' content. Simple beats clever here:
// hashing before writing would need either full buffering or a second client
// round trip.
//
// Content stored before chunking is one file under blobs/, and stays that
// way: it is read, copied and collected as before.
//
// Clients see MD5 ETags, as S3 serves them, never the BLAKE3 digest: that
// digest is the dedup key for every tenant's copy of some content.
package cas

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
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
	db     *db.DB
	blob   *storage.Bucket
	gc     config.GcConfig
	limits config.LimitsConfig
	log    *slog.Logger
}

// New returns a Store over the given database and blob backend.
func New(database *db.DB, bucket *storage.Bucket, gc config.GcConfig, limits config.LimitsConfig, log *slog.Logger) *Store {
	return &Store{db: database, blob: bucket, gc: gc, limits: limits, log: log}
}

// StagedBlob is an upload buffered in staging, with the hashes and size
// measured while it streamed past.
type StagedBlob struct {
	StagingKey string
	// Hash is the BLAKE3 digest the content is stored under.
	Hash string
	Size int64
	// MD5 is the hex MD5 of the content.
	MD5 string
	// ETag is what the content is served under once committed, unquoted: its
	// MD5, or for an assembled multipart upload the MD5 of its parts' MD5s
	// followed by "-" and the part count, as S3 computes it.
	ETag string
	// Chunks is the content cut into chunks, in order. A multipart part,
	// which is chunked only as part of the assembled object, has none.
	Chunks []db.ChunkRef
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

// Put stages body and commits it as namespace/key, returning the ETag and the
// stored size. declared is the size the client announced, or -1 when it
// announced none: a body declared over the size limit or the team's quota is
// refused before a byte of it is read.
func (s *Store) Put(ctx context.Context, namespaceID int64, key, contentType string, body io.Reader, declared int64) (etag string, size int64, err error) {
	if err := checkDeclared(declared, s.limits.MaxObjectBytes, "object"); err != nil {
		return "", 0, err
	}
	if declared > 0 {
		if err := s.checkQuota(ctx, db.QuotaCheck{NamespaceID: namespaceID, Bytes: declared, Key: key}); err != nil {
			return "", 0, err
		}
	}
	staged, err := s.Stage(ctx, body)
	if err != nil {
		return "", 0, err
	}
	etag, err = s.Commit(ctx, namespaceID, key, contentType, staged)
	if err != nil {
		return "", 0, err
	}
	return etag, staged.Size, nil
}

// PutPart stages body as one part of upload, replacing any earlier upload of
// the same part number. declared works as in Put, against the part size limit.
func (s *Store) PutPart(ctx context.Context, upload db.MultipartUpload, partNumber int32, body io.Reader, declared int64) (StagedBlob, error) {
	if err := checkDeclared(declared, s.limits.MaxPartBytes, "part"); err != nil {
		return StagedBlob{}, err
	}
	if declared > 0 {
		check := db.QuotaCheck{NamespaceID: upload.NamespaceID, Bytes: declared, Upload: upload.ID, PartNumber: partNumber}
		if err := s.checkQuota(ctx, check); err != nil {
			return StagedBlob{}, err
		}
	}
	staged, err := s.stage(ctx, body, s.limits.MaxPartBytes, "part", false)
	if err != nil {
		return StagedBlob{}, err
	}
	replaced, err := s.db.PutPart(ctx, upload.ID, partNumber,
		staged.StagingKey, staged.Size, staged.ETag, s.limits.TenantQuotaBytes)
	if err != nil {
		s.DiscardStaging(ctx, staged.StagingKey)
		return StagedBlob{}, err
	}
	if replaced != "" {
		s.DiscardStaging(ctx, replaced)
	}
	return staged, nil
}

// checkDeclared refuses a body whose announced size is already over limit.
func checkDeclared(declared, limit int64, what string) error {
	if declared > limit {
		return apperr.EntityTooLarge("%s of %d bytes exceeds the %d-byte limit", what, declared, limit)
	}
	return nil
}

// checkQuota is the unlocked early quota check (see db.CheckQuota).
func (s *Store) checkQuota(ctx context.Context, c db.QuotaCheck) error {
	if s.limits.TenantQuotaBytes <= 0 {
		return nil
	}
	return s.db.InTx(ctx, func(tx pgx.Tx) error {
		return db.CheckQuota(ctx, tx, s.limits.TenantQuotaBytes, c)
	})
}

// Stage streams r into a fresh staging file, hashing and chunking it as it
// goes. The staging file is removed if anything fails, so a failed upload
// leaves nothing behind. A body longer than the object size limit fails with
// EntityTooLarge.
func (s *Store) Stage(ctx context.Context, r io.Reader) (StagedBlob, error) {
	return s.stage(ctx, r, s.limits.MaxObjectBytes, "object", true)
}

func (s *Store) stage(ctx context.Context, r io.Reader, limit int64, what string, chunk bool) (StagedBlob, error) {
	key := storage.StagingPath(uuid.NewString())

	w, err := s.blob.NewWriter(ctx, key, nil)
	if err != nil {
		return StagedBlob{}, apperr.Internal(err)
	}

	// One byte past the limit is enough to know the body is too long, and
	// stops the copy there rather than staging the rest.
	src := &taggedReader{r: io.LimitReader(r, limit+1)}
	hasher, md5er := blake3.New(), md5.New()
	sinks := []io.Writer{w, hasher, md5er}
	var chunks *chunker
	if chunk {
		chunks = newChunker()
		sinks = append(sinks, chunks)
	}
	size, copyErr := io.Copy(io.MultiWriter(sinks...), src)

	// Close finalises the write (and, on object stores, completes the upload),
	// so its error matters as much as the copy's.
	closeErr := w.Close()

	switch {
	case src.err != nil && errors.As(src.err, new(*apperr.Error)):
		// The reader classified its own failure: a stored blob that could not
		// be read is the server's fault, not the client's, and a body that
		// failed its digest or signature check is refused as such.
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, src.err
	case src.err != nil && errors.Is(src.err, os.ErrDeadlineExceeded):
		// The router's stall timeout fired: the client stopped sending.
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.ErrRequestTimeout
	case src.err != nil:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.InvalidArgument("body read: %v", src.err)
	case size > limit:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.EntityTooLarge("%s exceeds the %d-byte limit", what, limit)
	case copyErr != nil:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.Internalf("stage upload: %w", copyErr)
	case closeErr != nil:
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.Internalf("finalise staged upload: %w", closeErr)
	}

	sum := hexSum(md5er)
	staged := StagedBlob{
		StagingKey: key,
		Hash:       hex.EncodeToString(hasher.Sum(nil)),
		Size:       size,
		MD5:        sum,
		ETag:       sum,
	}
	if chunks != nil {
		staged.Chunks = chunks.finish()
	}
	return staged, nil
}

// hexSum is h's digest in hex.
func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

// Commit publishes a staged blob as namespace/key and returns its ETag.
func (s *Store) Commit(ctx context.Context, namespaceID int64, key, contentType string, staged StagedBlob) (string, error) {
	return s.commit(ctx, namespaceID, key, contentType, staged, uuid.Nil)
}

// commit is Commit, with the parts of a multipart upload being completed left
// out of the quota check: they are dropped once the object is committed.
//
// The quota is checked twice. The first check, before anything is written,
// refuses an upload that is plainly over quota; a refusal after the write
// would roll back the rows and strand the bytes until the orphan sweep finds
// them. The second, after the object row is written, is the authoritative
// one under the team lock, and only loses bytes that way when two writers
// race past the first check together.
//
// The bytes are written whenever the namespace holds no other reference to
// them, not only when they are new. Dedup is global, so skipping the write
// for anything stored would make an upload of content another tenant holds
// measurably faster than one of new content, and that difference would tell
// anyone who can upload whether some other tenant stores a given file, or
// part of one. Content the namespace already holds is skipped, which tells
// the uploader nothing new; any other content a commit can reuse is written
// anyway, to a scratch object deleted once the commit is done (see plan).
//
// The plan is made outside the transaction and can go stale before the
// claim: a xorb it meant to reuse may be collected, or the blob may be
// created or collected meanwhile. The claim notices, and the commit plans
// and writes again, a few times at most.
func (s *Store) commit(ctx context.Context, namespaceID int64, key, contentType string, staged StagedBlob, upload uuid.UUID) (string, error) {
	quota := s.limits.TenantQuotaBytes
	if err := s.checkQuota(ctx, db.QuotaCheck{NamespaceID: namespaceID, Bytes: staged.Size, Key: key, Upload: upload}); err != nil {
		return "", err
	}

	var err error
	for attempt := 0; attempt < commitAttempts; attempt++ {
		var (
			p *commitPlan
			w written
		)
		p, err = s.plan(ctx, staged, namespaceID)
		if err != nil {
			return "", err
		}
		w, err = s.carryOut(ctx, staged, p)
		if err != nil {
			return "", err
		}
		err = s.db.InTx(ctx, func(tx pgx.Tx) error {
			check := db.QuotaCheck{NamespaceID: namespaceID, Bytes: staged.Size, Key: key, Upload: upload}
			if err := db.CheckQuota(ctx, tx, quota, check); err != nil {
				return err
			}
			claim, err := db.ClaimBlob(ctx, tx, staged.Hash, staged.Size, staged.MD5)
			if err != nil {
				return err
			}
			if claim.Fresh && !p.attach {
				// Planned for a blob that was stored, and has since been
				// collected. (One planned as new that someone else stored
				// meanwhile needs nothing: it has terms of its own, and
				// the xorbs written for it are left to the orphan sweep.)
				return errStale
			}
			if claim.Fresh {
				if err := db.AttachTerms(ctx, tx, staged.Hash, w.xorbs, p.terms, xorbBytes{s}); err != nil {
					return err
				}
			}
			if !claim.Chunked {
				// Stored whole before chunking. A blob revived from zero,
				// whose bytes GC may already have deleted, is rewritten
				// from staging, which is idempotent; and as above, so is
				// one new to the namespace.
				held, err := db.BlobReferencedInNamespace(ctx, tx, staged.Hash, namespaceID)
				if err != nil {
					return err
				}
				if claim.NeedsBytes() || !held {
					if err := s.blob.Copy(ctx, storage.BlobPath(staged.Hash), staged.StagingKey, nil); err != nil {
						return apperr.Internalf("promote staged blob: %w", err)
					}
				}
			}
			if err := db.UpsertObject(ctx, tx, namespaceID, key, staged.Hash, staged.ETag, staged.Size, contentType); err != nil {
				return err
			}
			return db.EnforceQuota(ctx, tx, quota, namespaceID, upload)
		})
		s.discardDecoys(context.WithoutCancel(ctx), w.decoys)
		if !isStale(err) {
			break
		}
	}
	if err != nil {
		if isStale(err) {
			return "", apperr.Internalf("commit kept going stale: %w", err)
		}
		// Leave the staging file for the sweeper: on a lost race it may be the
		// only copy of bytes a retry can reuse. New xorbs a failed commit
		// wrote have no row, and the orphan sweep reclaims them.
		return "", err
	}

	s.DiscardStaging(ctx, staged.StagingKey)
	return staged.ETag, nil
}

// commitAttempts is how many times a commit plans and writes before giving
// up on a plan that keeps going stale.
const commitAttempts = 3

// CopyObject implements copy semantics under content addressing: no bytes move,
// the destination simply claims another reference to the source blob. It
// returns the copy's ETag.
//
// The copy is a single-part object, so like S3 it gets the content's MD5 as its
// ETag even when the source was a multipart upload. The caller can already
// read the source, so writing no bytes reveals nothing.
func (s *Store) CopyObject(ctx context.Context, src db.ObjectMeta, dstNamespaceID int64, dstKey string) (string, error) {
	var etag string
	err := s.db.InTx(ctx, func(tx pgx.Tx) error {
		claim, ok, err := db.ClaimStoredBlob(ctx, tx, src.BlobHash)
		if err != nil {
			return err
		}
		if !ok {
			// The source was deleted after it was read, and GC has already
			// taken its blob. There is nothing to copy.
			return apperr.ErrNoSuchKey
		}
		if claim.NeedsBytes() {
			// A whole-file blob revived from zero: GC may have taken its bytes
			// and crashed before the row. There is no staged copy to restore
			// from, so the copy goes ahead only if the bytes are really there.
			// The claim's row lock keeps GC off them until the commit.
			present, err := s.blob.Exists(ctx, storage.BlobPath(src.BlobHash))
			if err != nil {
				return apperr.Internalf("check source blob: %w", err)
			}
			if !present {
				return apperr.ErrNoSuchKey
			}
		}
		if err := db.UpsertObject(ctx, tx, dstNamespaceID, dstKey, src.BlobHash, claim.MD5, src.Size, src.ContentType); err != nil {
			return err
		}
		etag = db.ObjectMeta{BlobHash: src.BlobHash, StoredETag: claim.MD5}.ETag()
		// A copy moves no bytes, but the destination team is charged for it
		// all the same.
		return db.EnforceQuota(ctx, tx, s.limits.TenantQuotaBytes, dstNamespaceID, uuid.Nil)
	})
	if err != nil {
		return "", err
	}
	return etag, nil
}

// LinkBlob points key at content that is already stored, transferring no bytes,
// and returns the new object's size and ETag. It reports linked=false when the blob is not present — or not visible to this
// tenant — so the caller can fall back to a real upload. This is what turns a
// client-side hash match into a zero-byte upload.
//
// tenantScope bounds visibility: when non-nil, the link succeeds only if the
// blob is already referenced inside that tenant, so the endpoint cannot be used
// to confirm the existence of another tenant's content. A nil scope links
// against any stored blob, which is correct only for a superuser caller or an
// unowned namespace — pass the namespace's own TenantID and it is always right.
func (s *Store) LinkBlob(ctx context.Context, namespaceID int64, key, hash, contentType string, tenantScope *int64) (size int64, etag string, linked bool, err error) {
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

		stored, md5, ok, err := db.ClaimExistingBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}

		size, linked = stored, true
		etag = db.ObjectMeta{BlobHash: hash, StoredETag: md5}.ETag()
		if err := db.UpsertObject(ctx, tx, namespaceID, key, hash, md5, stored, contentType); err != nil {
			return err
		}
		return db.EnforceQuota(ctx, tx, s.limits.TenantQuotaBytes, namespaceID, uuid.Nil)
	})
	if err != nil {
		return 0, "", false, err
	}
	return size, etag, linked, nil
}

// CompleteMultipart concatenates the parts into one staged blob, hashing the
// whole so the finished object dedups like any other upload, commits it, and
// then drops the parts.
//
// The assembled size is checked against the object size limit and the quota
// before any part is read, so a refused completion costs no copying.
func (s *Store) CompleteMultipart(ctx context.Context, upload db.MultipartUpload, parts []db.PartMeta) (string, error) {
	var total int64
	for _, p := range parts {
		total += p.Size
	}
	if total > s.limits.MaxObjectBytes {
		return "", apperr.EntityTooLarge("assembled object of %d bytes exceeds the %d-byte limit",
			total, s.limits.MaxObjectBytes)
	}
	check := db.QuotaCheck{NamespaceID: upload.NamespaceID, Bytes: total, Key: upload.Key, Upload: upload.ID}
	if err := s.checkQuota(ctx, check); err != nil {
		return "", err
	}

	staged, err := s.stageParts(ctx, parts)
	if err != nil {
		return "", err
	}

	etag, err := s.commit(ctx, upload.NamespaceID, upload.Key, upload.ContentType, staged, upload.ID)
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

// stageParts streams every part into a single staging file, hashing and
// chunking the concatenation, so chunk boundaries do not depend on where the
// client split its parts. Each part's MD5 is measured on the way through too, rather
// than trusted from the part's row, to give the multipart ETag.
func (s *Store) stageParts(ctx context.Context, parts []db.PartMeta) (StagedBlob, error) {
	key := storage.StagingPath(uuid.NewString())

	w, err := s.blob.NewWriter(ctx, key, nil)
	if err != nil {
		return StagedBlob{}, apperr.Internal(err)
	}

	hasher, md5er, partMD5s, chunks := blake3.New(), md5.New(), md5.New(), newChunker()
	var size int64

	for _, part := range parts {
		partMD5 := md5.New()
		sink := io.MultiWriter(w, hasher, md5er, chunks, partMD5)
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
		partMD5s.Write(partMD5.Sum(nil))
	}

	if err := w.Close(); err != nil {
		s.DiscardStaging(ctx, key)
		return StagedBlob{}, apperr.Internalf("finalise assembled upload: %w", err)
	}

	return StagedBlob{
		StagingKey: key,
		Hash:       hex.EncodeToString(hasher.Sum(nil)),
		Size:       size,
		MD5:        hexSum(md5er),
		ETag:       fmt.Sprintf("%s-%d", hexSum(partMD5s), len(parts)),
		Chunks:     chunks.finish(),
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
