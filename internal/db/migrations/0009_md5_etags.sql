-- S3 ETags become MD5s, as clients expect, instead of the BLAKE3 digest the
-- store addresses content by. Dedup stays global, so the BLAKE3 digest is the
-- key to every tenant's copy of some content, and it is no longer handed out.
--
-- blobs.md5 is the hex MD5 of the whole content. objects.etag is the ETag
-- served for the object, unquoted: the content MD5 for a single PUT, a copy or
-- a link, and for a multipart upload the MD5 of its parts' MD5s followed by
-- "-" and the part count, as S3 computes it.
--
-- Both are NULL for content stored before this migration. Until the GC loop's
-- backfill reads those blobs and fills them in, such an object is served with
-- its BLAKE3 digest as before.

ALTER TABLE blobs ADD COLUMN md5 TEXT;

ALTER TABLE objects ADD COLUMN etag TEXT;

CREATE INDEX objects_etag_backfill_idx ON objects (blob_hash) WHERE etag IS NULL;
