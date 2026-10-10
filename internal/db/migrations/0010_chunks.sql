-- Content is stored the way the Xet protocol stores it
-- (https://huggingface.co/docs/xet): cut into content-defined chunks, which
-- are packed into xorbs, and each blob is a list of terms, each a run of
-- chunks in one xorb. Two objects that share most of their bytes share most
-- of their storage, and an object store sees one write per xorb of up to
-- 64 MiB rather than one per chunk.
--
-- A blob is still one row per distinct content, keyed by the BLAKE3 digest of
-- the whole, and objects still count references to it. A chunked blob's bytes
-- are the concatenation of its terms in pos order. A xorb is named by its Xet
-- hash, stored under xorbs/, and xorb_chunks says where each of its chunks
-- sits in it (offset and length as stored, size once decompressed).
-- xorbs.refcount counts the blobs with a term on the xorb, each blob once,
-- and GC deletes a xorb that has stayed at zero past the grace period.
--
-- Blobs stored before this migration keep their bytes as one file under
-- blobs/ and have chunked = false. They are read, copied and collected as
-- before; only new content is chunked.

ALTER TABLE blobs ADD COLUMN chunked BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE xorbs (
    hash       TEXT PRIMARY KEY,
    size       BIGINT NOT NULL,
    refcount   BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX xorbs_gc_idx ON xorbs (updated_at) WHERE refcount = 0;

CREATE TABLE xorb_chunks (
    xorb_hash  TEXT NOT NULL REFERENCES xorbs (hash) ON DELETE CASCADE,
    idx        INT NOT NULL,
    chunk_hash TEXT NOT NULL,
    byte_start BIGINT NOT NULL,
    length     INT NOT NULL,
    size       INT NOT NULL,
    PRIMARY KEY (xorb_hash, idx)
);

-- Dedup looks chunks up by hash to find a xorb that already holds them.
CREATE INDEX xorb_chunks_chunk_idx ON xorb_chunks (chunk_hash);

CREATE TABLE blob_terms (
    blob_hash   TEXT NOT NULL REFERENCES blobs (hash),
    pos         BIGINT NOT NULL,
    xorb_hash   TEXT NOT NULL REFERENCES xorbs (hash),
    chunk_start INT NOT NULL,
    chunk_end   INT NOT NULL,
    size        BIGINT NOT NULL,
    PRIMARY KEY (blob_hash, pos)
);

CREATE INDEX blob_terms_xorb_idx ON blob_terms (xorb_hash);
