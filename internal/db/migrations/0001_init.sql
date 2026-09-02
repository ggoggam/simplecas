-- Core schema for simplecas.
-- Keys use COLLATE "C" so ORDER BY matches S3's byte-order key sorting.

CREATE TABLE namespaces (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT COLLATE "C" NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per unique content blob (blake3 hex). refcount counts referencing
-- objects; GC removes rows that stay at 0 past the grace period.
CREATE TABLE blobs (
    hash       TEXT PRIMARY KEY,
    size       BIGINT NOT NULL,
    refcount   BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX blobs_gc_idx ON blobs (updated_at) WHERE refcount = 0;

CREATE TABLE objects (
    namespace_id BIGINT NOT NULL REFERENCES namespaces (id) ON DELETE CASCADE,
    key          TEXT COLLATE "C" NOT NULL,
    blob_hash    TEXT NOT NULL REFERENCES blobs (hash),
    size         BIGINT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace_id, key)
);

CREATE INDEX objects_blob_idx ON objects (blob_hash);

CREATE TABLE multipart_uploads (
    id           UUID PRIMARY KEY,
    namespace_id BIGINT NOT NULL REFERENCES namespaces (id) ON DELETE CASCADE,
    key          TEXT COLLATE "C" NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE multipart_parts (
    upload_id   UUID NOT NULL REFERENCES multipart_uploads (id) ON DELETE CASCADE,
    part_number INT NOT NULL,
    staging_key TEXT NOT NULL,
    size        BIGINT NOT NULL,
    etag        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part_number)
);
