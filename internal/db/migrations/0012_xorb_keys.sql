-- Stored content can be encrypted at rest (storage.encryption_keys). Each
-- chunk of a xorb names the key it is sealed under, so the bytes alone are
-- enough to read it; key_id records the same thing per xorb, so that an
-- instance can tell at startup whether its keys can read everything stored.
--
-- key_id is the key every chunk of the xorb is sealed under, or NULL for a
-- xorb stored in the clear, as every xorb before this migration is. A xorb's
-- bytes are written once, by the commit or compaction that creates its row,
-- and each writes all its chunks under one key, so one value describes them.

ALTER TABLE xorbs ADD COLUMN key_id TEXT;

-- Startup lists the distinct keys in use with a loose index scan of this.
CREATE INDEX xorbs_key_idx ON xorbs (key_id) WHERE key_id IS NOT NULL;

-- Each instance records the fingerprint of every encryption key it is
-- configured with, under the key's id, and refuses to start if the id is
-- already on record with another fingerprint. Two instances given different
-- keys under one name would otherwise each write content the other cannot
-- open, and a chunk that does not open under the key it names looks exactly
-- like a damaged one. A key id names one key for good.
CREATE TABLE storage_keys (
    id          TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
