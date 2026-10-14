-- Stored content is re-read in the background and checked against its hashes
-- (scrubbing), and xorbs that are mostly chunks no blob uses any more are
-- rewritten with only the chunks still in use (compaction).
--
-- verified_at is when the bytes were last read back and found to match. A
-- row written from now on starts verified, since its bytes were hashed on
-- the way in; rows that predate this migration have never been checked, so
-- they stay NULL and are scrubbed first. damaged_at is set when a check finds
-- bytes that do not match, or are missing, and cleared when a later check
-- finds them sound again. Dedup never reuses chunks of a damaged xorb.
--
-- released_at marks a xorb that lost a blob but is still used by others, so
-- some of its chunks may now be dead. Compaction looks only at marked xorbs,
-- and unmarks each one it has dealt with. Every live xorb is marked here, so
-- that each is looked at once.

ALTER TABLE xorbs
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN damaged_at  TIMESTAMPTZ,
    ADD COLUMN released_at TIMESTAMPTZ;
ALTER TABLE xorbs ALTER COLUMN verified_at SET DEFAULT now();

ALTER TABLE blobs
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN damaged_at  TIMESTAMPTZ;
ALTER TABLE blobs ALTER COLUMN verified_at SET DEFAULT now();

UPDATE xorbs SET released_at = now() WHERE refcount > 0;

CREATE INDEX xorbs_scrub_idx ON xorbs (verified_at NULLS FIRST) WHERE refcount > 0;
CREATE INDEX blobs_scrub_idx ON blobs (verified_at NULLS FIRST) WHERE refcount > 0 AND NOT chunked;
CREATE INDEX xorbs_released_idx ON xorbs (released_at) WHERE released_at IS NOT NULL;
