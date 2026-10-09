-- Per-team S3 secrets sealed at rest, and keys that can expire.
--
-- A secret is now stored sealed (AES-256-GCM under one of the server's
-- auth.credential_keys, named in secret_key_id) rather than as plaintext. SQL
-- cannot seal, since the keys live in the server's configuration, so this
-- migration only makes room: the server seals every plaintext row when it
-- starts with keys configured, and secret_access_key stays NULL from then on.
-- The CHECK keeps each row in exactly one of the two forms.
ALTER TABLE tenant_credentials
    ALTER COLUMN secret_access_key DROP NOT NULL,
    ADD COLUMN secret_sealed BYTEA,
    ADD COLUMN secret_key_id TEXT,
    -- Who minted the key, for the listing. Kept when they leave the team or
    -- delete their account, as a key outlives its creator's membership.
    ADD COLUMN created_by    BIGINT REFERENCES users (id) ON DELETE SET NULL,
    -- NULL never expires. Past it, the key verifies nothing.
    ADD COLUMN expires_at    TIMESTAMPTZ,
    -- Refreshed by verified requests, at most once every few minutes, so an
    -- owner can tell a key in use from one safe to revoke.
    ADD COLUMN last_used_at  TIMESTAMPTZ,
    ADD CONSTRAINT tenant_credentials_secret_form CHECK (
        (secret_access_key IS NULL) <> (secret_sealed IS NULL)
        AND (secret_sealed IS NULL) = (secret_key_id IS NULL)
    );
