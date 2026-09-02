-- Per-tenant S3 credentials, which is what makes the S3 gateway a tenanted
-- plane rather than a single trusted admin plane. A request signed with one of
-- these keys may address only the namespaces owned by its tenant.
--
-- secret_access_key is stored recoverably, not hashed. SigV4 is a symmetric
-- HMAC scheme: the server has to re-derive the signing key from the secret to
-- verify a signature, so a one-way hash cannot work. This is the same property
-- that makes the admin credential in simplecas.toml plaintext. Treat the table
-- as secret material: it is equivalent to the objects it grants access to.
CREATE TABLE tenant_credentials (
    access_key_id     TEXT PRIMARY KEY,
    secret_access_key TEXT NOT NULL,
    tenant_id         BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    -- A human label so an owner can tell their keys apart when revoking one.
    description       TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX tenant_credentials_tenant_idx ON tenant_credentials (tenant_id);
