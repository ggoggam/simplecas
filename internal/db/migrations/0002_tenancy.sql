-- Team/org tenancy for the human-facing plane (/ui + /api). The S3 gateway
-- stays a single trusted admin plane: namespaces it creates have tenant_id
-- NULL and are invisible to tenant-scoped (signed-in) users.

CREATE TABLE tenants (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT COLLATE "C" NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Membership is keyed by (verified) email because invitations are issued by
-- email, before the invitee's first login. role is 'owner' (may manage
-- membership and delete the tenant) or 'member'.
CREATE TABLE tenant_members (
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email      TEXT COLLATE "C" NOT NULL,
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, email)
);

CREATE INDEX tenant_members_email_idx ON tenant_members (email);

-- Which tenant owns a namespace. NULL = unowned (created via the S3 admin
-- plane, or predating tenancy); such namespaces are hidden from tenant users.
ALTER TABLE namespaces ADD COLUMN tenant_id BIGINT REFERENCES tenants (id);

CREATE INDEX namespaces_tenant_idx ON namespaces (tenant_id);
