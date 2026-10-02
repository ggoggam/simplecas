-- Users keyed on the identity provider's (issuer, subject), and membership
-- keyed on the user rather than on an email address.
--
-- Keying membership on email let anyone who could get an identity provider to
-- vouch for an address inherit every team that address belonged to: another
-- configured provider with open sign-up, or whoever is later given a recycled
-- mailbox. The subject is the provider's stable, never-reassigned id for one
-- account, so it is what a membership now binds to. Email survives only where
-- it has to: an invitation is addressed to one, before the invitee has a user
-- row, and becomes a membership only when a signed-in user with that verified
-- address accepts it.

CREATE TABLE users (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer     TEXT COLLATE "C" NOT NULL,
    subject    TEXT COLLATE "C" NOT NULL,
    -- The last verified address the provider asserted, normalised, or '' when
    -- it asserted none. Display only: nothing authorizes on it.
    email      TEXT COLLATE "C" NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject)
);

CREATE TABLE tenant_invitations (
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email      TEXT COLLATE "C" NOT NULL,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    invited_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL only for the memberships carried over below, which predate expiry.
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, email)
);

CREATE INDEX tenant_invitations_email_idx ON tenant_invitations (email);

-- No user rows exist yet to attach the old email-keyed memberships to, so each
-- becomes a pending invitation with its role intact. Every existing member,
-- owners included, accepts once after signing in.
INSERT INTO tenant_invitations (tenant_id, email, role, created_at)
SELECT tenant_id, email, role, created_at FROM tenant_members;

DROP TABLE tenant_members;

CREATE TABLE tenant_members (
    tenant_id  BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX tenant_members_user_idx ON tenant_members (user_id);
