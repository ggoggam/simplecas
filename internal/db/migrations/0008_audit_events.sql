-- An append-only record of who changed a team's membership, invitations, S3
-- keys and namespaces. Each row is written in the same transaction as the change
-- it describes, so a change is recorded exactly when it commits.
--
-- tenant_id deliberately has no foreign key. A team's history has to outlive the
-- team, or deleting it would erase the record of who deleted it and of
-- everything before. Tenant ids are identity values and never reused, so a team
-- created later under the same name never sees the old one's rows. NULL is a
-- change to an unowned namespace (the S3 admin credential's, or /api with
-- sign-in off).
--
-- The actor columns snapshot who acted at the time: a signed-in user (id and
-- address), an S3 key, or neither when the change came through an open plane.
-- The address is display only and is not updated if the user's changes later.

CREATE TABLE audit_events (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id           BIGINT,
    -- A dotted noun.verb name such as member.remove; see db.Event* for the set.
    action              TEXT NOT NULL,
    actor_user_id       BIGINT REFERENCES users (id) ON DELETE SET NULL,
    actor_email         TEXT NOT NULL DEFAULT '',
    actor_access_key_id TEXT NOT NULL DEFAULT '',
    -- The router's X-Amz-Request-Id, tying the row to the request log.
    request_id          TEXT NOT NULL DEFAULT '',
    -- What was acted on: a tenant or namespace name, an invited address, an
    -- access key id, or a member's user id.
    target              TEXT NOT NULL DEFAULT '',
    -- The rest of the change as a flat JSON object, e.g. {"from":"member","to":"owner"}.
    details             JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object')
);

-- A team's history, newest first, paged by id.
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, id);
