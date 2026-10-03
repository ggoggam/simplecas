-- Server-side sessions, so a sign-in can be listed and revoked.
--
-- The session cookie stays signed, but it now also carries a random bearer
-- token, and a session is live only while a row here holds that token's
-- SHA-256. Only the hash is stored: someone who can read this table cannot
-- present any of these sessions.
--
-- Revoking a session deletes its row rather than marking it. Nothing reads a
-- revoked session again, so a tombstone would only be one more predicate on
-- every request's lookup and one more thing for the sweep to clear; the table
-- holds exactly the live and not-yet-swept expired sessions.

CREATE TABLE sessions (
    -- The public handle the API lists and revokes a session by. Random, so
    -- one user's id says nothing about anyone else's.
    id           UUID PRIMARY KEY,
    token_hash   BYTEA NOT NULL UNIQUE,
    user_id      BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Refreshed by authenticated requests, at most once every few minutes.
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    -- What the signing-in browser sent, truncated, for display only.
    user_agent   TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT ''
);

-- A user's sessions page, and revoking them. Deliberately not on last_seen_at:
-- with no index on it, refreshing it is a HOT update that touches no index.
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- The background sweep of expired rows.
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
