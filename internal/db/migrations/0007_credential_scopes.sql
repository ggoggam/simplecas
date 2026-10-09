-- Per-key scopes: which of its team's namespaces a key reaches, and what it
-- may do there.
--
-- permissions is a subset of read, list, write and delete. Existing keys keep
-- all four, which is what every key could do before this column existed.
-- namespaces NULL reaches every namespace the team owns, now and later; a list
-- names the only ones it reaches. Names rather than ids, so a namespace that is
-- deleted and created again by the same team is reached again, and one that
-- moves to another team never is: the gateway still requires the team to own
-- whatever a key addresses.
ALTER TABLE tenant_credentials
    ADD COLUMN permissions TEXT[] NOT NULL DEFAULT '{read,list,write,delete}',
    ADD COLUMN namespaces  TEXT[],
    ADD CONSTRAINT tenant_credentials_permissions CHECK (
        cardinality(permissions) > 0
        AND permissions <@ '{read,list,write,delete}'::TEXT[]
    ),
    -- An empty list would reach nothing, and is too easily mistaken for NULL.
    ADD CONSTRAINT tenant_credentials_namespaces CHECK (
        namespaces IS NULL OR cardinality(namespaces) > 0
    );
