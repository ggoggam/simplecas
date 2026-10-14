-- What each namespace stores is counted as it changes, so that a team's
-- quota check, and stats, read a few counters rather than sum every object.
--
-- The counting is done by triggers on objects, so no write path can forget
-- it, and it takes no lock on a shared row: every statement that changes
-- objects appends its net change per namespace to usage_deltas, which only
-- ever gains rows. A counter row updated in place by every write would be
-- locked by each writer until it committed, in whatever order the write had
-- taken its other locks (blob rows, object keys), and two writers could then
-- deadlock. GC folds the deltas into namespace_usage now and then; usage is
-- namespace_usage plus whatever deltas are not folded yet.
--
-- The triggers are statement-level with transition tables, so a statement
-- that changes many objects appends one delta per namespace, not per row.

CREATE TABLE namespace_usage (
    namespace_id BIGINT PRIMARY KEY REFERENCES namespaces (id) ON DELETE CASCADE,
    objects      BIGINT NOT NULL DEFAULT 0,
    bytes        BIGINT NOT NULL DEFAULT 0
);

-- No foreign key: a namespace's deltas may be written as it is deleted, and
-- are dropped when they are folded.
CREATE TABLE usage_deltas (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    namespace_id BIGINT NOT NULL,
    objects      BIGINT NOT NULL,
    bytes        BIGINT NOT NULL
);

CREATE INDEX usage_deltas_namespace_idx ON usage_deltas (namespace_id);

CREATE FUNCTION objects_usage_inserted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO usage_deltas (namespace_id, objects, bytes)
    SELECT namespace_id, count(*), sum(size) FROM new_objects GROUP BY namespace_id;
    RETURN NULL;
END
$$;

CREATE FUNCTION objects_usage_updated() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO usage_deltas (namespace_id, objects, bytes)
    SELECT namespace_id, sum(objects), sum(bytes) FROM (
        SELECT namespace_id, 1 AS objects, size AS bytes FROM new_objects
        UNION ALL
        SELECT namespace_id, -1, -size FROM old_objects
    ) changed
    GROUP BY namespace_id
    HAVING sum(objects) <> 0 OR sum(bytes) <> 0;
    RETURN NULL;
END
$$;

CREATE FUNCTION objects_usage_deleted() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO usage_deltas (namespace_id, objects, bytes)
    SELECT namespace_id, -count(*), -sum(size) FROM old_objects GROUP BY namespace_id;
    RETURN NULL;
END
$$;

-- Creating the triggers locks objects against writes until this migration
-- commits, so the counts below see every object, and every write after them
-- is counted by a trigger.
CREATE TRIGGER objects_usage_insert AFTER INSERT ON objects
    REFERENCING NEW TABLE AS new_objects
    FOR EACH STATEMENT EXECUTE FUNCTION objects_usage_inserted();
CREATE TRIGGER objects_usage_update AFTER UPDATE ON objects
    REFERENCING OLD TABLE AS old_objects NEW TABLE AS new_objects
    FOR EACH STATEMENT EXECUTE FUNCTION objects_usage_updated();
CREATE TRIGGER objects_usage_delete AFTER DELETE ON objects
    REFERENCING OLD TABLE AS old_objects
    FOR EACH STATEMENT EXECUTE FUNCTION objects_usage_deleted();

INSERT INTO namespace_usage (namespace_id, objects, bytes)
SELECT namespace_id, count(*), sum(size) FROM objects GROUP BY namespace_id;
