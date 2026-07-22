use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(pool)
}

#[derive(Debug, sqlx::FromRow)]
pub struct Namespace {
    pub id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    /// Owning tenant, or `None` for unowned (S3-admin-plane / pre-tenancy)
    /// namespaces.
    pub tenant_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct ObjectMeta {
    pub key: String,
    pub blob_hash: String,
    pub size: i64,
    pub content_type: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct PartMeta {
    pub part_number: i32,
    pub staging_key: String,
    pub size: i64,
    pub etag: String,
}

#[derive(Debug, serde::Serialize)]
pub struct Stats {
    pub namespace_count: i64,
    pub object_count: i64,
    pub blob_count: i64,
    pub logical_bytes: i64,
    pub physical_bytes: i64,
}

// ---- namespaces ----

pub async fn list_namespaces(pool: &PgPool) -> Result<Vec<Namespace>> {
    Ok(
        sqlx::query_as("SELECT id, name, created_at, tenant_id FROM namespaces ORDER BY name")
            .fetch_all(pool)
            .await?,
    )
}

/// Namespaces owned by any of `tenant_ids`, in name order. Used by the
/// tenant-scoped `/api` + `/ui` plane so a caller sees only their tenants'
/// namespaces (unowned NULL-tenant namespaces are excluded).
pub async fn list_namespaces_for_tenants(
    pool: &PgPool,
    tenant_ids: &[i64],
) -> Result<Vec<Namespace>> {
    Ok(sqlx::query_as(
        "SELECT id, name, created_at, tenant_id FROM namespaces
         WHERE tenant_id = ANY($1) ORDER BY name",
    )
    .bind(tenant_ids)
    .fetch_all(pool)
    .await?)
}

pub async fn get_namespace(pool: &PgPool, name: &str) -> Result<Namespace> {
    sqlx::query_as("SELECT id, name, created_at, tenant_id FROM namespaces WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::NoSuchNamespace)
}

/// Fetch a namespace only if `email` is a member of its owning tenant. Any
/// other case — missing namespace, unowned namespace, or caller not a member —
/// resolves to `NoSuchNamespace`, so the tenant plane never reveals the
/// existence of namespaces the caller can't access.
pub async fn get_namespace_for_member(pool: &PgPool, name: &str, email: &str) -> Result<Namespace> {
    sqlx::query_as(
        "SELECT n.id, n.name, n.created_at, n.tenant_id
         FROM namespaces n
         JOIN tenant_members m ON m.tenant_id = n.tenant_id AND m.email = $2
         WHERE n.name = $1",
    )
    .bind(name)
    .bind(email)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NoSuchNamespace)
}

pub async fn create_namespace(pool: &PgPool, name: &str, tenant_id: Option<i64>) -> Result<()> {
    let inserted = sqlx::query(
        "INSERT INTO namespaces (name, tenant_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(name)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(Error::NamespaceAlreadyExists);
    }
    Ok(())
}

/// S3 semantics: deleting a non-empty namespace is a 409.
pub async fn delete_namespace(pool: &PgPool, name: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    let namespace: Namespace = sqlx::query_as(
        "SELECT id, name, created_at, tenant_id FROM namespaces WHERE name = $1 FOR UPDATE",
    )
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NoSuchNamespace)?;
    let (occupied,): (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM objects WHERE namespace_id = $1)")
            .bind(namespace.id)
            .fetch_one(&mut *tx)
            .await?;
    if occupied {
        return Err(Error::NamespaceNotEmpty);
    }
    sqlx::query("DELETE FROM namespaces WHERE id = $1")
        .bind(namespace.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---- tenants ----

/// A tenant the caller belongs to, carrying the caller's role in it.
#[derive(Debug, sqlx::FromRow)]
pub struct TenantMembership {
    pub name: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct Member {
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// Tenants `email` is a member of, with the caller's role, in name order.
pub async fn list_tenants_for_email(pool: &PgPool, email: &str) -> Result<Vec<TenantMembership>> {
    Ok(sqlx::query_as(
        "SELECT t.name, m.role, t.created_at
         FROM tenants t
         JOIN tenant_members m ON m.tenant_id = t.id
         WHERE m.email = $1
         ORDER BY t.name",
    )
    .bind(email)
    .fetch_all(pool)
    .await?)
}

/// Tenant ids `email` belongs to (for scoping listings and stats).
pub async fn tenant_ids_for_email(pool: &PgPool, email: &str) -> Result<Vec<i64>> {
    let rows: Vec<(i64,)> = sqlx::query_as("SELECT tenant_id FROM tenant_members WHERE email = $1")
        .bind(email)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Resolve a tenant name to its id, or `NoSuchTenant`.
pub async fn tenant_id_by_name(pool: &PgPool, name: &str) -> Result<i64> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM tenants WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    row.map(|(id,)| id).ok_or(Error::NoSuchTenant)
}

/// The caller's role in `tenant_id`, or `None` if they're not a member.
pub async fn tenant_role(pool: &PgPool, tenant_id: i64, email: &str) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM tenant_members WHERE tenant_id = $1 AND email = $2")
            .bind(tenant_id)
            .bind(email)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(r,)| r))
}

/// Create a tenant with `owner_email` as its sole owner (both in one tx).
pub async fn create_tenant(pool: &PgPool, name: &str, owner_email: &str) -> Result<i64> {
    let mut tx = pool.begin().await?;
    let row: Option<(i64,)> = sqlx::query_as(
        "INSERT INTO tenants (name) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id,)) = row else {
        return Err(Error::TenantAlreadyExists);
    };
    sqlx::query("INSERT INTO tenant_members (tenant_id, email, role) VALUES ($1, $2, 'owner')")
        .bind(id)
        .bind(owner_email)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn list_members(pool: &PgPool, tenant_id: i64) -> Result<Vec<Member>> {
    Ok(sqlx::query_as(
        "SELECT email, role, created_at FROM tenant_members
         WHERE tenant_id = $1 ORDER BY email",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?)
}

/// Invite (or re-role) a member. Upserts so re-inviting updates the role.
pub async fn add_member(pool: &PgPool, tenant_id: i64, email: &str, role: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO tenant_members (tenant_id, email, role) VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, email) DO UPDATE SET role = $3",
    )
    .bind(tenant_id)
    .bind(email)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a member, refusing to strip a tenant of its last owner.
pub async fn remove_member(pool: &PgPool, tenant_id: i64, email: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    let victim: Option<(String,)> = sqlx::query_as(
        "SELECT role FROM tenant_members WHERE tenant_id = $1 AND email = $2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((role,)) = victim else {
        return Ok(()); // idempotent: not a member
    };
    if role == "owner" {
        let (owners,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner'",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if owners <= 1 {
            return Err(Error::InvalidArgument(
                "cannot remove the last owner of a tenant".into(),
            ));
        }
    }
    sqlx::query("DELETE FROM tenant_members WHERE tenant_id = $1 AND email = $2")
        .bind(tenant_id)
        .bind(email)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Delete an empty tenant (members cascade). A tenant that still owns
/// namespaces is a 409, mirroring non-empty namespace deletion.
pub async fn delete_tenant(pool: &PgPool, tenant_id: i64) -> Result<()> {
    let mut tx = pool.begin().await?;
    let (occupied,): (bool,) =
        sqlx::query_as("SELECT EXISTS(SELECT 1 FROM namespaces WHERE tenant_id = $1)")
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await?;
    if occupied {
        return Err(Error::TenantNotEmpty);
    }
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---- blobs / objects ----

/// Whether any object inside `tenant_id`'s namespaces references `hash`. Gates
/// the dedup "link" fast path so it can't be used as a cross-tenant existence
/// oracle: a caller only gets a zero-byte link for content their own tenant
/// already holds. (Physical dedup stays global — a real upload of the same
/// bytes still hits `claim_blob` and stores nothing new.)
pub async fn blob_referenced_in_tenant(
    tx: &mut Transaction<'_, Postgres>,
    hash: &str,
    tenant_id: i64,
) -> Result<bool> {
    let (referenced,): (bool,) = sqlx::query_as(
        "SELECT EXISTS(
             SELECT 1 FROM objects o
             JOIN namespaces n ON n.id = o.namespace_id
             WHERE o.blob_hash = $1 AND n.tenant_id = $2
         )",
    )
    .bind(hash)
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(referenced)
}

/// Claim a reference to `hash` inside `tx`, creating the blob row if new.
/// Returns true when this call created the row (caller must upload the bytes
/// before committing). The ON CONFLICT row lock serializes against the GC's
/// SELECT ... FOR UPDATE, so a blob being swept can't be re-referenced.
pub async fn claim_blob(tx: &mut Transaction<'_, Postgres>, hash: &str, size: i64) -> Result<bool> {
    let (inserted,): (bool,) = sqlx::query_as(
        "INSERT INTO blobs (hash, size, refcount) VALUES ($1, $2, 1)
         ON CONFLICT (hash) DO UPDATE
             SET refcount = blobs.refcount + 1, updated_at = now()
         RETURNING (xmax = 0)",
    )
    .bind(hash)
    .bind(size)
    .fetch_one(&mut **tx)
    .await?;
    Ok(inserted)
}

/// Claim a reference to `hash` only if the blob already exists, returning its
/// authoritative size. Returns `None` when the blob is absent (never referenced,
/// or swept by GC). Used by the dedup "link" path: the row lock serializes
/// against GC's `SELECT ... FOR UPDATE`, so a blob being swept resolves to
/// `None` (caller uploads the bytes for real) rather than a dangling reference.
pub async fn claim_existing_blob(
    tx: &mut Transaction<'_, Postgres>,
    hash: &str,
) -> Result<Option<i64>> {
    let row: Option<(i64,)> = sqlx::query_as(
        "UPDATE blobs SET refcount = refcount + 1, updated_at = now()
         WHERE hash = $1 RETURNING size",
    )
    .bind(hash)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|(s,)| s))
}

pub async fn release_blob(tx: &mut Transaction<'_, Postgres>, hash: &str) -> Result<()> {
    sqlx::query(
        "UPDATE blobs SET refcount = GREATEST(refcount - 1, 0), updated_at = now()
         WHERE hash = $1",
    )
    .bind(hash)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Point `key` at `hash`, adjusting refcounts for any blob it previously
/// referenced. Assumes `claim_blob` already ran for `hash` in this tx.
pub async fn upsert_object(
    tx: &mut Transaction<'_, Postgres>,
    namespace_id: i64,
    key: &str,
    hash: &str,
    size: i64,
    content_type: &str,
) -> Result<()> {
    let old: Option<(String,)> = sqlx::query_as(
        "SELECT blob_hash FROM objects WHERE namespace_id = $1 AND key = $2 FOR UPDATE",
    )
    .bind(namespace_id)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO objects (namespace_id, key, blob_hash, size, content_type)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (namespace_id, key) DO UPDATE
             SET blob_hash = $3, size = $4, content_type = $5, updated_at = now()",
    )
    .bind(namespace_id)
    .bind(key)
    .bind(hash)
    .bind(size)
    .bind(content_type)
    .execute(&mut **tx)
    .await?;
    if let Some((old_hash,)) = old {
        // Overwrite: drop the old reference (also nets out the double-count
        // when an object is overwritten with identical content).
        release_blob(tx, &old_hash).await?;
    }
    Ok(())
}

pub async fn get_object(pool: &PgPool, namespace_id: i64, key: &str) -> Result<ObjectMeta> {
    sqlx::query_as(
        "SELECT key, blob_hash, size, content_type, updated_at
         FROM objects WHERE namespace_id = $1 AND key = $2",
    )
    .bind(namespace_id)
    .bind(key)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NoSuchKey)
}

/// Returns Ok(false) if the key didn't exist (S3 DELETE is idempotent-204
/// either way, but callers may care).
pub async fn delete_object(pool: &PgPool, namespace_id: i64, key: &str) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let old: Option<(String,)> = sqlx::query_as(
        "DELETE FROM objects WHERE namespace_id = $1 AND key = $2 RETURNING blob_hash",
    )
    .bind(namespace_id)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?;
    let existed = if let Some((hash,)) = old {
        release_blob(&mut tx, &hash).await?;
        true
    } else {
        false
    };
    tx.commit().await?;
    Ok(existed)
}

// ---- listing ----

#[derive(Debug, Default)]
pub struct ListResult {
    pub objects: Vec<ObjectMeta>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    /// Key/prefix to continue after (encoded by the API layer).
    pub next_marker: Option<String>,
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// ListObjectsV2 core. `marker` is the raw key to resume strictly after.
/// Delimiter grouping is computed by walking key order in batches; when a
/// common prefix is found we jump past its group using the byte successor of
/// the prefix (delimiter is restricted to a single ASCII char, so the
/// successor is always valid UTF-8 under COLLATE "C" byte ordering).
pub async fn list_objects(
    pool: &PgPool,
    namespace_id: i64,
    prefix: &str,
    delimiter: Option<char>,
    marker: &str,
    max_keys: usize,
) -> Result<ListResult> {
    const BATCH: i64 = 1000;
    let mut result = ListResult::default();
    let mut marker = marker.to_string();
    let like = format!("{}%", escape_like(prefix));

    'outer: loop {
        let rows: Vec<ObjectMeta> = sqlx::query_as(
            "SELECT key, blob_hash, size, content_type, updated_at
             FROM objects
             WHERE namespace_id = $1 AND key LIKE $2 AND key > $3
             ORDER BY key
             LIMIT $4",
        )
        .bind(namespace_id)
        .bind(&like)
        .bind(&marker)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let exhausted_batch = rows.len() < BATCH as usize;

        for row in rows {
            if result.objects.len() + result.common_prefixes.len() >= max_keys {
                result.is_truncated = true;
                result.next_marker = Some(marker.clone());
                break 'outer;
            }
            let rest = &row.key[prefix.len()..];
            match delimiter.and_then(|d| rest.find(d)) {
                Some(idx) => {
                    let d_len = delimiter.unwrap().len_utf8();
                    let group = format!("{}{}", prefix, &rest[..idx + d_len]);
                    // Jump past every key in this group: successor of the
                    // group's trailing (ASCII) delimiter byte.
                    let mut jump = group.clone();
                    let last = jump.pop().unwrap() as u8;
                    jump.push((last + 1) as char);
                    marker = jump;
                    result.common_prefixes.push(group);
                    // Remaining rows in this batch may belong to the skipped
                    // group; refetch from the jump marker.
                    continue 'outer;
                }
                None => {
                    marker = row.key.clone();
                    result.objects.push(row);
                }
            }
        }
        if exhausted_batch {
            break;
        }
    }
    Ok(result)
}

// ---- multipart ----

pub async fn create_multipart(
    pool: &PgPool,
    namespace_id: i64,
    key: &str,
    content_type: &str,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO multipart_uploads (id, namespace_id, key, content_type) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(namespace_id)
    .bind(key)
    .bind(content_type)
    .execute(pool)
    .await?;
    Ok(id)
}

#[derive(Debug, sqlx::FromRow)]
pub struct MultipartUpload {
    pub id: Uuid,
    pub namespace_id: i64,
    pub key: String,
    pub content_type: String,
}

pub async fn get_multipart(
    pool: &PgPool,
    namespace_id: i64,
    key: &str,
    id: Uuid,
) -> Result<MultipartUpload> {
    sqlx::query_as(
        "SELECT id, namespace_id, key, content_type FROM multipart_uploads
         WHERE id = $1 AND namespace_id = $2 AND key = $3",
    )
    .bind(id)
    .bind(namespace_id)
    .bind(key)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NoSuchUpload)
}

/// Record a part; returns the staging key of a previous upload of the same
/// part number (caller deletes those bytes).
pub async fn put_part(
    pool: &PgPool,
    upload_id: Uuid,
    part_number: i32,
    staging_key: &str,
    size: i64,
    etag: &str,
) -> Result<Option<String>> {
    let mut tx = pool.begin().await?;
    let old: Option<(String,)> = sqlx::query_as(
        "SELECT staging_key FROM multipart_parts WHERE upload_id = $1 AND part_number = $2 FOR UPDATE",
    )
    .bind(upload_id)
    .bind(part_number)
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO multipart_parts (upload_id, part_number, staging_key, size, etag)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (upload_id, part_number) DO UPDATE
             SET staging_key = $3, size = $4, etag = $5, created_at = now()",
    )
    .bind(upload_id)
    .bind(part_number)
    .bind(staging_key)
    .bind(size)
    .bind(etag)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(old.map(|(k,)| k))
}

pub async fn list_parts(pool: &PgPool, upload_id: Uuid) -> Result<Vec<PartMeta>> {
    Ok(sqlx::query_as(
        "SELECT part_number, staging_key, size, etag FROM multipart_parts
         WHERE upload_id = $1 ORDER BY part_number",
    )
    .bind(upload_id)
    .fetch_all(pool)
    .await?)
}

/// One page of parts with `part_number > after`, capped at `limit`. Fetches one
/// extra row to tell the caller whether more remain (see [`PartPage`]).
pub struct PartPage {
    pub parts: Vec<PartMeta>,
    pub is_truncated: bool,
}

pub async fn list_parts_page(
    pool: &PgPool,
    upload_id: Uuid,
    after: i32,
    limit: i64,
) -> Result<PartPage> {
    let mut parts: Vec<PartMeta> = sqlx::query_as(
        "SELECT part_number, staging_key, size, etag FROM multipart_parts
         WHERE upload_id = $1 AND part_number > $2 ORDER BY part_number LIMIT $3",
    )
    .bind(upload_id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(pool)
    .await?;
    let is_truncated = parts.len() as i64 > limit;
    parts.truncate(limit as usize);
    Ok(PartPage {
        parts,
        is_truncated,
    })
}

#[derive(Debug, sqlx::FromRow)]
pub struct MultipartUploadEntry {
    pub id: Uuid,
    pub key: String,
    pub created_at: DateTime<Utc>,
}

/// In-progress uploads in a namespace whose key is >= `prefix`, ordered by key
/// then id. Non-paginated (bounded by `limit`); adequate for the modest number
/// of concurrent uploads this server expects.
pub async fn list_multipart_uploads(
    pool: &PgPool,
    namespace_id: i64,
    prefix: &str,
    limit: i64,
) -> Result<Vec<MultipartUploadEntry>> {
    Ok(sqlx::query_as(
        "SELECT id, key, created_at FROM multipart_uploads
         WHERE namespace_id = $1 AND key LIKE $2 || '%'
         ORDER BY key, id LIMIT $3",
    )
    .bind(namespace_id)
    .bind(prefix)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

/// Delete multipart uploads with no activity (upload or any part) inside the
/// expiry window, returning their part staging keys for byte cleanup. Because
/// `sweep_staging` deliberately protects part-referenced staging files from GC,
/// this is the *only* thing that reclaims bytes from abandoned uploads.
pub struct SweptMultipart {
    /// Number of uploads deleted (parts or not).
    pub uploads: u64,
    /// Staging keys whose bytes the caller must delete.
    pub staging_keys: Vec<String>,
}

pub async fn sweep_multipart(pool: &PgPool, expiry_secs: u64) -> Result<SweptMultipart> {
    let mut tx = pool.begin().await?;
    let stale: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT u.id FROM multipart_uploads u
         WHERE u.created_at < now() - make_interval(secs => $1)
           AND NOT EXISTS (
               SELECT 1 FROM multipart_parts p
               WHERE p.upload_id = u.id
                 AND p.created_at >= now() - make_interval(secs => $1)
           )
         FOR UPDATE SKIP LOCKED",
    )
    .bind(expiry_secs as f64)
    .fetch_all(&mut *tx)
    .await?;
    if stale.is_empty() {
        return Ok(SweptMultipart {
            uploads: 0,
            staging_keys: Vec::new(),
        });
    }
    let ids: Vec<Uuid> = stale.into_iter().map(|(id,)| id).collect();
    let keys: Vec<(String,)> =
        sqlx::query_as("SELECT staging_key FROM multipart_parts WHERE upload_id = ANY($1)")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await?;
    // Part rows cascade-delete with the upload.
    let deleted = sqlx::query("DELETE FROM multipart_uploads WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(SweptMultipart {
        uploads: deleted.rows_affected(),
        staging_keys: keys.into_iter().map(|(k,)| k).collect(),
    })
}

/// Remove the upload and its part rows, returning staging keys for cleanup.
pub async fn remove_multipart(pool: &PgPool, upload_id: Uuid) -> Result<Vec<String>> {
    let mut tx = pool.begin().await?;
    let keys: Vec<(String,)> =
        sqlx::query_as("SELECT staging_key FROM multipart_parts WHERE upload_id = $1 FOR UPDATE")
            .bind(upload_id)
            .fetch_all(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM multipart_uploads WHERE id = $1")
        .bind(upload_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(keys.into_iter().map(|(k,)| k).collect())
}

// ---- stats / gc ----

pub async fn stats(pool: &PgPool) -> Result<Stats> {
    let (namespace_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM namespaces")
        .fetch_one(pool)
        .await?;
    let (object_count, logical_bytes): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM objects")
            .fetch_one(pool)
            .await?;
    let (blob_count, physical_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM blobs WHERE refcount > 0",
    )
    .fetch_one(pool)
    .await?;
    Ok(Stats {
        namespace_count,
        object_count,
        blob_count,
        logical_bytes,
        physical_bytes,
    })
}

/// Stats restricted to the namespaces owned by `tenant_ids`. Under global
/// dedup a blob shared by two tenants counts toward each tenant's physical
/// footprint, so per-tenant `physical_bytes` summed across tenants can exceed
/// the global figure — it's "the footprint attributable to your data".
pub async fn stats_for_tenants(pool: &PgPool, tenant_ids: &[i64]) -> Result<Stats> {
    let (namespace_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM namespaces WHERE tenant_id = ANY($1)")
            .bind(tenant_ids)
            .fetch_one(pool)
            .await?;
    let (object_count, logical_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(o.size), 0)::BIGINT
         FROM objects o
         JOIN namespaces n ON n.id = o.namespace_id
         WHERE n.tenant_id = ANY($1)",
    )
    .bind(tenant_ids)
    .fetch_one(pool)
    .await?;
    let (blob_count, physical_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(size), 0)::BIGINT FROM (
             SELECT DISTINCT b.hash, b.size
             FROM blobs b
             JOIN objects o ON o.blob_hash = b.hash
             JOIN namespaces n ON n.id = o.namespace_id
             WHERE n.tenant_id = ANY($1)
         ) distinct_blobs",
    )
    .bind(tenant_ids)
    .fetch_one(pool)
    .await?;
    Ok(Stats {
        namespace_count,
        object_count,
        blob_count,
        logical_bytes,
        physical_bytes,
    })
}

/// One GC sweep: delete blobs that have sat at refcount 0 past the grace
/// period. Bytes are deleted while holding the row lock, so `claim_blob`
/// (which contends on the same lock) can never resurrect a half-deleted blob.
pub async fn gc_sweep(
    pool: &PgPool,
    op: &opendal::Operator,
    grace_secs: u64,
    limit: i64,
) -> Result<u64> {
    let mut swept = 0;
    loop {
        let mut tx = pool.begin().await?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT hash FROM blobs
             WHERE refcount = 0 AND updated_at < now() - make_interval(secs => $1)
             LIMIT 1
             FOR UPDATE SKIP LOCKED",
        )
        .bind(grace_secs as f64)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((hash,)) = row else { break };
        op.delete(&crate::storage::blob_path(&hash)).await?;
        sqlx::query("DELETE FROM blobs WHERE hash = $1")
            .bind(&hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        swept += 1;
        if swept >= limit as u64 {
            break;
        }
    }
    Ok(swept)
}
