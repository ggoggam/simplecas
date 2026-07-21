//! The content-addressed write path shared by single PUT, multipart
//! completion, and the admin API.
//!
//! Upload protocol (safe with N stateless servers + concurrent GC):
//!   1. Stream the body to `staging/<uuid>` while feeding a blake3 hasher.
//!   2. In one Postgres transaction: `claim_blob` (row-locks the blob,
//!      refcount++ or insert-at-1). If the row is new, copy staging into
//!      `blobs/..` *before* commit so a committed row always has bytes.
//!   3. Upsert the object row (releasing any overwritten blob) and commit.
//!   4. Delete the staging file (best-effort; stale staging is GC'd).
//!
//! Dedup hit cost: one staging write + delete. Simple beats clever here —
//! hash-before-write would need full buffering or a second client roundtrip.

use crate::db;
use crate::error::{Error, Result};
use crate::storage::{blob_path, staging_path};
use bytes::Bytes;
use futures::{Stream, StreamExt};
use opendal::Operator;
use sqlx::PgPool;
use uuid::Uuid;

pub struct AppState {
    pub pool: PgPool,
    pub op: Operator,
    pub config: crate::config::Config,
    /// Present only when OIDC is enabled; guards the `/ui` and `/api` surfaces.
    pub oidc: Option<std::sync::Arc<crate::auth::OidcRegistry>>,
}

pub struct StagedBlob {
    pub staging_key: String,
    pub hash: String,
    pub size: i64,
}

/// Stream `body` into a staging file, hashing as we go.
pub async fn stage_stream<S, E>(op: &Operator, mut body: S) -> Result<StagedBlob>
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    let staging_key = staging_path(&Uuid::new_v4());
    let mut writer = op.writer(&staging_key).await?;
    let mut hasher = blake3::Hasher::new();
    let mut size: i64 = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| Error::InvalidArgument(format!("body read: {e}")))?;
        if chunk.is_empty() {
            continue;
        }
        size += chunk.len() as i64;
        hasher.update(&chunk);
        if let Err(e) = writer.write(chunk).await {
            let _ = writer.abort().await;
            let _ = op.delete(&staging_key).await;
            return Err(e.into());
        }
    }
    writer.close().await?;
    Ok(StagedBlob {
        staging_key,
        hash: hasher.finalize().to_hex().to_string(),
        size,
    })
}

/// Commit a staged blob as `namespace/key`. Returns the blob hash (the ETag).
pub async fn commit_object(
    state: &AppState,
    namespace_id: i64,
    key: &str,
    content_type: &str,
    staged: StagedBlob,
) -> Result<String> {
    let mut tx = state.pool.begin().await?;
    let is_new = db::claim_blob(&mut tx, &staged.hash, staged.size).await?;
    if is_new {
        state
            .op
            .copy(&staged.staging_key, &blob_path(&staged.hash))
            .await?;
    }
    db::upsert_object(
        &mut tx,
        namespace_id,
        key,
        &staged.hash,
        staged.size,
        content_type,
    )
    .await?;
    tx.commit().await?;
    // Staging cleanup is best-effort; orphans expire via the staging sweeper.
    let _ = state.op.delete(&staged.staging_key).await;
    Ok(staged.hash)
}

/// Copy semantics under CAS: no bytes move, just claim another reference.
pub async fn copy_object(
    state: &AppState,
    src: &db::ObjectMeta,
    dst_namespace_id: i64,
    dst_key: &str,
) -> Result<String> {
    let mut tx = state.pool.begin().await?;
    let is_new = db::claim_blob(&mut tx, &src.blob_hash, src.size).await?;
    if is_new {
        // Source blob row vanished between read and claim (GC won the race
        // after the source object was deleted). Without bytes we can't honor
        // the copy.
        tx.rollback().await?;
        return Err(Error::NoSuchKey);
    }
    db::upsert_object(
        &mut tx,
        dst_namespace_id,
        dst_key,
        &src.blob_hash,
        src.size,
        &src.content_type,
    )
    .await?;
    tx.commit().await?;
    Ok(src.blob_hash.clone())
}

/// Dedup "link": point `key` at an already-stored blob without moving bytes.
/// Returns the (hash, size) on success, or `None` if the blob isn't present —
/// letting the caller fall back to a real upload. This is what turns a
/// client-side hash match into a zero-byte upload.
pub async fn link_blob(
    state: &AppState,
    namespace_id: i64,
    key: &str,
    hash: &str,
    content_type: &str,
) -> Result<Option<i64>> {
    let mut tx = state.pool.begin().await?;
    let Some(size) = db::claim_existing_blob(&mut tx, hash).await? else {
        tx.rollback().await?;
        return Ok(None);
    };
    db::upsert_object(&mut tx, namespace_id, key, hash, size, content_type).await?;
    tx.commit().await?;
    Ok(Some(size))
}

/// Concatenate multipart parts into one staged blob (hashing the whole),
/// then commit it like a normal PUT and drop the parts.
pub async fn complete_multipart(
    state: &AppState,
    upload: &db::MultipartUpload,
    parts: &[db::PartMeta],
) -> Result<String> {
    let staging_key = staging_path(&Uuid::new_v4());
    let mut writer = state.op.writer(&staging_key).await?;
    let mut hasher = blake3::Hasher::new();
    let mut size: i64 = 0;
    for part in parts {
        let reader = state.op.reader(&part.staging_key).await?;
        let mut stream = reader.into_bytes_stream(..).await?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| anyhow::anyhow!("part read: {e}"))?;
            size += chunk.len() as i64;
            hasher.update(&chunk);
            if let Err(e) = writer.write(chunk).await {
                let _ = writer.abort().await;
                let _ = state.op.delete(&staging_key).await;
                return Err(e.into());
            }
        }
    }
    writer.close().await?;
    let hash = hasher.finalize().to_hex().to_string();

    let staged = StagedBlob {
        staging_key,
        hash,
        size,
    };
    let etag = commit_object(
        state,
        upload.namespace_id,
        &upload.key,
        &upload.content_type,
        staged,
    )
    .await?;

    for key in db::remove_multipart(&state.pool, upload.id).await? {
        let _ = state.op.delete(&key).await;
    }
    Ok(etag)
}

/// Background loop: refcount-0 blob sweep + stale staging cleanup.
pub async fn gc_loop(state: std::sync::Arc<AppState>) {
    let interval = std::time::Duration::from_secs(state.config.gc.interval_secs.max(5));
    let grace = state.config.gc.grace_secs;
    loop {
        tokio::time::sleep(interval).await;
        match db::gc_sweep(&state.pool, &state.op, grace, 1000).await {
            Ok(n) if n > 0 => tracing::info!(swept = n, "gc: removed unreferenced blobs"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "gc sweep failed"),
        }
        if let Err(e) = sweep_staging(&state, grace).await {
            tracing::warn!(error = %e, "staging sweep failed");
        }
        match db::sweep_multipart(&state.pool, state.config.gc.multipart_expiry_secs).await {
            Ok(swept) if swept.uploads > 0 => {
                for key in &swept.staging_keys {
                    let _ = state.op.delete(key).await;
                }
                tracing::info!(
                    uploads = swept.uploads,
                    parts = swept.staging_keys.len(),
                    "gc: removed abandoned multipart uploads"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "multipart sweep failed"),
        }
    }
}

/// Delete staging files older than the grace period that no live multipart
/// part still references.
async fn sweep_staging(state: &AppState, grace_secs: u64) -> Result<()> {
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(grace_secs as i64);
    let entries = state.op.list("staging/").await?;
    for entry in entries {
        let meta = entry.metadata();
        if !meta.is_file() {
            continue;
        }
        // Backends that don't return last_modified in list results get a
        // stat; if even that lacks a timestamp, skip (never delete eagerly).
        let modified = match meta.last_modified() {
            Some(t) => Some(t),
            None => state
                .op
                .stat(entry.path())
                .await
                .ok()
                .and_then(|m| m.last_modified()),
        };
        let Some(modified) = modified else { continue };
        if modified > cutoff {
            continue;
        }
        let (referenced,): (bool,) =
            sqlx::query_as("SELECT EXISTS(SELECT 1 FROM multipart_parts WHERE staging_key = $1)")
                .bind(entry.path())
                .fetch_one(&state.pool)
                .await?;
        if !referenced {
            let _ = state.op.delete(entry.path()).await;
        }
    }
    Ok(())
}
