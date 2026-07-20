//! JSON admin API consumed by the bundled PWA. Same core paths as the S3
//! gateway, friendlier wire format. Unauthenticated by design — see README
//! ("put it behind your ingress auth or bind it privately").

use crate::cas::{self, AppState};
use crate::db;
use crate::error::Error;
use axum::body::Body;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// JSON rendering of crate::error::Error (the S3 layer renders XML instead).
pub struct ApiError(Error);

impl<E: Into<Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.0.status();
        if status.is_server_error() {
            tracing::error!(error = %self.0, "admin api error");
        }
        (
            status,
            Json(serde_json::json!({ "code": self.0.s3_code(), "message": self.0.to_string() })),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/stats", get(stats))
        .route(
            "/api/namespaces",
            get(list_namespaces).post(create_namespace),
        )
        .route(
            "/api/namespaces/{namespace}",
            axum::routing::delete(delete_namespace),
        )
        .route("/api/namespaces/{namespace}/objects", get(list_objects))
        .route(
            "/api/namespaces/{namespace}/objects/{*key}",
            get(download)
                .put(upload)
                .post(post_object)
                .delete(delete_object),
        )
        .layer(axum::extract::DefaultBodyLimit::disable())
}

#[derive(Serialize)]
struct StatsResponse {
    #[serde(flatten)]
    stats: db::Stats,
    dedup_ratio: f64,
    saved_bytes: i64,
}

async fn stats(State(state): State<Arc<AppState>>) -> ApiResult<Json<StatsResponse>> {
    let stats = db::stats(&state.pool).await?;
    let dedup_ratio = if stats.physical_bytes > 0 {
        stats.logical_bytes as f64 / stats.physical_bytes as f64
    } else {
        1.0
    };
    let saved_bytes = stats.logical_bytes - stats.physical_bytes;
    Ok(Json(StatsResponse {
        stats,
        dedup_ratio,
        saved_bytes,
    }))
}

#[derive(Serialize)]
struct NamespaceJson {
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_namespaces(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<NamespaceJson>>> {
    let namespaces = db::list_namespaces(&state.pool).await?;
    Ok(Json(
        namespaces
            .into_iter()
            .map(|b| NamespaceJson {
                name: b.name,
                created_at: b.created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct CreateNamespaceRequest {
    name: String,
}

async fn create_namespace(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateNamespaceRequest>,
) -> ApiResult<StatusCode> {
    if req.name.len() < 3
        || req.name.len() > 63
        || !req.name.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !req.name.ends_with(|c: char| c.is_ascii_alphanumeric())
        || !req
            .name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(Error::InvalidNamespaceName.into());
    }
    db::create_namespace(&state.pool, &req.name).await?;
    Ok(StatusCode::CREATED)
}

async fn delete_namespace(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
) -> ApiResult<StatusCode> {
    db::delete_namespace(&state.pool, &namespace).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    delimiter: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    max: Option<usize>,
}

#[derive(Serialize)]
struct ObjectJson {
    key: String,
    size: i64,
    etag: String,
    content_type: String,
    last_modified: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct ListResponse {
    objects: Vec<ObjectJson>,
    common_prefixes: Vec<String>,
    next_token: Option<String>,
}

async fn list_objects(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListResponse>> {
    let b = db::get_namespace(&state.pool, &namespace).await?;
    let delimiter = match q.delimiter.as_deref() {
        None | Some("") => None,
        Some(d) if d.len() == 1 && d.is_ascii() => d.chars().next(),
        Some(_) => {
            return Err(Error::InvalidArgument("delimiter must be one ASCII char".into()).into())
        }
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let marker = match &q.token {
        Some(t) => String::from_utf8(
            b64.decode(t)
                .map_err(|_| Error::InvalidArgument("bad token".into()))?,
        )
        .map_err(|_| Error::InvalidArgument("bad token".into()))?,
        None => String::new(),
    };
    let listing = db::list_objects(
        &state.pool,
        b.id,
        &q.prefix,
        delimiter,
        &marker,
        q.max.unwrap_or(500).clamp(1, 1000),
    )
    .await?;
    Ok(Json(ListResponse {
        objects: listing
            .objects
            .into_iter()
            .map(|o| ObjectJson {
                key: o.key,
                size: o.size,
                etag: o.blob_hash,
                content_type: o.content_type,
                last_modified: o.updated_at,
            })
            .collect(),
        common_prefixes: listing.common_prefixes,
        next_token: listing.next_marker.map(|m| b64.encode(m)),
    }))
}

fn parse_query(raw: Option<String>) -> HashMap<String, String> {
    raw.map(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    })
    .unwrap_or_default()
}

fn resolve_content_type(headers: &HeaderMap, key: &str) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            mime_guess::from_path(key)
                .first_or_octet_stream()
                .essence_str()
                .to_string()
        })
}

fn parse_upload_id(upload_id: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(upload_id).map_err(|_| Error::NoSuchUpload)
}

/// PUT dispatch: upload a part (`?uploadId&partNumber`), link an existing blob
/// by hash (`?link=<hash>`, empty body — the dedup fast path), or a plain
/// whole-object upload.
async fn upload(
    State(state): State<Arc<AppState>>,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let q = parse_query(raw);
    if let (Some(upload_id), Some(part_number)) = (q.get("uploadId"), q.get("partNumber")) {
        return upload_part(&state, &namespace, &key, upload_id, part_number, body).await;
    }
    if let Some(hash) = q.get("link") {
        return link_object(&state, &namespace, &key, hash, &headers).await;
    }
    let b = db::get_namespace(&state.pool, &namespace).await?;
    let content_type = resolve_content_type(&headers, &key);
    let staged = cas::stage_stream(&state.op, body.into_data_stream()).await?;
    let size = staged.size;
    let etag = cas::commit_object(&state, b.id, &key, &content_type, staged).await?;
    Ok(Json(json!({ "key": key, "etag": etag, "size": size })).into_response())
}

/// Link `key` to an already-stored blob without transferring bytes. Responds
/// `{ linked: true, ... }` on a dedup hit, or `{ linked: false }` when the blob
/// isn't present so the client uploads it for real.
async fn link_object(
    state: &AppState,
    namespace: &str,
    key: &str,
    hash: &str,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let content_type = resolve_content_type(headers, key);
    match cas::link_blob(state, b.id, key, hash, &content_type).await? {
        Some(size) => Ok(
            Json(json!({ "linked": true, "key": key, "etag": hash, "size": size })).into_response(),
        ),
        None => Ok(Json(json!({ "linked": false })).into_response()),
    }
}

async fn upload_part(
    state: &AppState,
    namespace: &str,
    key: &str,
    upload_id: &str,
    part_number: &str,
    body: Body,
) -> ApiResult<Response> {
    let part_number: i32 = part_number
        .parse()
        .ok()
        .filter(|n| (1..=10_000).contains(n))
        .ok_or_else(|| Error::InvalidArgument("partNumber must be 1-10000".into()))?;
    let b = db::get_namespace(&state.pool, namespace).await?;
    let upload = db::get_multipart(&state.pool, b.id, key, parse_upload_id(upload_id)?).await?;
    let staged = cas::stage_stream(&state.op, body.into_data_stream()).await?;
    let old = db::put_part(
        &state.pool,
        upload.id,
        part_number,
        &staged.staging_key,
        staged.size,
        &staged.hash,
    )
    .await?;
    if let Some(old_key) = old {
        let _ = state.op.delete(&old_key).await;
    }
    Ok(Json(json!({ "part_number": part_number, "etag": staged.hash })).into_response())
}

/// POST dispatch: initiate a multipart upload (`?uploads`) or complete one
/// (`?uploadId`, with a JSON manifest body).
async fn post_object(
    State(state): State<Arc<AppState>>,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let q = parse_query(raw);
    if q.contains_key("uploads") {
        let b = db::get_namespace(&state.pool, &namespace).await?;
        let content_type = resolve_content_type(&headers, &key);
        let id = db::create_multipart(&state.pool, b.id, &key, &content_type).await?;
        return Ok(Json(json!({ "upload_id": id })).into_response());
    }
    if let Some(upload_id) = q.get("uploadId") {
        return complete_multipart(&state, &namespace, &key, upload_id, body).await;
    }
    Err(Error::InvalidArgument("missing ?uploads or ?uploadId".into()).into())
}

#[derive(Deserialize)]
struct CompleteRequest {
    parts: Vec<CompletePartJson>,
}

#[derive(Deserialize)]
struct CompletePartJson {
    part_number: i32,
    #[serde(default)]
    etag: Option<String>,
}

async fn complete_multipart(
    state: &AppState,
    namespace: &str,
    key: &str,
    upload_id: &str,
    body: Body,
) -> ApiResult<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let upload = db::get_multipart(&state.pool, b.id, key, parse_upload_id(upload_id)?).await?;
    let bytes = axum::body::to_bytes(body, 8 * 1024 * 1024)
        .await
        .map_err(|e| Error::InvalidArgument(e.to_string()))?;
    let req: CompleteRequest =
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidArgument(e.to_string()))?;
    if req.parts.is_empty() {
        return Err(Error::InvalidPart("no parts in request".into()).into());
    }

    let stored = db::list_parts(&state.pool, upload.id).await?;
    let by_number: HashMap<i32, &db::PartMeta> =
        stored.iter().map(|p| (p.part_number, p)).collect();

    let mut ordered = Vec::with_capacity(req.parts.len());
    let mut last = 0;
    for cp in &req.parts {
        if cp.part_number <= last {
            return Err(Error::InvalidPart("part numbers must be ascending".into()).into());
        }
        last = cp.part_number;
        let part = by_number
            .get(&cp.part_number)
            .ok_or_else(|| Error::InvalidPart(format!("part {} not uploaded", cp.part_number)))?;
        if let Some(etag) = &cp.etag {
            if etag.trim_matches('"') != part.etag {
                return Err(Error::InvalidPart(format!(
                    "etag mismatch on part {}",
                    cp.part_number
                ))
                .into());
            }
        }
        ordered.push(db::PartMeta {
            part_number: part.part_number,
            staging_key: part.staging_key.clone(),
            size: part.size,
            etag: part.etag.clone(),
        });
    }

    let size: i64 = ordered.iter().map(|p| p.size).sum();
    let etag = cas::complete_multipart(state, &upload, &ordered).await?;
    Ok(Json(json!({ "key": key, "etag": etag, "size": size })).into_response())
}

/// GET dispatch: list the parts of an in-progress upload (`?uploadId`, used to
/// resume) or download the object.
async fn download(
    State(state): State<Arc<AppState>>,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let q = parse_query(raw);
    if let Some(upload_id) = q.get("uploadId") {
        let b = db::get_namespace(&state.pool, &namespace).await?;
        let upload =
            db::get_multipart(&state.pool, b.id, &key, parse_upload_id(upload_id)?).await?;
        let parts = db::list_parts(&state.pool, upload.id).await?;
        let parts: Vec<_> = parts
            .into_iter()
            .map(|p| json!({ "part_number": p.part_number, "etag": p.etag, "size": p.size }))
            .collect();
        return Ok(Json(json!({ "parts": parts })).into_response());
    }
    Ok(crate::s3::get_object(&state, &namespace, &key, &headers, false).await?)
}

/// DELETE dispatch: abort an in-progress upload (`?uploadId`) or delete the
/// object.
async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<StatusCode> {
    let q = parse_query(raw);
    let b = db::get_namespace(&state.pool, &namespace).await?;
    if let Some(upload_id) = q.get("uploadId") {
        let upload =
            db::get_multipart(&state.pool, b.id, &key, parse_upload_id(upload_id)?).await?;
        for staging_key in db::remove_multipart(&state.pool, upload.id).await? {
            let _ = state.op.delete(&staging_key).await;
        }
        return Ok(StatusCode::NO_CONTENT);
    }
    db::delete_object(&state.pool, b.id, &key).await?;
    Ok(StatusCode::NO_CONTENT)
}
