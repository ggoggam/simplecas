//! JSON admin API consumed by the bundled PWA. Same core paths as the S3
//! gateway, friendlier wire format.
//!
//! Authorization: when OIDC is enabled the guard middleware attaches the
//! caller's [`Session`] to each request, and every namespace is scoped to the
//! tenant that owns it — a caller sees and touches only namespaces belonging to
//! a tenant they're a member of. Namespaces with no tenant (created via the S3
//! admin plane) are invisible here. When OIDC is disabled there is no caller
//! and the API is the unauthenticated full-access plane it always was — put it
//! behind your ingress auth or bind it privately (see README).

use crate::auth::Session;
use crate::cas::{self, AppState};
use crate::db;
use crate::error::Error;
use axum::body::Body;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
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

/// The signed-in caller, present only when OIDC is enabled (the guard inserts
/// it). Absent = the unauthenticated admin plane.
type Caller = Option<Extension<Arc<Session>>>;

fn sess(caller: &Caller) -> Option<&Session> {
    caller.as_ref().map(|e| e.0.as_ref())
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/stats", get(stats))
        .route("/api/tenants", get(list_tenants).post(create_tenant))
        .route(
            "/api/tenants/{tenant}",
            axum::routing::delete(delete_tenant),
        )
        .route(
            "/api/tenants/{tenant}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/tenants/{tenant}/members/{email}",
            axum::routing::delete(remove_member),
        )
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

// ---------------------------------------------------------------------------
// Authorization helpers
// ---------------------------------------------------------------------------

/// Resolve a namespace, enforcing tenant membership when a caller is present.
/// With no caller (OIDC disabled) any namespace resolves. With a caller, only
/// namespaces owned by a tenant they belong to resolve; everything else —
/// missing, unowned, or another tenant's — is `NoSuchNamespace`, so existence
/// never leaks across tenants.
async fn authorize_namespace(
    state: &AppState,
    caller: Option<&Session>,
    name: &str,
) -> ApiResult<db::Namespace> {
    match caller {
        None => Ok(db::get_namespace(&state.pool, name).await?),
        Some(s) => {
            let email = s.tenant_email().ok_or(Error::NoSuchNamespace)?;
            Ok(db::get_namespace_for_member(&state.pool, name, &email).await?)
        }
    }
}

/// The caller's verified email, or 403 when tenancy can't apply (no signed-in
/// identity, or an unverified/absent email).
fn require_tenant_email(caller: Option<&Session>) -> ApiResult<String> {
    caller
        .and_then(Session::tenant_email)
        .ok_or_else(|| Error::Forbidden("sign-in with a verified email is required".into()).into())
}

/// Resolve a tenant by name and the caller's role in it. Non-members get
/// `NoSuchTenant` (existence hidden); when `need_owner`, a non-owner gets 403.
async fn authorize_tenant(
    state: &AppState,
    caller: Option<&Session>,
    name: &str,
    need_owner: bool,
) -> ApiResult<i64> {
    let email = require_tenant_email(caller)?;
    let tenant_id = db::tenant_id_by_name(&state.pool, name).await?;
    match db::tenant_role(&state.pool, tenant_id, &email).await? {
        None => Err(Error::NoSuchTenant.into()),
        Some(role) => {
            if need_owner && role != "owner" {
                return Err(Error::Forbidden("owner role required".into()).into());
            }
            Ok(tenant_id)
        }
    }
}

/// Shared name rules for tenants and namespaces (S3 bucket-name shape).
fn valid_name(name: &str) -> bool {
    (3..=63).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatsResponse {
    #[serde(flatten)]
    stats: db::Stats,
    dedup_ratio: f64,
    saved_bytes: i64,
}

async fn stats(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> ApiResult<Json<StatsResponse>> {
    let stats = match sess(&caller) {
        Some(s) => {
            let ids = match s.tenant_email() {
                Some(email) => db::tenant_ids_for_email(&state.pool, &email).await?,
                None => Vec::new(),
            };
            db::stats_for_tenants(&state.pool, &ids).await?
        }
        None => db::stats(&state.pool).await?,
    };
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

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TenantJson {
    name: String,
    role: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_tenants(
    State(state): State<Arc<AppState>>,
    caller: Caller,
) -> ApiResult<Json<Vec<TenantJson>>> {
    let email = require_tenant_email(sess(&caller))?;
    let tenants = db::list_tenants_for_email(&state.pool, &email).await?;
    Ok(Json(
        tenants
            .into_iter()
            .map(|t| TenantJson {
                name: t.name,
                role: t.role,
                created_at: t.created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct CreateTenantRequest {
    name: String,
}

async fn create_tenant(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Json(req): Json<CreateTenantRequest>,
) -> ApiResult<StatusCode> {
    let email = require_tenant_email(sess(&caller))?;
    if !valid_name(&req.name) {
        return Err(Error::InvalidTenantName.into());
    }
    db::create_tenant(&state.pool, &req.name, &email).await?;
    Ok(StatusCode::CREATED)
}

async fn delete_tenant(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(tenant): Path<String>,
) -> ApiResult<StatusCode> {
    let tenant_id = authorize_tenant(&state, sess(&caller), &tenant, true).await?;
    db::delete_tenant(&state.pool, tenant_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct MemberJson {
    email: String,
    role: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_members(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(tenant): Path<String>,
) -> ApiResult<Json<Vec<MemberJson>>> {
    let tenant_id = authorize_tenant(&state, sess(&caller), &tenant, false).await?;
    let members = db::list_members(&state.pool, tenant_id).await?;
    Ok(Json(
        members
            .into_iter()
            .map(|m| MemberJson {
                email: m.email,
                role: m.role,
                created_at: m.created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct AddMemberRequest {
    email: String,
    #[serde(default)]
    role: Option<String>,
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(tenant): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<StatusCode> {
    let tenant_id = authorize_tenant(&state, sess(&caller), &tenant, true).await?;
    let email = req.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidArgument("a valid email is required".into()).into());
    }
    let role = match req.role.as_deref() {
        None | Some("member") => "member",
        Some("owner") => "owner",
        Some(_) => {
            return Err(Error::InvalidArgument("role must be 'owner' or 'member'".into()).into())
        }
    };
    db::add_member(&state.pool, tenant_id, &email, role).await?;
    Ok(StatusCode::CREATED)
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path((tenant, email)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let tenant_id = authorize_tenant(&state, sess(&caller), &tenant, true).await?;
    db::remove_member(&state.pool, tenant_id, &email.trim().to_ascii_lowercase()).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct NamespaceJson {
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct NamespaceListQuery {
    /// Restrict to one team's namespaces (name). Requires membership. When
    /// omitted, all of the caller's teams' namespaces are returned.
    #[serde(default)]
    tenant: Option<String>,
}

async fn list_namespaces(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Query(q): Query<NamespaceListQuery>,
) -> ApiResult<Json<Vec<NamespaceJson>>> {
    let namespaces = match sess(&caller) {
        Some(s) => match q.tenant.as_deref() {
            Some(tenant) => {
                let tenant_id = authorize_tenant(&state, sess(&caller), tenant, false).await?;
                db::list_namespaces_for_tenants(&state.pool, &[tenant_id]).await?
            }
            None => {
                let ids = match s.tenant_email() {
                    Some(email) => db::tenant_ids_for_email(&state.pool, &email).await?,
                    None => Vec::new(),
                };
                db::list_namespaces_for_tenants(&state.pool, &ids).await?
            }
        },
        None => db::list_namespaces(&state.pool).await?,
    };
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
    /// The owning tenant (name). Required when signed in; ignored on the
    /// unauthenticated admin plane, where namespaces are created unowned.
    #[serde(default)]
    tenant: Option<String>,
}

async fn create_namespace(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Json(req): Json<CreateNamespaceRequest>,
) -> ApiResult<StatusCode> {
    if !valid_name(&req.name) {
        return Err(Error::InvalidNamespaceName.into());
    }
    let tenant_id = match sess(&caller) {
        Some(_) => {
            let tenant = req
                .tenant
                .as_deref()
                .ok_or_else(|| Error::InvalidArgument("tenant is required".into()))?;
            Some(authorize_tenant(&state, sess(&caller), tenant, false).await?)
        }
        None => None,
    };
    db::create_namespace(&state.pool, &req.name, tenant_id).await?;
    Ok(StatusCode::CREATED)
}

async fn delete_namespace(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path(namespace): Path<String>,
) -> ApiResult<StatusCode> {
    authorize_namespace(&state, sess(&caller), &namespace).await?;
    db::delete_namespace(&state.pool, &namespace).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Objects
// ---------------------------------------------------------------------------

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
    caller: Caller,
    Path(namespace): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<ListResponse>> {
    let b = authorize_namespace(&state, sess(&caller), &namespace).await?;
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
    caller: Caller,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let q = parse_query(raw);
    let b = authorize_namespace(&state, sess(&caller), &namespace).await?;
    if let (Some(upload_id), Some(part_number)) = (q.get("uploadId"), q.get("partNumber")) {
        return upload_part(&state, &b, &key, upload_id, part_number, body).await;
    }
    if let Some(hash) = q.get("link") {
        return link_object(&state, &b, &key, hash, &headers).await;
    }
    let content_type = resolve_content_type(&headers, &key);
    let staged = cas::stage_stream(&state.op, body.into_data_stream()).await?;
    let size = staged.size;
    let etag = cas::commit_object(&state, b.id, &key, &content_type, staged).await?;
    Ok(Json(json!({ "key": key, "etag": etag, "size": size })).into_response())
}

/// Link `key` to an already-stored blob without transferring bytes. Responds
/// `{ linked: true, ... }` on a dedup hit, or `{ linked: false }` when the blob
/// isn't present (or isn't visible to this tenant) so the client uploads it.
async fn link_object(
    state: &AppState,
    b: &db::Namespace,
    key: &str,
    hash: &str,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let content_type = resolve_content_type(headers, key);
    match cas::link_blob(state, b.id, key, hash, &content_type, b.tenant_id).await? {
        Some(size) => Ok(
            Json(json!({ "linked": true, "key": key, "etag": hash, "size": size })).into_response(),
        ),
        None => Ok(Json(json!({ "linked": false })).into_response()),
    }
}

async fn upload_part(
    state: &AppState,
    b: &db::Namespace,
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
    caller: Caller,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    let q = parse_query(raw);
    let b = authorize_namespace(&state, sess(&caller), &namespace).await?;
    if q.contains_key("uploads") {
        let content_type = resolve_content_type(&headers, &key);
        let id = db::create_multipart(&state.pool, b.id, &key, &content_type).await?;
        return Ok(Json(json!({ "upload_id": id })).into_response());
    }
    if let Some(upload_id) = q.get("uploadId") {
        return complete_multipart(&state, &b, &key, upload_id, body).await;
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
    b: &db::Namespace,
    key: &str,
    upload_id: &str,
    body: Body,
) -> ApiResult<Response> {
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
    caller: Caller,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let q = parse_query(raw);
    let b = authorize_namespace(&state, sess(&caller), &namespace).await?;
    if let Some(upload_id) = q.get("uploadId") {
        let upload =
            db::get_multipart(&state.pool, b.id, &key, parse_upload_id(upload_id)?).await?;
        let parts = db::list_parts(&state.pool, upload.id).await?;
        let parts: Vec<_> = parts
            .into_iter()
            .map(|p| json!({ "part_number": p.part_number, "etag": p.etag, "size": p.size }))
            .collect();
        return Ok(Json(json!({ "parts": parts })).into_response());
    }
    // Namespace already authorized above; get_object re-resolves it by name.
    Ok(crate::s3::get_object(&state, &namespace, &key, &headers, false).await?)
}

/// DELETE dispatch: abort an in-progress upload (`?uploadId`) or delete the
/// object.
async fn delete_object(
    State(state): State<Arc<AppState>>,
    caller: Caller,
    Path((namespace, key)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<StatusCode> {
    let q = parse_query(raw);
    let b = authorize_namespace(&state, sess(&caller), &namespace).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_rules() {
        // shared by tenants and namespaces
        assert!(valid_name("team-a.01"));
        assert!(valid_name("abc"));
        assert!(!valid_name("ab")); // too short
        assert!(!valid_name("-bad")); // must start alphanumeric
        assert!(!valid_name("bad-")); // must end alphanumeric
        assert!(!valid_name("Bad")); // no uppercase
        assert!(!valid_name(&"a".repeat(64))); // too long
    }
}
