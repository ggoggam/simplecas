//! S3-compatible gateway (path-style addressing).
//!
//! Supported: ListBuckets, Create/Delete/HeadBucket, GetBucketLocation,
//! ListObjects V1+V2 (prefix/delimiter/pagination), Put/Get/Head/DeleteObject,
//! CopyObject, DeleteObjects (batch), range GETs, and multipart uploads
//! (initiate / upload part / list parts / list uploads / complete / abort).
//!
//! Divergence from AWS: ETags are blake3 hex digests of content, not MD5.
//! Deliberately unsupported: versioning, ACLs/policies, presigned URLs,
//! virtual-host addressing.

mod sigv4;
pub mod xml;

use crate::cas::{self, AppState};
use crate::db;
use crate::error::{Error, Result};
use crate::storage::blob_path;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use base64::Engine;
use chrono::{DateTime, Utc};
use futures::TryStreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

const MAX_XML_BODY: usize = 8 * 1024 * 1024;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_namespaces))
        .route("/{namespace}", any(namespace_dispatch))
        .route("/{namespace}/", any(namespace_dispatch))
        .route("/{namespace}/{*key}", any(object_dispatch))
        .layer(axum::extract::DefaultBodyLimit::disable())
}

fn query_map(parts: &Parts) -> HashMap<String, String> {
    parts
        .uri
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn xml_response(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

fn iso8601(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn http_date(t: &DateTime<Utc>) -> String {
    t.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn quoted_etag(hash: &str) -> String {
    format!("\"{hash}\"")
}

fn valid_namespace_name(name: &str) -> bool {
    let len_ok = (3..=63).contains(&name.len());
    let chars_ok = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let ends_ok = name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.ends_with(|c: char| c.is_ascii_alphanumeric());
    len_ok && chars_ok && ends_ok
}

fn content_type_of(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string()
}

async fn read_xml_body(body: Body) -> Result<String> {
    let bytes = axum::body::to_bytes(body, MAX_XML_BODY)
        .await
        .map_err(|e| Error::MalformedXML(e.to_string()))?;
    String::from_utf8(bytes.to_vec()).map_err(|e| Error::MalformedXML(e.to_string()))
}

/// Single HTTP range (S3 supports one range per request).
/// Returns (start, inclusive_end); malformed headers are ignored per RFC 7233.
fn parse_range(header: &str, size: i64) -> Result<Option<(i64, i64)>> {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((start, end)) = spec.split_once('-') else {
        return Ok(None);
    };
    let (start, end) = match (start.trim(), end.trim()) {
        ("", suffix) => {
            let n: i64 = suffix.parse().map_err(|_| Error::InvalidRange)?;
            if n == 0 {
                return Err(Error::InvalidRange);
            }
            ((size - n).max(0), size - 1)
        }
        (s, "") => (s.parse().map_err(|_| Error::InvalidRange)?, size - 1),
        (s, e) => (
            s.parse().map_err(|_| Error::InvalidRange)?,
            e.parse::<i64>()
                .map_err(|_| Error::InvalidRange)?
                .min(size - 1),
        ),
    };
    if start >= size || start > end || start < 0 {
        return Err(Error::InvalidRange);
    }
    Ok(Some((start, end)))
}

// ---- service level ----

async fn list_namespaces(State(state): State<Arc<AppState>>, req: Request) -> Result<Response> {
    let (parts, _) = req.into_parts();
    sigv4::verify(&parts, &state)?;
    let namespaces = db::list_namespaces(&state.pool).await?;
    let result = xml::ListAllMyBucketsResult {
        xmlns: xml::XMLNS,
        owner: xml::Owner {
            id: "simplecas".into(),
            display_name: "simplecas".into(),
        },
        buckets: xml::Buckets {
            bucket: namespaces
                .into_iter()
                .map(|b| xml::BucketEntry {
                    name: b.name,
                    creation_date: iso8601(&b.created_at),
                })
                .collect(),
        },
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

// ---- namespace level ----

async fn namespace_dispatch(
    State(state): State<Arc<AppState>>,
    Path(namespace): Path<String>,
    req: Request,
) -> Result<Response> {
    let (parts, body) = req.into_parts();
    sigv4::verify(&parts, &state)?;
    let query = query_map(&parts);
    match parts.method {
        Method::PUT => create_namespace(&state, &namespace).await,
        Method::DELETE => {
            db::delete_namespace(&state.pool, &namespace).await?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Method::HEAD => {
            db::get_namespace(&state.pool, &namespace).await?;
            Ok(StatusCode::OK.into_response())
        }
        Method::GET => {
            if query.contains_key("location") {
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LocationConstraint xmlns=\"{}\">{}</LocationConstraint>",
                    xml::XMLNS,
                    state.config.server.region
                );
                return Ok(xml_response(StatusCode::OK, body));
            }
            if query.contains_key("versioning") {
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<VersioningConfiguration xmlns=\"{}\"/>",
                    xml::XMLNS
                );
                return Ok(xml_response(StatusCode::OK, body));
            }
            if query.contains_key("uploads") {
                return list_multipart_uploads(&state, &namespace, &query).await;
            }
            list_objects(&state, &namespace, &query).await
        }
        Method::POST if query.contains_key("delete") => {
            delete_objects(&state, &namespace, body).await
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
}

async fn create_namespace(state: &AppState, namespace: &str) -> Result<Response> {
    if !valid_namespace_name(namespace) {
        return Err(Error::InvalidNamespaceName);
    }
    db::create_namespace(&state.pool, namespace, None).await?;
    Ok((
        [(header::LOCATION, format!("/{namespace}"))],
        StatusCode::OK,
    )
        .into_response())
}

async fn list_objects(
    state: &AppState,
    namespace: &str,
    query: &HashMap<String, String>,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let v2 = query.get("list-type").map(|v| v == "2").unwrap_or(false);
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    let delimiter = match query.get("delimiter").map(String::as_str) {
        None | Some("") => None,
        Some(d) => {
            let mut chars = d.chars();
            let c = chars.next().unwrap();
            if chars.next().is_some() || !c.is_ascii() {
                return Err(Error::InvalidArgument(
                    "only single ASCII character delimiters are supported".into(),
                ));
            }
            Some(c)
        }
    };
    let max_keys: usize = query
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .min(1000);

    let b64 = base64::engine::general_purpose::STANDARD;
    let marker = if v2 {
        if let Some(token) = query.get("continuation-token") {
            String::from_utf8(
                b64.decode(token)
                    .map_err(|_| Error::InvalidArgument("bad continuation-token".into()))?,
            )
            .map_err(|_| Error::InvalidArgument("bad continuation-token".into()))?
        } else {
            query.get("start-after").cloned().unwrap_or_default()
        }
    } else {
        query.get("marker").cloned().unwrap_or_default()
    };

    let listing = db::list_objects(
        &state.pool,
        b.id,
        &prefix,
        delimiter,
        &marker,
        max_keys.max(1),
    )
    .await?;

    let key_count = listing.objects.len() + listing.common_prefixes.len();
    let last_key = listing.objects.last().map(|o| o.key.clone());
    let result = xml::ListBucketResult {
        xmlns: xml::XMLNS,
        name: namespace.to_string(),
        prefix,
        delimiter: delimiter.map(String::from),
        max_keys,
        key_count,
        is_truncated: listing.is_truncated,
        continuation_token: if v2 {
            query.get("continuation-token").cloned()
        } else {
            None
        },
        next_continuation_token: if v2 {
            listing.next_marker.as_ref().map(|m| b64.encode(m))
        } else {
            None
        },
        marker: if v2 { None } else { Some(marker) },
        next_marker: if v2 {
            None
        } else if listing.is_truncated {
            // V1: NextMarker falls back to the last returned key.
            listing.next_marker.clone().or(last_key)
        } else {
            None
        },
        contents: listing
            .objects
            .into_iter()
            .map(|o| xml::Contents {
                key: o.key,
                last_modified: iso8601(&o.updated_at),
                etag: quoted_etag(&o.blob_hash),
                size: o.size,
                storage_class: "STANDARD",
            })
            .collect(),
        common_prefixes: listing
            .common_prefixes
            .into_iter()
            .map(|p| xml::CommonPrefix { prefix: p })
            .collect(),
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

async fn delete_objects(state: &AppState, namespace: &str, body: Body) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let raw = read_xml_body(body).await?;
    let req: xml::Delete =
        quick_xml::de::from_str(&raw).map_err(|e| Error::MalformedXML(e.to_string()))?;
    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for entry in req.objects {
        match db::delete_object(&state.pool, b.id, &entry.key).await {
            // S3 reports missing keys as Deleted too (idempotent delete).
            Ok(_) => deleted.push(xml::DeletedEntry { key: entry.key }),
            Err(e) => errors.push(xml::DeleteErrorEntry {
                key: entry.key,
                code: e.s3_code().to_string(),
                message: e.to_string(),
            }),
        }
    }
    if req.quiet {
        deleted.clear();
    }
    let result = xml::DeleteResult {
        xmlns: xml::XMLNS,
        deleted,
        errors,
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

// ---- object level ----

async fn object_dispatch(
    State(state): State<Arc<AppState>>,
    Path((namespace, key)): Path<(String, String)>,
    req: Request,
) -> Result<Response> {
    let (parts, body) = req.into_parts();
    sigv4::verify(&parts, &state)?;
    let query = query_map(&parts);
    match parts.method {
        Method::PUT => {
            if let (Some(part_number), Some(upload_id)) =
                (query.get("partNumber"), query.get("uploadId"))
            {
                if parts.headers.contains_key("x-amz-copy-source") {
                    return Err(Error::InvalidArgument(
                        "UploadPartCopy is not supported".into(),
                    ));
                }
                upload_part(&state, &namespace, &key, part_number, upload_id, body).await
            } else if parts.headers.contains_key("x-amz-copy-source") {
                copy_object(&state, &namespace, &key, &parts.headers).await
            } else {
                put_object(&state, &namespace, &key, &parts.headers, body).await
            }
        }
        Method::GET => {
            if let Some(upload_id) = query.get("uploadId") {
                list_parts(&state, &namespace, &key, upload_id, &query).await
            } else {
                get_object(&state, &namespace, &key, &parts.headers, false).await
            }
        }
        Method::HEAD => get_object(&state, &namespace, &key, &parts.headers, true).await,
        Method::DELETE => {
            if let Some(upload_id) = query.get("uploadId") {
                abort_multipart(&state, &namespace, &key, upload_id).await
            } else {
                let b = db::get_namespace(&state.pool, &namespace).await?;
                db::delete_object(&state.pool, b.id, &key).await?;
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Method::POST => {
            if query.contains_key("uploads") {
                initiate_multipart(&state, &namespace, &key, &parts.headers).await
            } else if let Some(upload_id) = query.get("uploadId") {
                complete_multipart(&state, &namespace, &key, upload_id, body).await
            } else {
                Ok(StatusCode::METHOD_NOT_ALLOWED.into_response())
            }
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
}

async fn put_object(
    state: &AppState,
    namespace: &str,
    key: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let staged = cas::stage_stream(&state.op, body.into_data_stream()).await?;
    let hash = cas::commit_object(state, b.id, key, &content_type_of(headers), staged).await?;
    Ok(([(header::ETAG, quoted_etag(&hash))], StatusCode::OK).into_response())
}

/// CopyObject: pure metadata operation — the destination claims another
/// reference to the source blob. No bytes are read or written.
async fn copy_object(
    state: &AppState,
    dst_namespace: &str,
    dst_key: &str,
    headers: &HeaderMap,
) -> Result<Response> {
    let source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::InvalidArgument("bad x-amz-copy-source".into()))?;
    let source = percent_encoding::percent_decode_str(source)
        .decode_utf8()
        .map_err(|_| Error::InvalidArgument("bad x-amz-copy-source".into()))?;
    let source = source.trim_start_matches('/');
    let (src_namespace, src_key) = source
        .split_once('/')
        .ok_or_else(|| Error::InvalidArgument("x-amz-copy-source must be bucket/key".into()))?;

    let sb = db::get_namespace(&state.pool, src_namespace).await?;
    let src = db::get_object(&state.pool, sb.id, src_key).await?;
    let db_dst = db::get_namespace(&state.pool, dst_namespace).await?;
    let hash = cas::copy_object(state, &src, db_dst.id, dst_key).await?;
    let now = Utc::now();
    let result = xml::CopyObjectResult {
        xmlns: xml::XMLNS,
        last_modified: iso8601(&now),
        etag: quoted_etag(&hash),
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

pub(crate) async fn get_object(
    state: &AppState,
    namespace: &str,
    key: &str,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let meta = db::get_object(&state.pool, b.id, key).await?;

    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(r) if meta.size > 0 => parse_range(r, meta.size)?,
        Some(_) => None, // zero-byte object: serve whole (empty) body
        None => None,
    };

    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, &meta.content_type)
        .header(header::ETAG, quoted_etag(&meta.blob_hash))
        .header(header::LAST_MODIFIED, http_date(&meta.updated_at))
        .header(header::ACCEPT_RANGES, "bytes")
        .header("x-amz-meta-blake3", &meta.blob_hash);

    let (status, start, end) = match range {
        Some((start, end)) => {
            builder = builder.header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end}/{}", meta.size),
            );
            (StatusCode::PARTIAL_CONTENT, start, end)
        }
        None => (StatusCode::OK, 0, meta.size - 1),
    };
    let len = if meta.size == 0 {
        0
    } else {
        (end - start + 1) as u64
    };
    builder = builder.status(status).header(header::CONTENT_LENGTH, len);

    if head_only || len == 0 {
        return Ok(builder.body(Body::empty()).map_err(anyhow::Error::from)?);
    }
    let reader = state.op.reader(&blob_path(&meta.blob_hash)).await?;
    let stream = reader
        .into_bytes_stream(start as u64..start as u64 + len)
        .await?
        .map_err(std::io::Error::other);
    Ok(builder
        .body(Body::from_stream(stream))
        .map_err(anyhow::Error::from)?)
}

// ---- multipart ----

async fn initiate_multipart(
    state: &AppState,
    namespace: &str,
    key: &str,
    headers: &HeaderMap,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let id = db::create_multipart(&state.pool, b.id, key, &content_type_of(headers)).await?;
    let result = xml::InitiateMultipartUploadResult {
        xmlns: xml::XMLNS,
        bucket: namespace.to_string(),
        key: key.to_string(),
        upload_id: id.to_string(),
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

fn parse_upload_id(upload_id: &str) -> Result<Uuid> {
    Uuid::parse_str(upload_id).map_err(|_| Error::NoSuchUpload)
}

async fn upload_part(
    state: &AppState,
    namespace: &str,
    key: &str,
    part_number: &str,
    upload_id: &str,
    body: Body,
) -> Result<Response> {
    let part_number: i32 = part_number
        .parse()
        .ok()
        .filter(|n| (1..=10_000).contains(n))
        .ok_or_else(|| Error::InvalidArgument("partNumber must be 1-10000".into()))?;
    let b = db::get_namespace(&state.pool, namespace).await?;
    let upload = db::get_multipart(&state.pool, b.id, key, parse_upload_id(upload_id)?).await?;

    // Parts stay in staging under their own hash-of-part etag; dedup happens
    // once at completion when the full object hash is known.
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
    Ok(([(header::ETAG, quoted_etag(&staged.hash))], StatusCode::OK).into_response())
}

async fn list_parts(
    state: &AppState,
    namespace: &str,
    key: &str,
    upload_id: &str,
    query: &HashMap<String, String>,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let upload = db::get_multipart(&state.pool, b.id, key, parse_upload_id(upload_id)?).await?;
    let marker: i32 = query
        .get("part-number-marker")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let max_parts: i64 = query
        .get("max-parts")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let page = db::list_parts_page(&state.pool, upload.id, marker, max_parts).await?;
    let next_marker = if page.is_truncated {
        page.parts.last().map(|p| p.part_number)
    } else {
        None
    };
    let result = xml::ListPartsResult {
        xmlns: xml::XMLNS,
        bucket: namespace.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
        part_number_marker: marker,
        next_part_number_marker: next_marker,
        max_parts,
        is_truncated: page.is_truncated,
        parts: page
            .parts
            .into_iter()
            .map(|p| xml::PartEntry {
                part_number: p.part_number,
                etag: quoted_etag(&p.etag),
                size: p.size,
            })
            .collect(),
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

async fn list_multipart_uploads(
    state: &AppState,
    namespace: &str,
    query: &HashMap<String, String>,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    let max_uploads: i64 = query
        .get("max-uploads")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let uploads = db::list_multipart_uploads(&state.pool, b.id, &prefix, max_uploads).await?;
    let result = xml::ListMultipartUploadsResult {
        xmlns: xml::XMLNS,
        bucket: namespace.to_string(),
        prefix,
        max_uploads,
        is_truncated: false,
        uploads: uploads
            .into_iter()
            .map(|u| xml::UploadEntry {
                key: u.key,
                upload_id: u.id.to_string(),
                initiated: iso8601(&u.created_at),
            })
            .collect(),
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

async fn complete_multipart(
    state: &AppState,
    namespace: &str,
    key: &str,
    upload_id: &str,
    body: Body,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let upload = db::get_multipart(&state.pool, b.id, key, parse_upload_id(upload_id)?).await?;
    let raw = read_xml_body(body).await?;
    let request: xml::CompleteMultipartUpload =
        quick_xml::de::from_str(&raw).map_err(|e| Error::MalformedXML(e.to_string()))?;
    if request.parts.is_empty() {
        return Err(Error::InvalidPart("no parts in request".into()));
    }

    let stored = db::list_parts(&state.pool, upload.id).await?;
    let by_number: HashMap<i32, &db::PartMeta> =
        stored.iter().map(|p| (p.part_number, p)).collect();

    // Validate the client's manifest and assemble parts in the client's
    // (required ascending) order.
    let mut ordered = Vec::with_capacity(request.parts.len());
    let mut last = 0;
    for cp in &request.parts {
        if cp.part_number <= last {
            return Err(Error::InvalidPart("part numbers must be ascending".into()));
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
                )));
            }
        }
        ordered.push(db::PartMeta {
            part_number: part.part_number,
            staging_key: part.staging_key.clone(),
            size: part.size,
            etag: part.etag.clone(),
        });
    }

    let hash = cas::complete_multipart(state, &upload, &ordered).await?;
    let result = xml::CompleteMultipartUploadResult {
        xmlns: xml::XMLNS,
        location: format!("/{namespace}/{key}"),
        bucket: namespace.to_string(),
        key: key.to_string(),
        etag: quoted_etag(&hash),
    };
    Ok(xml_response(StatusCode::OK, xml::render(&result)))
}

async fn abort_multipart(
    state: &AppState,
    namespace: &str,
    key: &str,
    upload_id: &str,
) -> Result<Response> {
    let b = db::get_namespace(&state.pool, namespace).await?;
    let upload = db::get_multipart(&state.pool, b.id, key, parse_upload_id(upload_id)?).await?;
    for staging_key in db::remove_multipart(&state.pool, upload.id).await? {
        let _ = state.op.delete(&staging_key).await;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("bytes=0-4", 10).unwrap(), Some((0, 4)));
        assert_eq!(parse_range("bytes=5-", 10).unwrap(), Some((5, 9)));
        assert_eq!(parse_range("bytes=-3", 10).unwrap(), Some((7, 9)));
        assert_eq!(parse_range("bytes=0-99", 10).unwrap(), Some((0, 9)));
        assert!(parse_range("bytes=10-", 10).is_err());
        assert!(parse_range("bytes=-0", 10).is_err());
        assert_eq!(parse_range("bytes=0-1,3-4", 10).unwrap(), None);
    }

    #[test]
    fn namespace_names() {
        assert!(valid_namespace_name("my-namespace.01"));
        assert!(!valid_namespace_name("ab"));
        assert!(!valid_namespace_name("-bad"));
        assert!(!valid_namespace_name("Bad"));
    }
}
