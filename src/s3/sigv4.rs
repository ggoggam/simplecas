//! AWS Signature Version 4 verification (adapted from openxet's gateway).
//!
//! Header-signed requests only (`Authorization: AWS4-HMAC-SHA256 …`);
//! presigned-URL query auth and POST-policy uploads are rejected rather than
//! half-supported. The payload hash comes from `x-amz-content-sha256` as sent
//! (streaming uploads use UNSIGNED-PAYLOAD), so no body buffering.
//!
//! When `auth.enabled` is false the check is skipped entirely, so
//! `aws s3 --no-sign-request` and the PWA work against a dev instance.

use crate::cas::AppState;
use crate::error::Error;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

struct AuthHeader {
    access_key_id: String,
    date_stamp: String,
    region: String,
    service: String,
    signed_headers: String,
    signature: String,
}

fn parse_auth_header(value: &str) -> Option<AuthHeader> {
    let rest = value.strip_prefix("AWS4-HMAC-SHA256")?.trim_start();
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        match k {
            "Credential" => credential = Some(v.to_string()),
            "SignedHeaders" => signed_headers = Some(v.to_string()),
            "Signature" => signature = Some(v.to_string()),
            _ => {}
        }
    }
    // Credential = AKID/date/region/service/aws4_request
    let credential = credential?;
    let mut scope = credential.splitn(5, '/');
    let access_key_id = scope.next()?.to_string();
    let date_stamp = scope.next()?.to_string();
    let region = scope.next()?.to_string();
    let service = scope.next()?.to_string();
    if scope.next()? != "aws4_request" {
        return None;
    }
    Some(AuthHeader {
        access_key_id,
        date_stamp,
        region,
        service,
        signed_headers: signed_headers?,
        signature: signature?,
    })
}

/// RFC 3986 encoding per AWS canonical rules: unreserved characters pass
/// through, everything else percent-encoded uppercase. `/` is preserved in
/// path context and encoded in query context.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn canonical_query_string(query: Option<&str>) -> String {
    let Some(query) = query else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (uri_encode(&k, true), uri_encode(&v, true)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_header_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

#[allow(clippy::too_many_arguments)]
fn compute_signature(
    secret: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    signed_headers: &str,
    canonical_headers: &str,
    hashed_payload: &str,
    amz_date: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> String {
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
    );
    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret, date_stamp, region, service);
    hex::encode(hmac(&key, string_to_sign.as_bytes()))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |r, (x, y)| r | (x ^ y)) == 0
}

fn build_canonical_headers(headers: &HeaderMap, signed_headers: &str) -> Option<String> {
    let mut out = String::new();
    for name in signed_headers.split(';') {
        let value = headers.get(name)?.to_str().ok()?;
        out.push_str(name);
        out.push(':');
        out.push_str(&canonical_header_value(value));
        out.push('\n');
    }
    Some(out)
}

/// Verify the request signature against the configured credential. Call from
/// every S3 handler with the request `Parts`.
pub fn verify(parts: &Parts, state: &AppState) -> Result<(), Error> {
    let auth = &state.config.auth;
    if !auth.enabled {
        return Ok(());
    }
    let auth_value = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::AccessDenied)?;
    if !auth_value.starts_with("AWS4-HMAC-SHA256") {
        return Err(Error::AccessDenied);
    }
    let parsed = parse_auth_header(auth_value).ok_or(Error::AccessDenied)?;
    if parsed.access_key_id != auth.access_key_id {
        return Err(Error::AccessDenied);
    }
    let amz_date = parts
        .headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::AccessDenied)?;
    let hashed_payload = parts
        .headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");
    let canonical_headers = build_canonical_headers(&parts.headers, &parsed.signed_headers)
        .ok_or(Error::SignatureDoesNotMatch)?;

    let expected = compute_signature(
        &auth.secret_access_key,
        parts.method.as_str(),
        parts.uri.path(),
        &canonical_query_string(parts.uri.query()),
        &parsed.signed_headers,
        &canonical_headers,
        hashed_payload,
        amz_date,
        &parsed.date_stamp,
        &parsed.region,
        &parsed.service,
    );
    if !ct_eq(expected.as_bytes(), parsed.signature.as_bytes()) {
        return Err(Error::SignatureDoesNotMatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's published "GET Object" SigV4 example (docs.aws.amazon.com,
    /// "Authenticating Requests: Using the Authorization Header").
    #[test]
    fn aws_get_object_vector() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let canonical_headers = format!(
            "host:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n\
             x-amz-content-sha256:{empty_hash}\nx-amz-date:20130524T000000Z\n"
        );
        let sig = compute_signature(
            secret,
            "GET",
            "/test.txt",
            "",
            "host;range;x-amz-content-sha256;x-amz-date",
            &canonical_headers,
            empty_hash,
            "20130524T000000Z",
            "20130524",
            "us-east-1",
            "s3",
        );
        assert_eq!(
            sig,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn canonical_query_sorts_and_encodes() {
        assert_eq!(
            canonical_query_string(Some("prefix=foo/bar&list-type=2")),
            "list-type=2&prefix=foo%2Fbar"
        );
    }
}
