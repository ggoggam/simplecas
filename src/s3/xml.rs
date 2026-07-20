//! S3 XML wire types. Serialized with quick-xml's serde support; field names
//! match the S3 API spec exactly.

use serde::{Deserialize, Serialize};

pub const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

pub fn render<T: Serialize>(value: &T) -> String {
    let body = quick_xml::se::to_string(value).unwrap_or_default();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}")
}

// ---- ListBuckets ----

#[derive(Serialize)]
#[serde(rename = "ListAllMyBucketsResult")]
pub struct ListAllMyBucketsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Owner")]
    pub owner: Owner,
    #[serde(rename = "Buckets")]
    pub buckets: Buckets,
}

#[derive(Serialize)]
pub struct Owner {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
}

#[derive(Serialize)]
pub struct Buckets {
    #[serde(rename = "Bucket")]
    pub bucket: Vec<BucketEntry>,
}

#[derive(Serialize)]
pub struct BucketEntry {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
}

// ---- ListObjects (V1 + V2 share this shape) ----

#[derive(Serialize)]
#[serde(rename = "ListBucketResult")]
pub struct ListBucketResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "Delimiter", skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<String>,
    #[serde(rename = "MaxKeys")]
    pub max_keys: usize,
    #[serde(rename = "KeyCount")]
    pub key_count: usize,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "ContinuationToken", skip_serializing_if = "Option::is_none")]
    pub continuation_token: Option<String>,
    #[serde(
        rename = "NextContinuationToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_continuation_token: Option<String>,
    #[serde(rename = "Marker", skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    #[serde(rename = "NextMarker", skip_serializing_if = "Option::is_none")]
    pub next_marker: Option<String>,
    #[serde(rename = "Contents")]
    pub contents: Vec<Contents>,
    #[serde(rename = "CommonPrefixes")]
    pub common_prefixes: Vec<CommonPrefix>,
}

#[derive(Serialize)]
pub struct Contents {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: i64,
    #[serde(rename = "StorageClass")]
    pub storage_class: &'static str,
}

#[derive(Serialize)]
pub struct CommonPrefix {
    #[serde(rename = "Prefix")]
    pub prefix: String,
}

// ---- CopyObject ----

#[derive(Serialize)]
#[serde(rename = "CopyObjectResult")]
pub struct CopyObjectResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "LastModified")]
    pub last_modified: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

// ---- Multipart ----

#[derive(Serialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
pub struct InitiateMultipartUploadResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
}

#[derive(Serialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
pub struct CompleteMultipartUploadResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Location")]
    pub location: String,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "ETag")]
    pub etag: String,
}

#[derive(Serialize)]
#[serde(rename = "ListPartsResult")]
pub struct ListPartsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "PartNumberMarker")]
    pub part_number_marker: i32,
    #[serde(
        rename = "NextPartNumberMarker",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_part_number_marker: Option<i32>,
    #[serde(rename = "MaxParts")]
    pub max_parts: i64,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Part")]
    pub parts: Vec<PartEntry>,
}

// ---- ListMultipartUploads ----

#[derive(Serialize)]
#[serde(rename = "ListMultipartUploadsResult")]
pub struct ListMultipartUploadsResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Bucket")]
    pub bucket: String,
    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "MaxUploads")]
    pub max_uploads: i64,
    #[serde(rename = "IsTruncated")]
    pub is_truncated: bool,
    #[serde(rename = "Upload")]
    pub uploads: Vec<UploadEntry>,
}

#[derive(Serialize)]
pub struct UploadEntry {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "UploadId")]
    pub upload_id: String,
    #[serde(rename = "Initiated")]
    pub initiated: String,
}

#[derive(Serialize)]
pub struct PartEntry {
    #[serde(rename = "PartNumber")]
    pub part_number: i32,
    #[serde(rename = "ETag")]
    pub etag: String,
    #[serde(rename = "Size")]
    pub size: i64,
}

#[derive(Debug, Deserialize)]
pub struct CompleteMultipartUpload {
    #[serde(rename = "Part", default)]
    pub parts: Vec<CompletePart>,
}

#[derive(Debug, Deserialize)]
pub struct CompletePart {
    #[serde(rename = "PartNumber")]
    pub part_number: i32,
    #[serde(rename = "ETag", default)]
    pub etag: Option<String>,
}

// ---- DeleteObjects ----

#[derive(Debug, Deserialize)]
pub struct Delete {
    #[serde(rename = "Object", default)]
    pub objects: Vec<DeleteObjectEntry>,
    #[serde(rename = "Quiet", default)]
    pub quiet: bool,
}

#[derive(Debug, Deserialize)]
pub struct DeleteObjectEntry {
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Serialize)]
#[serde(rename = "DeleteResult")]
pub struct DeleteResult {
    #[serde(rename = "@xmlns")]
    pub xmlns: &'static str,
    #[serde(rename = "Deleted")]
    pub deleted: Vec<DeletedEntry>,
    #[serde(rename = "Error")]
    pub errors: Vec<DeleteErrorEntry>,
}

#[derive(Serialize)]
pub struct DeletedEntry {
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Serialize)]
pub struct DeleteErrorEntry {
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Message")]
    pub message: String,
}
