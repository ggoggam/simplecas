use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Error type shared by the S3 gateway and admin API. Each variant carries an
/// S3 error code so the XML layer can render spec-shaped errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("namespace not found")]
    NoSuchNamespace,
    #[error("object not found")]
    NoSuchKey,
    #[error("multipart upload not found")]
    NoSuchUpload,
    #[error("namespace already exists")]
    NamespaceAlreadyExists,
    #[error("namespace is not empty")]
    NamespaceNotEmpty,
    #[error("invalid namespace name")]
    InvalidNamespaceName,
    #[error("tenant not found")]
    NoSuchTenant,
    #[error("tenant already exists")]
    TenantAlreadyExists,
    #[error("tenant still has namespaces")]
    TenantNotEmpty,
    #[error("invalid tenant name")]
    InvalidTenantName,
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    InvalidArgument(String),
    #[error("invalid part: {0}")]
    InvalidPart(String),
    #[error("requested range not satisfiable")]
    InvalidRange,
    #[error("access denied")]
    AccessDenied,
    #[error("signature mismatch")]
    SignatureDoesNotMatch,
    #[error("malformed request: {0}")]
    MalformedXML(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Storage(#[from] opendal::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    pub fn s3_code(&self) -> &'static str {
        match self {
            // S3 wire error codes: the gateway exposes namespaces as S3
            // buckets, so these strings stay the S3-spec bucket codes.
            Error::NoSuchNamespace => "NoSuchBucket",
            Error::NoSuchKey => "NoSuchKey",
            Error::NoSuchUpload => "NoSuchUpload",
            Error::NamespaceAlreadyExists => "BucketAlreadyOwnedByYou",
            Error::NamespaceNotEmpty => "BucketNotEmpty",
            Error::InvalidNamespaceName => "InvalidBucketName",
            Error::NoSuchTenant => "NoSuchTenant",
            Error::TenantAlreadyExists => "TenantAlreadyExists",
            Error::TenantNotEmpty => "TenantNotEmpty",
            Error::InvalidTenantName => "InvalidTenantName",
            Error::Forbidden(_) => "AccessDenied",
            Error::InvalidArgument(_) => "InvalidArgument",
            Error::InvalidPart(_) => "InvalidPart",
            Error::InvalidRange => "InvalidRange",
            Error::AccessDenied => "AccessDenied",
            Error::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Error::MalformedXML(_) => "MalformedXML",
            Error::Db(_) | Error::Storage(_) | Error::Other(_) => "InternalError",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Error::NoSuchNamespace | Error::NoSuchKey | Error::NoSuchUpload => {
                StatusCode::NOT_FOUND
            }
            Error::NoSuchTenant => StatusCode::NOT_FOUND,
            Error::NamespaceAlreadyExists
            | Error::NamespaceNotEmpty
            | Error::TenantAlreadyExists
            | Error::TenantNotEmpty => StatusCode::CONFLICT,
            Error::InvalidNamespaceName
            | Error::InvalidTenantName
            | Error::InvalidArgument(_)
            | Error::InvalidPart(_)
            | Error::MalformedXML(_) => StatusCode::BAD_REQUEST,
            Error::InvalidRange => StatusCode::RANGE_NOT_SATISFIABLE,
            Error::AccessDenied | Error::SignatureDoesNotMatch | Error::Forbidden(_) => {
                StatusCode::FORBIDDEN
            }
            Error::Db(_) | Error::Storage(_) | Error::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// S3-style XML error body. The admin API wraps this into JSON instead.
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if matches!(self, Error::Db(_) | Error::Storage(_) | Error::Other(_)) {
            tracing::error!(error = %self, "internal error");
        }
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message></Error>",
            self.s3_code(),
            quick_xml::escape::escape(self.to_string().as_str()),
        );
        (self.status(), [("content-type", "application/xml")], body).into_response()
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
