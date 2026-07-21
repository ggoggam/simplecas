use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub gc: GcConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Region reported in SigV4 scope validation and S3 responses.
    #[serde(default = "default_region")]
    pub region: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            region: default_region(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_pool_size")]
    pub max_connections: u32,
}

/// Storage backend selection. All backends are addressed through OpenDAL, so
/// blobs live under the same logical layout regardless of backend:
///   blobs/<h[0..2]>/<h[2..4]>/<hash>   and   staging/<uuid>
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum StorageConfig {
    Fs {
        root: String,
    },
    S3 {
        bucket: String,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        access_key_id: Option<String>,
        #[serde(default)]
        secret_access_key: Option<String>,
        #[serde(default)]
        root: Option<String>,
    },
    Gcs {
        bucket: String,
        /// Path to a service-account JSON file; omitted = ambient credentials.
        #[serde(default)]
        credential_path: Option<String>,
        #[serde(default)]
        root: Option<String>,
    },
    Azblob {
        container: String,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        account_name: Option<String>,
        #[serde(default)]
        account_key: Option<String>,
        #[serde(default)]
        root: Option<String>,
    },
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::Fs {
            root: "./data".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub secret_access_key: String,
}

/// OIDC single sign-on for the human-facing surface (the PWA at `/ui` and the
/// JSON admin API at `/api`). The S3 gateway keeps its own SigV4 auth — OIDC is
/// a browser flow and does not apply to machine clients.
///
/// Sessions are stateless: on a successful login the server sets an
/// HMAC-signed cookie carrying the identity + expiry, so no session table and
/// no shared state is needed across instances (they only need the same
/// `session_secret`). The provider fields mirror a standard OIDC relying-party
/// registration; discovery is performed at startup and refreshed periodically.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Public base URL of this instance (e.g. `https://cas.example.com`), used
    /// to derive each provider's redirect URI. Required when `enabled`.
    #[serde(default)]
    pub public_url: String,
    /// Secret used to HMAC-sign session and flow-state cookies. Must be shared
    /// by every instance behind the load balancer. Required when `enabled`.
    #[serde(default)]
    pub session_secret: String,
    /// How long a login session stays valid before re-authentication.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// Optional allowlist: if either list is non-empty, a login is accepted
    /// only when the (verified) email matches an entry here. Empty = allow any
    /// identity that authenticates at a configured provider.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_emails: Vec<String>,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
}

/// One external identity provider. Fields mirror hitch's `ProviderConfig`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderConfig {
    /// Stable slug used in the redirect URI and login URLs (e.g. `google`).
    pub id: String,
    /// Human-facing label on the login button; defaults to `id`.
    #[serde(default)]
    pub name: Option<String>,
    /// Issuer URL for OIDC discovery (`<issuer>/.well-known/openid-configuration`).
    pub issuer: String,
    pub client_id: String,
    /// Omitted for public clients (PKCE-only).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Requested scopes; defaults to `["openid", "email", "profile"]`.
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GcConfig {
    #[serde(default = "default_gc_interval")]
    pub interval_secs: u64,
    /// How long a blob may sit at refcount 0 before its bytes are deleted.
    /// Also the expiry for orphaned staging files.
    #[serde(default = "default_gc_grace")]
    pub grace_secs: u64,
    /// How long a multipart upload may go without activity (initiation or a new
    /// part) before it's abandoned and its staged parts reclaimed.
    #[serde(default = "default_multipart_expiry")]
    pub multipart_expiry_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_gc_interval(),
            grace_secs: default_gc_grace(),
            multipart_expiry_secs: default_multipart_expiry(),
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0:9000".to_string()
}
fn default_region() -> String {
    "us-east-1".to_string()
}
fn default_pool_size() -> u32 {
    16
}
fn default_session_ttl() -> u64 {
    86_400
}
fn default_gc_interval() -> u64 {
    60
}
fn default_gc_grace() -> u64 {
    300
}
fn default_multipart_expiry() -> u64 {
    86_400
}

impl Config {
    /// Layered config: simplecas.toml (or $SIMPLECAS_CONFIG), then
    /// SIMPLECAS__ env vars (e.g. SIMPLECAS__DATABASE__URL).
    pub fn load() -> anyhow::Result<Self> {
        let path =
            std::env::var("SIMPLECAS_CONFIG").unwrap_or_else(|_| "simplecas.toml".to_string());
        let config = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("SIMPLECAS__").split("__"))
            .extract()?;
        Ok(config)
    }
}
