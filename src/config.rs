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
