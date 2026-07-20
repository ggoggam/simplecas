use crate::config::StorageConfig;
use opendal::{services, Operator};

/// Logical layout inside the backend, identical across fs/S3/GCS/Azure:
///   blobs/<h[0..2]>/<h[2..4]>/<hash>  – content-addressed, immutable
///   staging/<uuid>                    – in-flight uploads and multipart parts
pub fn blob_path(hash: &str) -> String {
    format!("blobs/{}/{}/{}", &hash[0..2], &hash[2..4], hash)
}

pub fn staging_path(id: &uuid::Uuid) -> String {
    format!("staging/{id}")
}

pub fn build_operator(config: &StorageConfig) -> anyhow::Result<Operator> {
    let op = match config {
        StorageConfig::Fs { root } => {
            std::fs::create_dir_all(root)?;
            Operator::new(services::Fs::default().root(root))?.finish()
        }
        StorageConfig::S3 {
            bucket,
            region,
            endpoint,
            access_key_id,
            secret_access_key,
            root,
        } => {
            let mut builder = services::S3::default().bucket(bucket);
            if let Some(region) = region {
                builder = builder.region(region);
            }
            if let Some(endpoint) = endpoint {
                builder = builder.endpoint(endpoint);
            }
            if let Some(ak) = access_key_id {
                builder = builder.access_key_id(ak);
            }
            if let Some(sk) = secret_access_key {
                builder = builder.secret_access_key(sk);
            }
            if let Some(root) = root {
                builder = builder.root(root);
            }
            Operator::new(builder)?.finish()
        }
        StorageConfig::Gcs {
            bucket,
            credential_path,
            root,
        } => {
            let mut builder = services::Gcs::default().bucket(bucket);
            if let Some(path) = credential_path {
                builder = builder.credential_path(path);
            }
            if let Some(root) = root {
                builder = builder.root(root);
            }
            Operator::new(builder)?.finish()
        }
        StorageConfig::Azblob {
            container,
            endpoint,
            account_name,
            account_key,
            root,
        } => {
            let mut builder = services::Azblob::default().container(container);
            if let Some(endpoint) = endpoint {
                builder = builder.endpoint(endpoint);
            }
            if let Some(name) = account_name {
                builder = builder.account_name(name);
            }
            if let Some(key) = account_key {
                builder = builder.account_key(key);
            }
            if let Some(root) = root {
                builder = builder.root(root);
            }
            Operator::new(builder)?.finish()
        }
    };
    Ok(op)
}
