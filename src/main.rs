mod api;
mod cas;
mod config;
mod db;
mod error;
mod s3;
mod storage;
mod ui;

use cas::AppState;
use std::sync::Arc;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "simplecas=info,tower_http=info".into()),
        )
        .init();

    let config = config::Config::load()?;
    let pool = db::connect(&config.database.url, config.database.max_connections).await?;
    let op = storage::build_operator(&config.storage)?;
    // Fail fast on unusable backend credentials/paths.
    op.check().await?;

    let bind = config.server.bind.clone();
    let state = Arc::new(AppState { pool, op, config });

    tokio::spawn(cas::gc_loop(state.clone()));

    // Route precedence: /api and /ui are literal segments, so they win over
    // the S3 gateway's /{namespace} captures. Namespace names "api" and "ui"
    // are therefore reserved.
    let app = ui::router()
        .merge(api::router())
        .merge(s3::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, "simplecas listening (S3 gateway at /, PWA at /ui/, admin API at /api/)");
    axum::serve(listener, app).await?;
    Ok(())
}
