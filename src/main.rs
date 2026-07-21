mod api;
mod auth;
mod cas;
mod config;
mod db;
mod error;
mod s3;
mod storage;
mod ui;

use axum::Router;
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

    // OIDC discovery (and JWKS fetch) happens here, so a broken auth config
    // fails startup rather than every login.
    let oidc = auth::build_registry(&config.oidc).await?;

    let bind = config.server.bind.clone();
    let state = Arc::new(AppState {
        pool,
        op,
        config,
        oidc,
    });

    tokio::spawn(cas::gc_loop(state.clone()));
    tokio::spawn(auth::refresh_loop(state.clone()));

    // Route precedence: /api, /ui and /auth are literal segments, so they win
    // over the S3 gateway's /{namespace} captures. Namespace names "api", "ui"
    // and "auth" are therefore reserved.
    //
    // When OIDC is on, the guard middleware is layered onto the /ui and /api
    // routers only — the S3 gateway keeps its SigV4 auth and the /auth login
    // endpoints must stay reachable while signed out.
    let mut ui_router = ui::router();
    let mut api_router = api::router();
    let mut app = Router::new();
    if state.oidc.is_some() {
        let guard = axum::middleware::from_fn_with_state(state.clone(), auth::guard);
        ui_router = ui_router.layer(guard.clone());
        api_router = api_router.layer(guard);
        app = app.merge(auth::router());
    }
    let app = app
        .merge(ui_router)
        .merge(api_router)
        .merge(s3::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, "simplecas listening (S3 gateway at /, PWA at /ui/, admin API at /api/)");
    axum::serve(listener, app).await?;
    Ok(())
}
