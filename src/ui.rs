//! Serves the bundled PWA (built from web/ into web/dist and embedded into
//! the binary at compile time). SPA routing: unknown paths under /ui fall
//! back to index.html.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Assets;

pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route("/ui", get(|| async { Redirect::permanent("/ui/") }))
        .route("/ui/", get(|| async { serve("index.html") }))
        .route("/ui/{*path}", get(serve_path))
}

async fn serve_path(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches("/ui/");
    serve(path)
}

fn serve(path: &str) -> Response {
    let asset = Assets::get(path).or_else(|| Assets::get("index.html"));
    match asset {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_else(|| mime_guess::mime::TEXT_HTML);
            // Hashed assets can cache forever; index.html must revalidate.
            let cache = if path.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref()),
                    (header::CACHE_CONTROL, cache),
                ],
                content.data,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
