//! Ensures `web/dist/` exists so rust-embed can compile even before the PWA is
//! built. Production builds should run `bun run build` in web/ first (the
//! Dockerfile does this); a bare `cargo build` gets a placeholder page that
//! points developers at the build step.

use std::fs;
use std::path::Path;

fn main() {
    let dist = Path::new("web/dist");
    let index = dist.join("index.html");
    if !index.exists() {
        fs::create_dir_all(dist).expect("create web/dist");
        fs::write(
            &index,
            "<!doctype html><meta charset=utf-8><title>simplecas</title>\
             <p style=\"font-family:sans-serif;padding:2rem\">\
             UI not built. Run <code>bun install &amp;&amp; bun run build</code> in <code>web/</code>, \
             then rebuild the server.</p>",
        )
        .expect("write placeholder index.html");
    }
    println!("cargo:rerun-if-changed=web/dist");
}
