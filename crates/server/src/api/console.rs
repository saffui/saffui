//! The admin console, served from inside the binary.
//!
//! Compiled only under `embedded-admin`, which requires `admin/dist` to
//! exist at build time (`pnpm --dir admin build`). The single-page app owns
//! every path under `/console/`: a file that exists is served, with a long
//! cache life when its name carries a build hash, and everything else gets
//! `index.html`, which is how a client-side router survives a reload.

use actix_web::{HttpResponse, web};
use include_dir::{Dir, include_dir};

static CONSOLE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../admin/dist");

pub async fn serve(path: web::Path<String>) -> HttpResponse {
    let asked = path.into_inner();
    let (name, file) = match CONSOLE.get_file(asked.as_str()) {
        Some(file) if !asked.is_empty() => (asked.as_str(), file),
        _ => match CONSOLE.get_file("index.html") {
            Some(file) => ("index.html", file),
            None => return HttpResponse::NotFound().finish(),
        },
    };
    let content_type = match name.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    };
    HttpResponse::Ok()
        .insert_header(("Content-Type", content_type))
        .insert_header((
            "Cache-Control",
            // The hash in an asset's name is its version; index.html is the
            // one thing that must always be fetched fresh.
            if name.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            },
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .body(file.contents())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;

    async fn served(path: &str) -> (String, String, Vec<u8>) {
        let answer = serve(web::Path::from(path.to_owned())).await;
        let content_type = answer
            .headers()
            .get("content-type")
            .and_then(|held| held.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let caching = answer
            .headers()
            .get("cache-control")
            .and_then(|held| held.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = answer.into_body().try_into_bytes().unwrap().to_vec();
        (content_type, caching, body)
    }

    /// The app owns its root: the shell comes back for the root, for any
    /// route its own router knows, and always fresh; a hashed asset comes
    /// back as itself and may be kept for good.
    #[actix_web::test]
    async fn the_console_serves_its_shell_and_keeps_its_assets() {
        let (kind, caching, body) = served("").await;
        assert!(kind.starts_with("text/html"), "{kind}");
        assert_eq!(caching, "no-cache");
        assert!(body.windows(9).any(|held| held == b"<div id=\""), "not the shell");

        let (kind, caching, spa) = served("main/users").await;
        assert!(kind.starts_with("text/html"), "{kind}");
        assert_eq!(caching, "no-cache");
        assert_eq!(spa, body, "a route the router owns did not get the shell");

        let asset = CONSOLE
            .get_dir("assets")
            .expect("a built assets directory")
            .files()
            .find(|file| file.path().extension().is_some_and(|held| held == "js"))
            .expect("a built script")
            .path()
            .to_string_lossy()
            .into_owned();
        let (kind, caching, _) = served(&asset).await;
        assert!(kind.starts_with("text/javascript"), "{kind}");
        assert!(caching.contains("immutable"), "{caching}");
    }
}
