//! The page at the root, for the person who typed the host and nothing else.
//!
//! It says what is running and where the doors are, and nothing more: no
//! version, because an unauthenticated page that names its build hands a
//! scanner its worklist, and no realm names, because which realms exist is
//! nobody's to enumerate. The style rides inline: every stylesheet this
//! server serves lives under a realm's path, and this page stands outside
//! every realm.

use std::sync::LazyLock;

use actix_web::HttpResponse;

/// Rendered once: the page is the same for everyone, and which doors it
/// shows was settled when the binary was built.
static PAGE: LazyLock<String> = LazyLock::new(|| {
    let door = if cfg!(feature = "embedded-admin") {
        "<p><a class=\"door\" href=\"/console\">Administration console</a></p>"
    } else {
        ""
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>saffui</title><style>{style}</style></head><body><main>\
         <p class=\"mark\" aria-hidden=\"true\">S</p>\
         <h1>saffui</h1>\
         <p class=\"word\">identity, and the plane that administers it</p>{door}\
         <p class=\"aside\"><a href=\"https://github.com/saffui/saffui\">\
         Source and documentation</a></p>\
         </main></body></html>",
        style = include_str!("welcome.css"),
    )
});

pub async fn serve() -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        // Public and the same for everyone, so a cache may keep it a while.
        .insert_header(("Cache-Control", "public, max-age=300"))
        .body(PAGE.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::MessageBody;
    use actix_web::web;

    /// The root greets, names no version and no realm, and points at the
    /// console exactly when the build carries one.
    #[actix_web::test]
    async fn the_root_greets_without_saying_too_much() {
        let app = actix_web::test::init_service(
            actix_web::App::new().service(web::resource("/").route(web::get().to(serve))),
        )
        .await;
        let request = actix_web::test::TestRequest::get().uri("/").to_request();
        let answered = actix_web::test::call_service(&app, request).await;
        assert!(answered.status().is_success());
        assert_eq!(
            answered
                .headers()
                .get("x-content-type-options")
                .and_then(|held| held.to_str().ok()),
            Some("nosniff")
        );

        let body = answered.into_body().try_into_bytes().unwrap();
        let page = std::str::from_utf8(&body).unwrap();
        assert!(page.contains("<h1>saffui</h1>"));
        assert_eq!(
            page.contains("href=\"/console\""),
            cfg!(feature = "embedded-admin"),
            "the console door does not match what the build carries"
        );
        assert!(
            !page.contains(env!("CARGO_PKG_VERSION")),
            "the page names its build"
        );
    }
}
