use actix_web::{HttpRequest, HttpResponse, web};
use include_dir::{Dir, include_dir};

static ACCOUNT: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../account/dist");

/// What the console may load and call: its own bundle, the images and fonts the
/// build inlines, and this server. Nothing inline runs and no page may frame it.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                      img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
                      form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// The console's routes: its assets once for every realm, since a build is the
/// same for all of them, and the app for every page under a realm's console.
pub fn mount_account_console(config: &mut web::ServiceConfig) {
    config
        .service(web::resource("/account/assets/{file:.*}").route(web::get().to(serve_asset)))
        .service(
            web::resource([
                "/realms/{realm}/account",
                "/realms/{realm}/account/{path:.*}",
            ])
            .route(web::get().to(serve_shell)),
        );
}

/// The app, whose router reads the realm and the page off the address, so a
/// reload of any page lands back on it.
async fn serve_shell() -> HttpResponse {
    match ACCOUNT.get_file("index.html") {
        Some(file) => answer_file("index.html", file.contents()),
        None => HttpResponse::NotFound().finish(),
    }
}

/// A built asset, under the name the build gave it. Any other name is not found:
/// answering the app in its place would hand a script a page.
async fn serve_asset(request: HttpRequest) -> HttpResponse {
    let asked = format!(
        "assets/{}",
        request.match_info().get("file").unwrap_or_default()
    );
    match ACCOUNT.get_file(&asked) {
        Some(file) => answer_file(&asked, file.contents()),
        None => HttpResponse::NotFound().finish(),
    }
}

fn answer_file(name: &str, body: &'static [u8]) -> HttpResponse {
    let content_type = match name.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    HttpResponse::Ok()
        .insert_header(("Content-Type", content_type))
        .insert_header((
            "Cache-Control",
            // A built asset's name carries its version; the app is always fetched
            // fresh, so a new build reaches the next reload.
            if name.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            },
        ))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        // A sign-in comes back to the console with its code in the address.
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, test};

    const READ_HEADERS: [&str; 4] = [
        "content-type",
        "cache-control",
        "content-security-policy",
        "referrer-policy",
    ];

    /// Ask the console as the server mounts it, and read back the status, the
    /// headers named above in their order, and the body.
    async fn fetch_from_console(path: &str) -> (u16, Vec<String>, Vec<u8>) {
        let app = test::init_service(App::new().configure(mount_account_console)).await;
        let response =
            test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
        let status = response.status().as_u16();
        let headers = READ_HEADERS
            .iter()
            .map(|named| {
                response
                    .headers()
                    .get(*named)
                    .and_then(|held| held.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        let body = test::read_body(response).await.to_vec();
        (status, headers, body)
    }

    /// Every page of a realm's console is the app, fetched fresh each time, under
    /// a policy that runs nothing inline and lets no page frame it, and telling no
    /// page it leads to where the person came from.
    #[actix_web::test]
    async fn every_page_of_a_realms_console_is_the_app() {
        let app = ACCOUNT
            .get_file("index.html")
            .expect("a built app")
            .contents();
        for asked in [
            "/realms/main/account",
            "/realms/main/account/",
            "/realms/main/account/login/return?code=c&state=s",
            "/realms/a%20b/account/profile",
        ] {
            let (status, headers, body) = fetch_from_console(asked).await;
            assert_eq!(status, 200, "{asked}");
            assert_eq!(headers[0], "text/html; charset=utf-8", "{asked}");
            assert_eq!(headers[1], "no-cache", "{asked}");
            assert!(
                headers[2].contains("script-src 'self';")
                    && headers[2].contains("frame-ancestors 'none'"),
                "{asked}: {}",
                headers[2]
            );
            assert_eq!(headers[3], "no-referrer", "{asked}");
            assert_eq!(body, app, "{asked} was not the app");
        }
    }

    /// A built asset is itself and may be kept for good; a name the build did not
    /// make is not found rather than answered with the app, and nothing climbs
    /// out of the assets.
    #[actix_web::test]
    async fn an_asset_is_itself_or_not_found() {
        let script = ACCOUNT
            .get_dir("assets")
            .expect("built assets")
            .files()
            .find(|file| file.path().extension().is_some_and(|held| held == "js"))
            .expect("a built script");
        let (status, headers, body) =
            fetch_from_console(&format!("/account/{}", script.path().to_string_lossy())).await;
        assert_eq!(status, 200);
        assert_eq!(headers[0], "text/javascript; charset=utf-8");
        assert!(headers[1].contains("immutable"), "{}", headers[1]);
        assert_eq!(body, script.contents());

        for missing in [
            "/account/assets/nothing.js",
            "/account/assets/../index.html",
            "/account/assets/%2e%2e/index.html",
            "/account/index.html",
        ] {
            let (status, _, _) = fetch_from_console(missing).await;
            assert_eq!(status, 404, "{missing}");
        }
    }
}
