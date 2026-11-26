//! The end-session endpoint of a realm, the page that signs a person out
//! or asks them first, and the frames that tell the clients the session
//! served.

use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use askama::Template;
use saffui_core::app::App as Product;
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::login::session::SessionTicket;
use saffui_core::oidc::logout::{
    ConfirmationCause, FrontChannelLogout, Logout, LogoutParameters, begin_logout, confirm_logout,
    write_logout_query,
};
use serde::Deserialize;

use crate::api::rest::endpoints::login::page::{
    Frame, is_posted_from_elsewhere, is_realm_label, render_framing_page, render_page,
    render_refusal,
};
use crate::extract::cookies::{is_served_over_tls, name_session_cookie, read_cookie, write_cookie};

/// What a request to end a session carries, in a query or in a form. A
/// parameter named twice is refused; one not named here is passed over.
#[derive(Deserialize)]
pub struct LogoutRequest {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    logout_hint: Option<String>,
    ui_locales: Option<String>,
}

impl LogoutRequest {
    fn read_parameters(&self) -> LogoutParameters<'_> {
        LogoutParameters {
            id_token_hint: self.id_token_hint.as_deref(),
            post_logout_redirect_uri: self.post_logout_redirect_uri.as_deref(),
            state: self.state.as_deref(),
            client_id: self.client_id.as_deref(),
            logout_hint: self.logout_hint.as_deref(),
            ui_locales: self.ui_locales.as_deref(),
        }
    }
}

/// The page that signs a person out, or asks them first.
#[derive(Template)]
#[template(path = "oidc/logout.html")]
struct LogoutPage<'a> {
    frame: Frame,
    shown: Shown<'a>,
    /// Where the browser goes once the page and its frames loaded.
    leaving: Option<&'a str>,
}

enum Shown<'a> {
    /// The session is over, and the frames tell the clients it served.
    SignedOut { frames: &'a [FrontChannelLogout] },
    /// The question, why it is asked, and the form that answers it.
    Confirmation {
        realm: &'a str,
        cause: ConfirmationCause,
    },
    /// The address asked is not one the client registered: nothing ended,
    /// and the person is asked.
    ReturnUnregistered { realm: &'a str, address: &'a str },
}

/// The `Set-Cookie` that takes the session cookie back from the browser.
/// Nothing is written for a name that is not a realm label.
fn clear_session_cookie(product: &Product, realm: &str) -> Option<String> {
    let secure = is_served_over_tls(product);
    is_realm_label(realm)
        .then(|| write_cookie(&name_session_cookie(realm, secure), "", Some(0), secure))
}

fn read_ticket(product: &Product, realm: &str, http: &HttpRequest) -> Option<SessionTicket> {
    let name = name_session_cookie(realm, is_served_over_tls(product));
    read_cookie(http, &name).and_then(|value| SessionTicket::parse(&value))
}

/// The page that says the session is over, which loads the frames of the
/// clients it served, and then leaves for `leaving` when there is one. The
/// browser gives the session cookie back.
fn render_signed_out(
    product: &Product,
    realm: &str,
    frames: &[FrontChannelLogout],
    leaving: Option<&str>,
) -> HttpResponse {
    let sources: Vec<&str> = frames.iter().map(|frame| frame.source.as_str()).collect();
    let mut page = render_framing_page(product, StatusCode::OK, &sources, |frame| LogoutPage {
        frame,
        shown: Shown::SignedOut { frames },
        leaving,
    });
    if let Some(Ok(cookie)) = clear_session_cookie(product, realm).map(|cookie| cookie.parse()) {
        page.headers_mut().append(SET_COOKIE, cookie);
    }
    page
}

#[get("/realms/{realm}/oauth2/logout")]
pub async fn begin(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
    query: web::Query<LogoutRequest>,
) -> HttpResponse {
    let ticket = read_ticket(&product, &realm, &http);
    let parameters = query.read_parameters();
    match begin_logout(&product, &realm, parameters, ticket.as_ref()).await {
        // Without a frame to load, the browser is sent on at once.
        Ok(Logout::SignedOut {
            location: Some(location),
            frames,
        }) if frames.is_empty() => {
            let mut response = HttpResponse::SeeOther();
            response
                .insert_header((LOCATION, location))
                .insert_header((CACHE_CONTROL, "no-store"));
            if let Some(cookie) = clear_session_cookie(&product, &realm) {
                response.insert_header((SET_COOKIE, cookie));
            }
            response.finish()
        }
        // A redirection would leave before the frames load: the page goes
        // on by itself once they did.
        Ok(Logout::SignedOut { location, frames }) => {
            render_signed_out(&product, &realm, &frames, location.as_deref())
        }
        // Nothing a client sent is written on this page: the form carries no field.
        Ok(Logout::ConfirmationRequired(cause)) if is_realm_label(&realm) => {
            render_page(&product, StatusCode::OK, |frame| LogoutPage {
                frame,
                shown: Shown::Confirmation {
                    realm: &realm,
                    cause,
                },
                leaving: None,
            })
        }
        Ok(Logout::ReturnUnregistered { address }) if is_realm_label(&realm) => {
            render_page(&product, StatusCode::BAD_REQUEST, |frame| LogoutPage {
                frame,
                shown: Shown::ReturnUnregistered {
                    realm: &realm,
                    address: &address,
                },
                leaving: None,
            })
        }
        // A name that is not a realm label resolved to no realm: this is never reached.
        Ok(Logout::ConfirmationRequired(_) | Logout::ReturnUnregistered { .. }) => {
            render_refusal(&product, &Failure::new(ErrorCode::RealmNotFound))
        }
        Err(failure) => render_refusal(&product, &failure),
    }
}

/// A request to end a session posted by a client (RP-Initiated Logout 1.0,
/// section 2), carried on to the endpoint in the browser: the cookie of the
/// session comes with a navigation of its own, never with a post another
/// site makes. Nothing is read or ended here.
#[post("/realms/{realm}/oauth2/logout")]
pub async fn relay_posted_logout(
    product: web::Data<Product>,
    realm: web::Path<String>,
    form: web::Form<LogoutRequest>,
) -> HttpResponse {
    if !is_realm_label(&realm) {
        return render_refusal(&product, &Failure::new(ErrorCode::RealmNotFound));
    }
    let query = write_logout_query(&form.read_parameters());
    HttpResponse::SeeOther()
        .insert_header((LOCATION, format!("/realms/{realm}/oauth2/logout{query}")))
        .insert_header((CACHE_CONTROL, "no-store"))
        .finish()
}

#[post("/realms/{realm}/oauth2/logout/confirm")]
pub async fn confirm(
    product: web::Data<Product>,
    realm: web::Path<String>,
    http: HttpRequest,
) -> HttpResponse {
    // The session cookie is withheld from a form another site posts: this
    // refuses such a post by name, before anything is read.
    if is_posted_from_elsewhere(&product, &http) {
        return HttpResponse::Forbidden()
            .insert_header((CACHE_CONTROL, "no-store"))
            .finish();
    }
    let frames = match read_ticket(&product, &realm, &http) {
        Some(ticket) => match confirm_logout(&product, &realm, &ticket).await {
            Ok(frames) => frames,
            Err(failure) => return render_refusal(&product, &failure),
        },
        None => Vec::new(),
    };
    render_signed_out(&product, &realm, &frames, None)
}

#[cfg(test)]
mod tests {
    use actix_web::body::MessageBody;
    use actix_web::http::StatusCode;
    use actix_web::test::{TestRequest, call_service, init_service};
    use actix_web::{App, web};
    use saffui_core::oidc::logout::{ConfirmationCause, FrontChannelLogout};
    use saffui_core::testkit::memory::MemoryStorage;

    use super::{LogoutPage, Shown, render_signed_out};
    use crate::api::rest::endpoints::login::page::render_page;
    use crate::api::rest::endpoints::login::page::tests::{HOSTILE, assert_written_as_text};
    use crate::middleware::security_headers::protect_answers;

    #[test]
    fn every_text_the_sign_out_page_shows_is_written_as_text() {
        let (product, _storage) = MemoryStorage::wire();
        let frames = [FrontChannelLogout {
            url: HOSTILE.to_owned(),
            source: "https://app.example.test".to_owned(),
        }];

        for (shown, held) in [
            (
                Shown::Confirmation {
                    realm: HOSTILE,
                    cause: ConfirmationCause::NoHint,
                },
                1,
            ),
            (
                Shown::ReturnUnregistered {
                    realm: HOSTILE,
                    address: HOSTILE,
                },
                2,
            ),
        ] {
            let page = render_page(&product, StatusCode::OK, |frame| LogoutPage {
                frame,
                shown,
                leaving: None,
            });
            assert_written_as_text(page, held);
        }
        // The frame, and where the page goes after it: its refresh and its link.
        assert_written_as_text(
            render_signed_out(&product, "acme", &frames, Some(HOSTILE)),
            3,
        );
    }

    #[test]
    fn a_page_that_loads_frames_hides_them_runs_no_script_and_frames_their_origins_alone() {
        let (product, _storage) = MemoryStorage::wire();
        let frames = [
            FrontChannelLogout {
                url: "https://app.example.test/out?iss=x&sid=y".to_owned(),
                source: "https://app.example.test".to_owned(),
            },
            FrontChannelLogout {
                url: "https://app.example.test/again?iss=x&sid=y".to_owned(),
                source: "https://app.example.test".to_owned(),
            },
            FrontChannelLogout {
                url: "http://127.0.0.1:8080/out?iss=x&sid=y".to_owned(),
                source: "http://127.0.0.1:8080".to_owned(),
            },
        ];

        let page = render_signed_out(
            &product,
            "acme",
            &frames,
            Some("https://app.example.test/bye?state=a'b;c,d"),
        );

        let policy = page
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            policy.contains(" frame-src https://app.example.test http://127.0.0.1:8080;"),
            "each origin once, and no path: {policy}"
        );
        assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
        assert!(!policy.contains("script-src"), "{policy}");
        let body = page.into_body().try_into_bytes().expect("a body");
        let body = String::from_utf8_lossy(&body);
        assert_eq!(
            body.matches(
                "<iframe hidden sandbox=\"allow-scripts allow-same-origin allow-forms\" \
                 title=\"Signing out of an application\" src=\""
            )
            .count(),
            3,
            "{body}"
        );
        assert!(!body.contains("loading="), "{body}");
        assert!(!body.contains("<script"), "{body}");
        assert!(
            body.contains(
                "<meta http-equiv=\"refresh\" content=\"0; \
                 url=https://app.example.test/bye?state=a&#39;b;c,d\">"
            ),
            "{body}"
        );
        assert!(
            body.contains("<a href=\"https://app.example.test/bye?state=a&#39;b;c,d\">"),
            "{body}"
        );
    }

    #[actix_web::test]
    async fn the_head_of_a_page_at_the_bound_of_its_frames_stays_under_four_kibibytes() {
        let (product, _storage) = MemoryStorage::wire();
        assert!(
            product
                .settings
                .public_origin
                .as_str()
                .starts_with("https://")
        );
        // Two origins of 1,535 bytes take the 3 KiB of the policy, with
        // their spaces, and the realm has the longest name a realm takes.
        let frames: Vec<FrontChannelLogout> = ['a', 'b']
            .into_iter()
            .map(|letter| {
                let source = format!("https://{}", String::from(letter).repeat(1_527));
                FrontChannelLogout {
                    url: format!("{source}/out?iss=x&sid=y"),
                    source,
                }
            })
            .collect();
        let realm = "r".repeat(63);
        let page = {
            let product = product.clone();
            move || std::future::ready(render_signed_out(&product, &realm, &frames, None))
        };
        let service = init_service(
            App::new().service(
                web::scope("")
                    .wrap(protect_answers(&product))
                    .route("/", web::get().to(page)),
            ),
        )
        .await;

        let answer = call_service(&service, TestRequest::get().to_request()).await;

        assert_eq!(answer.status(), StatusCode::OK);
        // As a proxy reads them: the status line, each header, and the two
        // the connection adds, `date` and `content-length`.
        let headers: usize = answer
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4)
            .sum();
        let body = answer.into_body().try_into_bytes().expect("a body").len();
        let head = "HTTP/1.1 200 OK\r\n".len()
            + headers
            + "date: Wed, 25 Nov 2026 00:00:00 GMT\r\n".len()
            + format!("content-length: {body}\r\n").len()
            + "\r\n".len();
        assert!(head < 4_096, "{head} bytes");
    }
}
