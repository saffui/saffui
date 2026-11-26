//! The end-session endpoint in process: the frames that tell the clients a
//! session served, the page that leaves once they loaded, and the requests
//! of RP-Initiated Logout that end nothing they do not prove.

use std::fmt::Write as _;
use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::http::header::{COOKIE, ORIGIN};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::app::App;
use saffui_core::audit::EventKind;
use saffui_core::clients::register::NewClient;
use saffui_core::testkit::fixtures::{
    Application, check_and_register_client, create_person, create_realm, register_application,
};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::Value;

use super::login::{Answer, get, post};

const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const GOODBYE: &str = "https://app.example.test/goodbye";
const FRAMED: &str = "https://app.example.test/signed-out?from=idp";
const ISSUER: &str = "https%3A%2F%2Fid.example.test%2Frealms%2Facme";
const SESSION_COOKIE: &str = "__Host-saffui_session_acme=";

/// Percent-encodes a value for a query string, every byte but letters and digits.
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Percent-encodes a value as the endpoint does: all but what RFC 3986
/// leaves unreserved.
fn encode_unreserved(value: &str) -> String {
    let mut written = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            written.push(char::from(byte));
        } else {
            let _ = write!(written, "%{byte:02X}");
        }
    }
    written
}

/// Reads HTML text back: the five characters the pages write as references.
fn decode_html(text: &str) -> String {
    text.replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#38;", "&")
}

/// Every value of `attribute` in the tags named `tag`, read back.
fn read_attributes(body: &str, tag: &str, attribute: &str) -> Vec<String> {
    body.split(&format!("<{tag} "))
        .skip(1)
        .filter_map(|after| {
            let tag = format!(" {}", after.split('>').next()?);
            let (_, value) = tag.split_once(&format!(" {attribute}=\""))?;
            value.split('"').next().map(decode_html)
        })
        .collect()
}

/// Where the page refreshes to, for each refresh it says.
fn read_refreshes(body: &str) -> Vec<String> {
    body.split("<meta http-equiv=\"refresh\" content=\"")
        .skip(1)
        .filter_map(|after| after.split('"').next().map(decode_html))
        .collect()
}

fn read_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a compact token");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("JSON")
}

/// The realm `acme`, the person `ada`, the application `portal`, which
/// registered where people go after they sign out, and `framed`, loaded at
/// `FRAMED` when a session it served ends.
async fn start() -> (App, Arc<MemoryStorage>) {
    let (product, storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", PASSWORD).await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.test/callback",
        post_logout_redirect_uri: Some(GOODBYE),
        public: true,
        requires_consent: false,
    };
    register_application(&product, scope, portal).await;
    let (scopes, callbacks) = (
        ["openid".to_owned()],
        ["https://app.example.test/callback".to_owned()],
    );
    let mut work = product.storage.begin(scope).await.expect("a unit of work");
    check_and_register_client(
        &product,
        work.as_mut(),
        NewClient {
            client_id: "framed",
            name: "framed",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: Some(FRAMED),
            response_types: &[],
            public: true,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: None,
        },
    )
    .await
    .expect("framed");
    work.commit().await.expect("a commit");
    (product, storage)
}

fn write_authorize_path(product: &App, client_id: &str, more: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid\
         &state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256{more}"
    )
}

/// Exchanges a code of `client_id`, and returns its identity token.
async fn exchange(product: &App, client_id: &str, answered: &Answer) -> String {
    let code = answered.read_location_parameter("code").expect("a code");
    let form = format!(
        "grant_type=authorization_code&client_id={client_id}&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}"
    );
    let tokens = post(product, "/realms/acme/oauth2/token", &[], &form).await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
    let tokens: Value = serde_json::from_str(&tokens.body).expect("JSON");
    tokens["id_token"]
        .as_str()
        .expect("an identity token")
        .to_owned()
}

/// Signs `ada` in through `portal`, and returns her session cookie and the
/// identity token `portal` was given.
async fn sign_in(product: &App) -> (String, String) {
    let sent = get(product, &write_authorize_path(product, "portal", ""), &[]).await;
    let request = sent.read_location_parameter("request").expect("a request");
    let flow = sent
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let form = format!("request={request}&username=ada&password=correct+horse+battery");
    let signed_in = post(
        product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &flow)],
        &form,
    )
    .await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    let session = signed_in.read_cookie(SESSION_COOKIE).expect("a session");
    let identity = exchange(product, "portal", &signed_in).await;
    (session, identity)
}

/// Has the session of `session` answer `client_id` at once, and returns the
/// identity token the client was given.
async fn serve(product: &App, client_id: &str, session: &str) -> String {
    let answered = get(
        product,
        &write_authorize_path(product, client_id, ""),
        &[(COOKIE.as_str(), session)],
    )
    .await;
    assert_eq!(answered.status, StatusCode::SEE_OTHER, "{}", answered.body);
    exchange(product, client_id, &answered).await
}

/// What a request of `portal` that asks nothing is answered in the session
/// of `session`: a code while it lives, `login_required` once it ended.
async fn ask_silently(product: &App, session: &str) -> Answer {
    get(
        product,
        &write_authorize_path(product, "portal", "&prompt=none"),
        &[(COOKIE.as_str(), session)],
    )
    .await
}

fn is_cleared(answer: &Answer) -> bool {
    answer.cookies.iter().any(|cookie| {
        cookie.starts_with("__Host-saffui_session_acme=;") && cookie.contains("Max-Age=0")
    })
}

#[actix_web::test]
async fn a_sign_out_loads_the_frame_of_each_client_it_tells_then_leaves_on_markup() {
    let (product, _storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    let told = serve(&product, "framed", &session).await;
    // Ninety characters of the printable range, as a client may send.
    let state: String = (0x20_u8..=0x7e).map(char::from).take(90).collect();

    let out = get(
        &product,
        &format!(
            "/realms/acme/oauth2/logout?id_token_hint={identity}\
             &post_logout_redirect_uri={}&state={}",
            encode(GOODBYE),
            encode(&state)
        ),
        &[(COOKIE.as_str(), &session)],
    )
    .await;

    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    let sid = read_claims(&told)["sid"]
        .as_str()
        .expect("a session")
        .to_owned();
    assert_eq!(
        read_attributes(&out.body, "iframe", "src"),
        [format!("{FRAMED}&iss={ISSUER}&sid={sid}")],
        "the address it registered, then iss and sid, and nothing else"
    );
    let leaving = format!("{GOODBYE}?state={}", encode_unreserved(&state));
    assert_eq!(
        read_refreshes(&out.body),
        [format!("0; url={leaving}")],
        "{}",
        out.body
    );
    assert_eq!(read_attributes(&out.body, "a", "href"), [leaving]);
    assert!(out.location.is_none(), "no redirection outruns the frame");
    let policy = out
        .read_header("content-security-policy")
        .unwrap_or_default();
    assert!(
        policy.contains(" frame-src https://app.example.test;"),
        "{policy}"
    );
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    assert_eq!(out.read_header("x-frame-options"), Some("DENY"));
    assert_eq!(out.read_header("referrer-policy"), Some("same-origin"));
    assert_eq!(out.read_header("cache-control"), Some("no-store"));
    assert!(is_cleared(&out), "{:?}", out.cookies);

    let silent = ask_silently(&product, &session).await;
    assert_eq!(
        silent.read_location_parameter("error").as_deref(),
        Some("login_required"),
        "the session the frame told of is over"
    );
}

#[actix_web::test]
async fn without_an_address_or_after_a_confirmation_the_signed_out_page_loads_the_frames() {
    let (product, _storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    serve(&product, "framed", &session).await;

    let out = get(
        &product,
        &format!("/realms/acme/oauth2/logout?id_token_hint={identity}"),
        &[(COOKIE.as_str(), &session)],
    )
    .await;

    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    assert_eq!(
        read_attributes(&out.body, "iframe", "src").len(),
        1,
        "{}",
        out.body
    );
    assert!(out.body.contains("You are signed out."), "{}", out.body);
    assert!(
        out.body
            .contains("If one still shows you signed in, sign out there too."),
        "{}",
        out.body
    );
    assert!(read_refreshes(&out.body).is_empty(), "{}", out.body);
    assert!(is_cleared(&out));

    let (session, _) = sign_in(&product).await;
    serve(&product, "framed", &session).await;
    let asked = get(
        &product,
        "/realms/acme/oauth2/logout",
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    assert!(read_attributes(&asked.body, "iframe", "src").is_empty());
    let confirmed = post(
        &product,
        "/realms/acme/oauth2/logout/confirm",
        &[(COOKIE.as_str(), &session)],
        "",
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    assert_eq!(read_attributes(&confirmed.body, "iframe", "src").len(), 1);
    assert!(read_refreshes(&confirmed.body).is_empty());
    assert!(is_cleared(&confirmed));
}

#[actix_web::test]
async fn an_ending_that_was_not_written_shows_no_frame_and_keeps_the_cookie() {
    let (product, storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    serve(&product, "framed", &session).await;
    storage.refuse_commits_recording(EventKind::SessionEnded);

    let out = get(
        &product,
        &format!(
            "/realms/acme/oauth2/logout?id_token_hint={identity}&post_logout_redirect_uri={}",
            encode(GOODBYE)
        ),
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    let confirmed = post(
        &product,
        "/realms/acme/oauth2/logout/confirm",
        &[(COOKIE.as_str(), &session)],
        "",
    )
    .await;

    for answer in [&out, &confirmed] {
        assert_eq!(
            answer.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            answer.body
        );
        assert!(!answer.body.contains("<iframe"), "{}", answer.body);
        assert!(!answer.body.contains("signed out"), "{}", answer.body);
        assert!(answer.location.is_none());
        assert!(answer.cookies.is_empty(), "{:?}", answer.cookies);
    }
}

#[actix_web::test]
async fn a_request_posted_from_another_site_is_carried_to_the_page_and_ends_nothing_itself() {
    let (product, _storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    let form = format!(
        "id_token_hint={identity}&post_logout_redirect_uri={}&state=bye&client_id=portal\
         &logout_hint=ada&ui_locales=fr%20en&unknown=passed-over",
        encode(GOODBYE)
    );

    // With the cookie or without: a post reads no session.
    for cookies in [vec![], vec![(COOKIE.as_str(), session.as_str())]] {
        let mut head = vec![(ORIGIN.as_str(), "https://app.example.test")];
        head.extend(cookies);
        let posted = post(&product, "/realms/acme/oauth2/logout", &head, &form).await;
        assert_eq!(posted.status, StatusCode::SEE_OTHER, "{}", posted.body);
        assert_eq!(
            posted.location.as_deref(),
            Some(
                format!(
                    "/realms/acme/oauth2/logout?id_token_hint={identity}\
                     &post_logout_redirect_uri={}&state=bye&client_id=portal&logout_hint=ada\
                     &ui_locales=fr%20en",
                    "https%3A%2F%2Fapp.example.test%2Fgoodbye"
                )
                .as_str()
            ),
            "the six, and nothing else"
        );
        assert_eq!(posted.read_header("cache-control"), Some("no-store"));
        assert!(posted.cookies.is_empty());
        assert!(
            ask_silently(&product, &session)
                .await
                .read_location_parameter("code")
                .is_some()
        );
    }

    let carried = post(&product, "/realms/acme/oauth2/logout", &[], &form)
        .await
        .location
        .expect("the page");
    let out = get(&product, &carried, &[(COOKIE.as_str(), &session)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(
        out.location.as_deref(),
        Some("https://app.example.test/goodbye?state=bye")
    );
    assert_eq!(
        ask_silently(&product, &session)
            .await
            .read_location_parameter("error")
            .as_deref(),
        Some("login_required")
    );

    let repeated = post(
        &product,
        "/realms/acme/oauth2/logout",
        &[],
        "state=one&state=two",
    )
    .await;
    assert_eq!(
        repeated.status,
        StatusCode::BAD_REQUEST,
        "{}",
        repeated.body
    );
    assert!(repeated.location.is_none());

    let misnamed = post(&product, "/realms/ACME/oauth2/logout", &[], &form).await;
    assert_eq!(misnamed.status, StatusCode::NOT_FOUND, "{}", misnamed.body);
    assert!(misnamed.location.is_none(), "no realm is written so");
}

#[actix_web::test]
async fn a_hint_without_the_cookie_of_its_session_ends_nothing_by_get_or_post() {
    let (product, _storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    let (other, _) = sign_in(&product).await;
    let query = format!("id_token_hint={identity}");

    let by_get = get(
        &product,
        &format!("/realms/acme/oauth2/logout?{query}"),
        &[],
    )
    .await;
    let posted = post(&product, "/realms/acme/oauth2/logout", &[], &query).await;
    let carried = posted.location.expect("the page");
    let by_post = get(&product, &carried, &[]).await;
    let with_another = get(&product, &carried, &[(COOKIE.as_str(), &other)]).await;

    for answer in [&by_get, &by_post] {
        assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    }
    assert!(
        with_another.body.contains("Do you want to sign out?"),
        "the cookie of another session asks: {}",
        with_another.body
    );
    for (cookie, why) in [
        (&session, "the session the hint names"),
        (&other, "another session"),
    ] {
        assert!(
            ask_silently(&product, cookie)
                .await
                .read_location_parameter("code")
                .is_some(),
            "{why} lives"
        );
    }
}

#[actix_web::test]
async fn the_person_is_told_why_they_are_asked_and_nothing_the_client_sent_is_shown() {
    let (product, _storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    let ask = async |query: &str| {
        let asked = get(
            &product,
            &format!("/realms/acme/oauth2/logout?state=planted-state{query}"),
            &[(COOKIE.as_str(), &session)],
        )
        .await;
        assert_eq!(asked.status, StatusCode::OK, "{query}: {}", asked.body);
        assert!(asked.body.contains("Do you want to sign out?"), "{query}");
        assert!(!asked.body.contains("planted"), "{query}");
        assert!(asked.cookies.is_empty(), "{query}: nothing ends yet");
        asked.body
    };

    let missing = ask("").await;
    let invalid = ask("&id_token_hint=not.a.token").await;
    let of_another_client = ask(&format!("&id_token_hint={identity}&client_id=framed")).await;

    assert!(missing.contains("without saying who you are"), "{missing}");
    assert!(!invalid.contains("without saying who you are"), "{invalid}");
    assert!(
        invalid.contains("does not prove it asks for this session"),
        "{invalid}"
    );
    assert!(
        of_another_client.contains("does not prove it asks for this session"),
        "a client the hint was not issued to proves nothing: {of_another_client}"
    );
    assert!(!of_another_client.contains("framed"));
}

#[actix_web::test]
async fn an_address_not_registered_ends_nothing_and_is_named_on_a_page_that_asks() {
    let (product, _storage) = start().await;
    let (session, identity) = sign_in(&product).await;
    let long = format!("https://evil.example/{}", "a".repeat(10_000));
    let cut = format!("https://evil.example/{}\u{2026}", "a".repeat(179));

    for (asked, shown) in [
        ("https://evil.example/<x>", "https://evil.example/<x>"),
        (&format!("{GOODBYE}?foo=bar"), &format!("{GOODBYE}?foo=bar")),
        (
            "https://evil.example/\u{202e}gro.elpmaxe",
            "https://evil.example/\u{fffd}gro.elpmaxe",
        ),
        (&long, &cut),
    ] {
        let refused = get(
            &product,
            &format!(
                "/realms/acme/oauth2/logout?id_token_hint={identity}&post_logout_redirect_uri={}",
                encode(asked)
            ),
            &[(COOKIE.as_str(), &session)],
        )
        .await;

        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
        assert!(refused.location.is_none());
        assert!(refused.cookies.is_empty(), "nothing ends");
        assert!(
            decode_html(&refused.body).contains(&format!(
                "to send you to <code>{shown}</code> after you sign out"
            )),
            "{}",
            refused.body
        );
        assert!(
            !refused.body.contains('\u{202e}'),
            "nothing reorders the page"
        );
        assert!(!refused.body.contains("<x>"), "written as text");
        assert!(
            refused
                .body
                .contains("<form method=\"post\" action=\"/realms/acme/oauth2/logout/confirm\">")
        );
        assert!(
            ask_silently(&product, &session)
                .await
                .read_location_parameter("code")
                .is_some()
        );
    }
}
