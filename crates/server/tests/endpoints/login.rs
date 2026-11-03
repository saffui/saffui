use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, SET_COOKIE};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test, web};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::testkit::fixtures::{
    Application, create_person, create_realm, register_application,
};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::Value;
use server::api::config::register_data_plane;

const REDIRECT: &str = "https://app.example.test/callback";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) location: Option<String>,
    pub(crate) cookies: Vec<String>,
    pub(crate) head: Vec<(String, String)>,
    pub(crate) body: String,
}

impl Answer {
    pub(crate) fn read_header(&self, name: &str) -> Option<&str> {
        self.head
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The `name=value` of the cookie whose name starts with `prefix`.
    pub(crate) fn read_cookie(&self, prefix: &str) -> Option<String> {
        self.cookies
            .iter()
            .find(|cookie| cookie.starts_with(prefix))
            .and_then(|cookie| cookie.split(';').next())
            .map(str::to_owned)
    }

    pub(crate) fn read_location_parameter(&self, name: &str) -> Option<String> {
        let location = self.location.as_deref()?;
        let (_, query) = location.split_once('?')?;
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_owned())
    }
}

struct Sent<'a> {
    method: Method,
    path: &'a str,
    head: &'a [(&'a str, &'a str)],
    form: Option<&'a str>,
}

async fn send(product: &saffui_core::app::App, sent: Sent<'_>) -> Answer {
    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let mut request = test::TestRequest::default()
        .method(sent.method)
        .uri(sent.path);
    for (name, value) in sent.head {
        request = request.insert_header((*name, *value));
    }
    if let Some(form) = sent.form {
        request = request
            .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(form.to_owned());
    }
    let response = test::call_service(&app, request.to_request()).await;
    let head: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let read_all = |wanted: &str| -> Vec<String> {
        head.iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.clone())
            .collect()
    };
    let status = response.status();
    let location = read_all(LOCATION.as_str()).into_iter().next();
    let cookies = read_all(SET_COOKIE.as_str());
    let body = String::from_utf8_lossy(&test::read_body(response).await).into_owned();
    Answer {
        status,
        location,
        cookies,
        head,
        body,
    }
}

pub(crate) async fn get(
    product: &saffui_core::app::App,
    path: &str,
    head: &[(&str, &str)],
) -> Answer {
    let sent = Sent {
        method: Method::GET,
        path,
        head,
        form: None,
    };
    send(product, sent).await
}

pub(crate) async fn post(
    product: &saffui_core::app::App,
    path: &str,
    head: &[(&str, &str)],
    form: &str,
) -> Answer {
    let sent = Sent {
        method: Method::POST,
        path,
        head,
        form: Some(form),
    };
    send(product, sent).await
}

/// The realm `acme`, the person `ada`, and the public application `portal`.
async fn start() -> saffui_core::app::App {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", PASSWORD).await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: REDIRECT,
        post_logout_redirect_uri: Some("https://app.example.test/goodbye"),
        public: true,
    };
    register_application(&product, scope, portal).await;
    product
}

fn write_authorize_path(product: &saffui_core::app::App, more: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=portal\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid%20profile\
         &state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256{more}"
    )
}

/// Goes to the authorization endpoint without a session. Returns the pending
/// request and the cookie that binds it to this browser.
async fn start_sign_in(product: &saffui_core::app::App) -> (String, String) {
    let sent_to_login = get(product, &write_authorize_path(product, ""), &[]).await;
    assert_eq!(
        sent_to_login.status,
        StatusCode::SEE_OTHER,
        "{}",
        sent_to_login.body
    );
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let cookie = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    (request, cookie)
}

#[actix_web::test]
async fn a_person_signs_in_and_the_application_exchanges_the_code_for_tokens() {
    let product = start().await;

    let sent_to_login = get(&product, &write_authorize_path(&product, ""), &[]).await;
    assert_eq!(sent_to_login.status, StatusCode::SEE_OTHER);
    let login = sent_to_login.location.clone().expect("a location");
    assert!(login.starts_with("/realms/acme/login?request="), "{login}");
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    assert_eq!(
        flow.split('=').next(),
        Some(format!("__Host-saffui_flow_{request}").as_str())
    );
    let flow_attributes = &sent_to_login.cookies[0];
    assert!(flow_attributes.contains("; Path=/; "), "{flow_attributes}");
    assert!(
        flow_attributes.ends_with("; HttpOnly; SameSite=Lax; Secure"),
        "{flow_attributes}"
    );

    let page = get(&product, &login, &[(COOKIE.as_str(), &flow)]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains(&format!("name=\"request\" value=\"{request}\""))
    );

    let form = format!("request={request}&username=Ada&password=correct+horse+battery");
    let signed_in = post(
        &product,
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
    let back = signed_in.location.clone().expect("a location");
    assert!(
        back.starts_with("https://app.example.test/callback?code="),
        "{back}"
    );
    assert_eq!(
        signed_in.read_location_parameter("state").as_deref(),
        Some("xyz")
    );
    assert_eq!(
        signed_in.read_location_parameter("iss").as_deref(),
        Some("https%3A%2F%2Fid.example.test%2Frealms%2Facme")
    );
    let session = signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session cookie");
    let session_attributes = signed_in
        .cookies
        .iter()
        .find(|cookie| cookie.starts_with("__Host-saffui_session_acme="))
        .expect("the session cookie");
    assert!(
        session_attributes.ends_with("; Path=/; HttpOnly; SameSite=Lax; Secure"),
        "a session lives as long as the browser: {session_attributes}"
    );
    assert!(
        !session_attributes.contains("Max-Age"),
        "{session_attributes}"
    );
    // The browser is marked, past the session, to be counted apart next time.
    let device_attributes = signed_in
        .cookies
        .iter()
        .find(|cookie| cookie.starts_with("__Host-saffui_mark_acme="))
        .expect("the mark of the browser");
    assert!(
        device_attributes.ends_with("; Path=/; Max-Age=7776000; HttpOnly; SameSite=Lax; Secure"),
        "{device_attributes}"
    );
    // The flow is over: its cookie is taken back.
    assert!(
        signed_in.cookies.iter().any(|cookie| cookie
            .starts_with(&format!("__Host-saffui_flow_{request}=;"))
            && cookie.contains("Max-Age=0")),
        "{:?}",
        signed_in.cookies
    );

    let code = signed_in.read_location_parameter("code").expect("a code");
    let exchange = format!(
        "grant_type=authorization_code&client_id=portal&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}"
    );
    let tokens = post(&product, "/realms/acme/oauth2/token", &[], &exchange).await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
    let tokens: Value = serde_json::from_str(&tokens.body).expect("JSON");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid profile");
    assert!(tokens["access_token"].is_string());
    assert!(tokens["id_token"].is_string());

    // The access token tells the application who signed in, and a request
    // that presents none, or a wrong one, is challenged.
    let bearer = format!(
        "Bearer {}",
        tokens["access_token"].as_str().expect("a token")
    );
    let told = get(
        &product,
        "/realms/acme/oauth2/userinfo",
        &[("authorization", &bearer)],
    )
    .await;
    assert_eq!(told.status, StatusCode::OK, "{}", told.body);
    assert_eq!(told.read_header("cache-control"), Some("no-store"));
    let told: Value = serde_json::from_str(&told.body).expect("JSON");
    assert_eq!(told["preferred_username"], "ada");
    assert!(told.get("email").is_none(), "{told}");
    let unasked = get(&product, "/realms/acme/oauth2/userinfo", &[]).await;
    assert_eq!(unasked.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unasked.read_header("www-authenticate"), Some("Bearer"));
    let wrong = get(
        &product,
        "/realms/acme/oauth2/userinfo",
        &[("authorization", "Bearer not.a.token")],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        wrong.read_header("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );

    // The refresh token is spent for the next one, through the same form.
    let presented = tokens["refresh_token"].as_str().expect("a refresh token");
    let refresh = format!("grant_type=refresh_token&client_id=portal&refresh_token={presented}");
    let refreshed = post(&product, "/realms/acme/oauth2/token", &[], &refresh).await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.body);
    assert_eq!(refreshed.read_header("cache-control"), Some("no-store"));
    let refreshed: Value = serde_json::from_str(&refreshed.body).expect("JSON");
    assert_eq!(refreshed["scope"], "openid profile");
    assert!(
        refreshed["refresh_token"]
            .as_str()
            .is_some_and(|next| next != presented)
    );

    // The code served once.
    let again = post(&product, "/realms/acme/oauth2/token", &[], &exchange).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    let again: Value = serde_json::from_str(&again.body).expect("JSON");
    assert_eq!(again["error"], "invalid_grant");

    // With its session, the person is not asked again.
    let straight_back = get(
        &product,
        &write_authorize_path(&product, ""),
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    assert_eq!(straight_back.status, StatusCode::SEE_OTHER);
    assert!(
        straight_back
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("https://app.example.test/callback?code=")),
        "{:?}",
        straight_back.location
    );
    assert!(straight_back.cookies.is_empty());

    // Its identity token names the person: the session answers it without a
    // page, and a hint that is no identity token is refused.
    let identity = tokens["id_token"].as_str().expect("an identity token");
    let hinted = get(
        &product,
        &write_authorize_path(&product, &format!("&prompt=none&id_token_hint={identity}")),
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    assert!(
        hinted.read_location_parameter("code").is_some(),
        "{:?}",
        hinted.location
    );
    let unreadable = get(
        &product,
        &write_authorize_path(&product, "&prompt=none&id_token_hint=not.a.token"),
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    assert_eq!(
        unreadable.read_location_parameter("error").as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn a_request_from_an_unknown_client_or_to_an_unregistered_address_is_shown_and_sent_nowhere()
{
    let product = start().await;
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    let unknown_client = format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=ghost\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback\
         &code_challenge={challenge}&code_challenge_method=S256"
    );
    let unregistered_address = format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=portal\
         &redirect_uri=https%3A%2F%2Fevil.example.test%2Fcallback&state=xyz\
         &code_challenge={challenge}&code_challenge_method=S256"
    );

    for (path, status, message) in [
        (unknown_client, StatusCode::NOT_FOUND, "No such client."),
        (
            unregistered_address,
            StatusCode::BAD_REQUEST,
            "The redirect URI is not one the client registered.",
        ),
    ] {
        let shown = get(&product, &path, &[]).await;

        assert_eq!(shown.status, status, "{path}");
        assert_eq!(shown.location, None, "{path}");
        assert!(shown.body.contains(message), "{}", shown.body);
        assert!(!shown.body.contains("evil.example.test"), "{}", shown.body);
    }
}

#[actix_web::test]
async fn a_trusted_client_that_asks_wrongly_gets_its_error_back_with_its_state_and_the_issuer() {
    let product = start().await;
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    let base = "/realms/acme/oauth2/authorize?client_id=portal\
                &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&state=xyz";
    let pkce = format!("&code_challenge={challenge}&code_challenge_method=S256");

    for (query, error) in [
        (format!("{base}&response_type=code"), "invalid_request"),
        (
            format!(
                "{base}&response_type=code&code_challenge={challenge}&code_challenge_method=plain"
            ),
            "invalid_request",
        ),
        (
            format!("{base}&response_type=token{pkce}"),
            "unsupported_response_type",
        ),
        (
            format!("{base}&response_type=code&scope=openid%20payments{pkce}"),
            "invalid_scope",
        ),
    ] {
        let returned = get(&product, &query, &[]).await;

        assert_eq!(returned.status, StatusCode::SEE_OTHER, "{query}");
        assert_eq!(
            returned.read_location_parameter("error").as_deref(),
            Some(error),
            "{query}"
        );
        assert_eq!(
            returned.read_location_parameter("state").as_deref(),
            Some("xyz")
        );
        assert!(returned.read_location_parameter("iss").is_some());
        assert!(returned.cookies.is_empty(), "{query}");
    }
}

#[actix_web::test]
async fn a_wrong_password_shows_the_form_again_and_the_same_request_then_succeeds() {
    let product = start().await;
    let (request, flow) = start_sign_in(&product).await;
    let cookie = [(COOKIE.as_str(), flow.as_str())];

    let wrong = format!("request={request}&username=ada&password=not+the+password");
    let refused = post(&product, "/realms/acme/login", &cookie, &wrong).await;

    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(refused.body.contains("The name or the password is wrong."));
    assert!(
        refused
            .body
            .contains(&format!("name=\"request\" value=\"{request}\""))
    );
    assert!(refused.cookies.is_empty());
    assert!(!refused.body.contains("not the password"));

    let right = format!("request={request}&username=ada&password=correct+horse+battery");
    let signed_in = post(&product, "/realms/acme/login", &cookie, &right).await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
}

#[actix_web::test]
async fn a_sign_in_that_another_browser_or_another_site_submits_is_refused_like_an_expired_one() {
    let product = start().await;
    let (request, flow) = start_sign_in(&product).await;
    let form = format!("request={request}&username=ada&password=correct+horse+battery");
    let (other_request, other_flow) = start_sign_in(&product).await;
    let borrowed = format!(
        "__Host-saffui_flow_{request}={}",
        other_flow.split_once('=').expect("a cookie").1
    );
    assert_ne!(request, other_request);

    let without_cookie = post(&product, "/realms/acme/login", &[], &form).await;
    let with_the_cookie_of_another_request = post(
        &product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &borrowed)],
        &form,
    )
    .await;
    let from_another_site = post(
        &product,
        "/realms/acme/login",
        &[
            (COOKIE.as_str(), &flow),
            (ORIGIN.as_str(), "https://evil.example.test"),
        ],
        &form,
    )
    .await;

    for refused in [
        without_cookie,
        with_the_cookie_of_another_request,
        from_another_site,
    ] {
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert!(refused.body.contains("This sign-in has expired."));
        assert_eq!(refused.location, None);
        assert!(refused.cookies.is_empty());
    }

    // Its own browser, on the origin of the provider, still finishes it.
    let finished = post(
        &product,
        "/realms/acme/login",
        &[
            (COOKIE.as_str(), &flow),
            (ORIGIN.as_str(), "https://id.example.test"),
        ],
        &form,
    )
    .await;
    assert_eq!(finished.status, StatusCode::SEE_OTHER, "{}", finished.body);
}

#[actix_web::test]
async fn the_sign_in_page_runs_no_script_is_framed_by_nobody_and_is_kept_by_no_cache() {
    let product = start().await;
    let (request, flow) = start_sign_in(&product).await;

    let page = get(
        &product,
        &format!("/realms/acme/login?request={request}"),
        &[(COOKIE.as_str(), &flow)],
    )
    .await;

    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(
        page.read_header(CONTENT_TYPE.as_str()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(page.read_header(CACHE_CONTROL.as_str()), Some("no-store"));
    assert_eq!(page.read_header("x-frame-options"), Some("DENY"));
    assert_eq!(page.read_header("x-content-type-options"), Some("nosniff"));
    assert_eq!(page.read_header("referrer-policy"), Some("no-referrer"));
    let policy = page
        .read_header("content-security-policy")
        .expect("a policy");
    assert!(
        policy.starts_with("default-src 'none'; style-src 'nonce-"),
        "{policy}"
    );
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    assert!(!policy.contains("script-src"), "{policy}");
    assert!(!page.body.contains("<script"), "{}", page.body);
}

#[actix_web::test]
async fn a_sign_in_page_asked_with_no_request_or_a_strange_one_shows_no_form() {
    let product = start().await;

    for path in [
        "/realms/acme/login",
        "/realms/acme/login?request=%22%3E%3Cscript%3E",
    ] {
        let page = get(&product, path, &[]).await;

        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{path}");
        assert!(!page.body.contains("<form"), "{}", page.body);
        assert!(!page.body.contains("<script"), "{}", page.body);
    }
}

#[actix_web::test]
async fn a_session_cookie_sent_twice_is_believed_for_neither_value() {
    let product = start().await;
    let (request, flow) = start_sign_in(&product).await;
    let form = format!("request={request}&username=ada&password=correct+horse+battery");
    let signed_in = post(
        &product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &flow)],
        &form,
    )
    .await;
    let session = signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session cookie");
    // What a neighbouring host could add to the jar: the same name, first.
    let planted = format!("__Host-saffui_session_acme=planted; {session}");

    let with_one = get(
        &product,
        &write_authorize_path(&product, ""),
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    let with_two = get(
        &product,
        &write_authorize_path(&product, ""),
        &[(COOKIE.as_str(), &planted)],
    )
    .await;

    assert!(
        with_one
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("https://app.example.test/callback?code=")),
        "{:?}",
        with_one.location
    );
    assert!(
        with_two
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("/realms/acme/login?request=")),
        "the person signs in again: {:?}",
        with_two.location
    );
}

/// Signs `ada` in on a new pending request, with the cookies of the
/// browser beside the cookie of the flow.
async fn submit_password(
    product: &saffui_core::app::App,
    password: &str,
    browser: Option<&str>,
) -> Answer {
    submit_password_as(product, "ada", password, browser).await
}

async fn submit_password_as(
    product: &saffui_core::app::App,
    name: &str,
    password: &str,
    browser: Option<&str>,
) -> Answer {
    let (request, flow) = start_sign_in(product).await;
    let cookies = browser.map_or_else(|| flow.clone(), |more| format!("{flow}; {more}"));
    let form = format!(
        "request={request}&username={name}&password={}",
        password.replace(' ', "+")
    );
    post(
        product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &cookies)],
        &form,
    )
    .await
}

#[actix_web::test]
async fn the_browser_that_signed_in_before_brings_its_mark_back_through_a_lock() {
    let product = start().await;
    let first = submit_password(&product, PASSWORD, None).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.body);
    let mark = first
        .read_cookie("__Host-saffui_mark_acme=")
        .expect("the mark of the browser");

    // Five guesses from elsewhere lock the name: the tests have no address,
    // so the name alone is counted.
    for _ in 0..5 {
        let refused = submit_password(&product, "a guess", None).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    }
    let held = submit_password(&product, PASSWORD, None).await;
    assert_eq!(
        held.status,
        StatusCode::UNAUTHORIZED,
        "a browser without the mark is held"
    );

    let through = submit_password(&product, PASSWORD, Some(&mark)).await;
    assert_eq!(through.status, StatusCode::SEE_OTHER, "{}", through.body);
    let renewed = through
        .read_cookie("__Host-saffui_mark_acme=")
        .expect("the mark, renewed");
    assert_eq!(
        renewed.split('.').nth(1),
        mark.split('.').nth(1),
        "the browser keeps its device"
    );
}

#[actix_web::test]
async fn a_browser_two_people_sign_in_on_keeps_a_mark_for_each() {
    let product = start().await;
    let (_, scope) = saffui_core::tenancy::resolve::resolve_realm(&product, "acme")
        .await
        .expect("the realm");
    create_person(&product, scope, "bob", PASSWORD).await;
    let of_ada = submit_password(&product, PASSWORD, None)
        .await
        .read_cookie("__Host-saffui_mark_acme=")
        .expect("the mark of ada");
    let of_both = submit_password_as(&product, "bob", PASSWORD, Some(&of_ada))
        .await
        .read_cookie("__Host-saffui_mark_acme=")
        .expect("the marks of both");
    let ada_alone = of_ada.trim_start_matches("__Host-saffui_mark_acme=");
    assert!(
        of_both.ends_with(&format!("~{ada_alone}")),
        "the mark of bob first, then the one of ada: {of_both}"
    );

    // Each name locked from elsewhere, the browser passes for both.
    for name in ["ada", "bob"] {
        for _ in 0..5 {
            let refused = submit_password_as(&product, name, "a guess", None).await;
            assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        }
        let through = submit_password_as(&product, name, PASSWORD, Some(&of_both)).await;
        assert_eq!(
            through.status,
            StatusCode::SEE_OTHER,
            "{name}: {}",
            through.body
        );
    }
}

#[actix_web::test]
async fn a_person_signs_out_at_once_with_the_identity_token_of_the_session_and_is_asked_otherwise()
{
    let product = start().await;
    let signed_in = submit_password(&product, PASSWORD, None).await;
    let session = signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session cookie");
    let code = signed_in.read_location_parameter("code").expect("a code");
    let exchange = format!(
        "grant_type=authorization_code&client_id=portal&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}"
    );
    let tokens = post(&product, "/realms/acme/oauth2/token", &[], &exchange).await;
    let tokens: Value = serde_json::from_str(&tokens.body).expect("JSON");
    let identity = tokens["id_token"].as_str().expect("an identity token");

    // Without the identity token, the person is asked, on a page that
    // writes nothing the request carried.
    let asked = get(
        &product,
        "/realms/acme/oauth2/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2F\
         &state=planted-state",
        &[(COOKIE.as_str(), &session)],
    )
    .await;
    assert_eq!(asked.status, StatusCode::OK);
    assert!(
        asked
            .body
            .contains("<form method=\"post\" action=\"/realms/acme/oauth2/logout\">"),
        "{}",
        asked.body
    );
    assert!(!asked.body.contains("evil.example") && !asked.body.contains("planted"));
    assert!(asked.cookies.is_empty(), "nothing ends yet");

    // A form another site posts is refused by name.
    let from_elsewhere = post(
        &product,
        "/realms/acme/oauth2/logout",
        &[
            (COOKIE.as_str(), &session),
            (ORIGIN.as_str(), "https://evil.example"),
        ],
        "",
    )
    .await;
    assert_eq!(from_elsewhere.status, StatusCode::FORBIDDEN);

    // With it, the session ends at once, and the browser goes back to the
    // address the application registered.
    let path = format!(
        "/realms/acme/oauth2/logout?id_token_hint={identity}\
         &post_logout_redirect_uri=https%3A%2F%2Fapp.example.test%2Fgoodbye&state=bye"
    );
    let out = get(&product, &path, &[(COOKIE.as_str(), &session)]).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(
        out.location.as_deref(),
        Some("https://app.example.test/goodbye?state=bye")
    );
    assert!(
        out.cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-saffui_session_acme=;")
                && cookie.contains("Max-Age=0")),
        "{:?}",
        out.cookies
    );
    let refresh = format!(
        "grant_type=refresh_token&client_id=portal&refresh_token={}",
        tokens["refresh_token"].as_str().expect("a refresh token")
    );
    let refused = post(&product, "/realms/acme/oauth2/token", &[], &refresh).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "the refresh tokens of the session went with it"
    );

    // Confirmed on the page of the realm, a sign-out ends what is left.
    let confirmed = post(
        &product,
        "/realms/acme/oauth2/logout",
        &[(COOKIE.as_str(), &session)],
        "",
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK);
    assert!(confirmed.body.contains("You are signed out."));
}
