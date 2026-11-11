use std::sync::Arc;
use std::time::Duration;

use actix_web::http::header::{AUTHORIZATION, COOKIE, ORIGIN};
use actix_web::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::authz::capability::Capability;
use saffui_core::testkit::clock::FixedClock;
use saffui_core::testkit::crypto::{PredictableCodes, TrustingKeys, UnservedKeys};
use saffui_core::testkit::fixtures::{
    CodeFlow, create_administrator, create_application, create_person, create_realm, run_code_flow,
};
use saffui_core::testkit::memory::MemoryStorage;

use super::login::{Answer, Sent, get, post, send};

const CALLBACK: &str = "https://app.example.test/callback";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const AUTHENTICATOR: &str = "/realms/acme/account/authenticator";
const CONFIRM: &str = "/realms/acme/account/authenticator/confirm";
const SECURITY_KEY: &str = "/realms/acme/account/security-key";
const CONFIRM_KEY: &str = "/realms/acme/account/security-key/confirm";
const LOGIN: &str = "/realms/acme/login";

struct Started {
    product: saffui_core::app::App,
    clock: Arc<FixedClock>,
    /// The session cookie of `ada`, as her browser sends it.
    session: String,
    scope: saffui_core::tenancy::RealmScope,
}

/// The realm `acme`, and the person `ada` signed in through `portal`.
async fn start() -> Started {
    let (product, _storage, clock) = MemoryStorage::wire_with_clock();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", PASSWORD).await;
    create_application(&product, scope, "portal", CALLBACK, true).await;
    let flow = CodeFlow {
        realm: "acme",
        client_id: "portal",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid",
        username: "ada",
        password: PASSWORD,
    };
    let ticket = run_code_flow(&product, flow).await.ticket;
    Started {
        session: format!("__Host-saffui_session_acme={}", ticket.write()),
        product,
        clock,
        scope,
    }
}

fn read_between<'a>(text: &'a str, before: &str, after: &str) -> Option<&'a str> {
    let (_, rest) = text.split_once(before)?;
    rest.split_once(after).map(|(found, _)| found)
}

fn read_code_now(started: &Started, typed_secret: &str) -> String {
    let seconds = u64::try_from(started.product.now().unix_timestamp()).expect("after 1970");
    PredictableCodes::compute_from_text(typed_secret, seconds)
}

/// Enrolls an authenticator for `ada` on the hosted pages and returns its
/// secret. The clock then moves to the next step: the first code is spent.
async fn enroll(started: &Started) -> String {
    let cookie = [(COOKIE.as_str(), started.session.as_str())];
    let offered = post(&started.product, AUTHENTICATOR, &cookie, "").await;
    assert_eq!(offered.status, StatusCode::OK, "{}", offered.body);
    let secret = read_between(&offered.body, "<code id=\"secret\">", "</code>")
        .expect("the secret is shown")
        .to_owned();
    let form = format!(
        "password=correct+horse+battery&code={}",
        read_code_now(started, &secret)
    );
    let confirmed = post(&started.product, CONFIRM, &cookie, &form).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    started.clock.advance(Duration::from_secs(30));
    secret
}

fn write_authorize_path(product: &saffui_core::app::App) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=portal\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope=openid\
         &state=xyz&code_challenge={challenge}&code_challenge_method=S256"
    )
}

/// Signs `ada` in again on the hosted page, in a new browser, with her
/// password and a code. Returns her new session cookie.
async fn sign_in_with_code(started: &Started, secret: &str) -> String {
    let sent_to_login = get(
        &started.product,
        &write_authorize_path(&started.product),
        &[],
    )
    .await;
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let cookie = [(COOKIE.as_str(), flow.as_str())];
    let login = "/realms/acme/login";
    let form = format!("request={request}&username=ada&password=correct+horse+battery");
    post(&started.product, login, &cookie, &form).await;
    let form = format!("request={request}&code={}", read_code_now(started, secret));
    post(&started.product, login, &cookie, &form)
        .await
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session")
}

#[actix_web::test]
async fn a_person_sets_up_an_authenticator_with_their_password_and_a_first_code() {
    let started = start().await;
    let cookie = [(COOKIE.as_str(), started.session.as_str())];

    let page = get(&started.product, AUTHENTICATOR, &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Set up an authenticator application"));
    assert_eq!(page.read_header("cache-control"), Some("no-store"));

    let offered = post(&started.product, AUTHENTICATOR, &cookie, "").await;
    assert_eq!(offered.status, StatusCode::OK, "{}", offered.body);
    assert_eq!(offered.read_header("cache-control"), Some("no-store"));
    let secret = read_between(&offered.body, "<code id=\"secret\">", "</code>")
        .expect("the secret is shown")
        .to_owned();
    assert!(
        offered
            .body
            .contains("otpauth://totp/https://id.example.test/realms/acme:ada?secret="),
        "{}",
        offered.body
    );
    let code = read_code_now(&started, &secret);

    let wrong_password = post(
        &started.product,
        CONFIRM,
        &cookie,
        &format!("password=not+the+password&code={code}"),
    )
    .await;
    assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
    assert!(
        !wrong_password.body.contains(&secret),
        "the secret is shown once"
    );
    let wrong_code = post(
        &started.product,
        CONFIRM,
        &cookie,
        "password=correct+horse+battery&code=000000",
    )
    .await;
    assert_eq!(wrong_code.status, StatusCode::UNAUTHORIZED);
    assert!(wrong_code.body.contains("The code is wrong"));

    let confirmed = post(
        &started.product,
        CONFIRM,
        &cookie,
        &format!("password=correct+horse+battery&code={code}"),
    )
    .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.body);
    assert!(confirmed.body.contains("is set up"));

    let again = post(&started.product, AUTHENTICATOR, &cookie, "").await;
    assert_eq!(
        again.status,
        StatusCode::FORBIDDEN,
        "the password alone opened this session"
    );
    started.clock.advance(Duration::from_secs(30));
    let proven = sign_in_with_code(&started, &secret).await;
    let again = post(
        &started.product,
        AUTHENTICATOR,
        &[(COOKIE.as_str(), proven.as_str())],
        "",
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert!(
        !again.body.contains("<code id=\"secret\">"),
        "no second secret is made over a confirmed one"
    );
    let page = get(&started.product, AUTHENTICATOR, &cookie).await;
    assert!(page.body.contains("is set up"), "{}", page.body);
}

#[actix_web::test]
async fn the_pages_of_the_authenticator_serve_nobody_without_a_session_or_from_another_site() {
    let started = start().await;
    let evil = [
        (COOKIE.as_str(), started.session.as_str()),
        (ORIGIN.as_str(), "https://evil.example.test"),
    ];

    let anonymous: [Answer; 3] = [
        get(&started.product, AUTHENTICATOR, &[]).await,
        post(&started.product, AUTHENTICATOR, &[], "").await,
        post(&started.product, CONFIRM, &[], "password=x&code=000000").await,
    ];
    let from_another_site: [Answer; 2] = [
        post(&started.product, AUTHENTICATOR, &evil, "").await,
        post(&started.product, CONFIRM, &evil, "password=x&code=000000").await,
    ];

    for refused in anonymous.iter().chain(&from_another_site) {
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        assert!(refused.body.contains("Sign in from an application first."));
        assert!(!refused.body.contains("<code id=\"secret\">"));
    }
}

#[actix_web::test]
async fn a_form_is_read_after_its_guard_and_within_the_limit_of_the_plane() {
    let started = start().await;
    let cookie = [(COOKIE.as_str(), started.session.as_str())];
    let evil = [
        (COOKIE.as_str(), started.session.as_str()),
        (ORIGIN.as_str(), "https://evil.example.test"),
    ];
    // Well formed, and larger than the forms the plane reads.
    let large = format!("password={}&code=000000", "a".repeat(9 * 1024));

    let from_another_site = post(&started.product, CONFIRM, &evil, &large).await;
    assert_eq!(from_another_site.status, StatusCode::UNAUTHORIZED);
    assert!(
        from_another_site
            .body
            .contains("Sign in from an application first."),
        "the guard answers, not the form: {}",
        from_another_site.body
    );

    let from_here = post(&started.product, CONFIRM, &cookie, &large).await;
    assert_eq!(from_here.status, StatusCode::BAD_REQUEST);
    assert!(
        from_here.body.contains("name=\"code\""),
        "the page asks again: {}",
        from_here.body
    );
}

#[actix_web::test]
async fn a_person_with_an_authenticator_signs_in_with_their_password_then_a_code() {
    let started = start().await;
    let secret = enroll(&started).await;

    // A new browser: no session, so the whole sign-in.
    let sent_to_login = get(
        &started.product,
        &write_authorize_path(&started.product),
        &[],
    )
    .await;
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let cookie = [(COOKIE.as_str(), flow.as_str())];

    let asked_for_a_code = post(
        &started.product,
        "/realms/acme/login",
        &cookie,
        &format!("request={request}&username=ada&password=correct+horse+battery"),
    )
    .await;
    assert_eq!(asked_for_a_code.status, StatusCode::OK);
    assert!(asked_for_a_code.body.contains("name=\"code\""));
    assert!(!asked_for_a_code.body.contains("name=\"password\""));
    assert_eq!(asked_for_a_code.location, None);
    assert!(
        asked_for_a_code.cookies.is_empty(),
        "no session before the code: {:?}",
        asked_for_a_code.cookies
    );

    let refused = post(
        &started.product,
        "/realms/acme/login",
        &cookie,
        &format!("request={request}&code=000000"),
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(refused.body.contains("name=\"code\""));
    assert!(refused.cookies.is_empty());

    let signed_in = post(
        &started.product,
        "/realms/acme/login",
        &cookie,
        &format!(
            "request={request}&code={}",
            read_code_now(&started, &secret)
        ),
    )
    .await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    assert!(
        signed_in
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("https://app.example.test/callback?code=")),
        "{:?}",
        signed_in.location
    );
    assert!(
        signed_in
            .read_cookie("__Host-saffui_session_acme=")
            .is_some()
    );
}

#[actix_web::test]
async fn a_code_given_before_any_password_finishes_nothing() {
    let started = start().await;
    let secret = enroll(&started).await;
    let sent_to_login = get(
        &started.product,
        &write_authorize_path(&started.product),
        &[],
    )
    .await;
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");

    let skipped = post(
        &started.product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &flow)],
        &format!(
            "request={request}&code={}",
            read_code_now(&started, &secret)
        ),
    )
    .await;

    assert_eq!(skipped.status, StatusCode::BAD_REQUEST);
    assert!(skipped.body.contains("This sign-in has expired."));
    assert!(skipped.cookies.is_empty());
}

#[actix_web::test]
async fn an_administrator_takes_an_authenticator_away_and_the_password_is_enough_again() {
    let started = start().await;
    enroll(&started).await;
    let person = {
        let mut work = started
            .product
            .storage
            .begin(started.scope)
            .await
            .expect("a unit of work");
        work.read_person_by_username("ada")
            .await
            .expect("a read")
            .expect("ada")
            .id
    };
    let writer = create_administrator(
        &started.product,
        "acme",
        started.scope,
        "operator",
        &[Capability::UserWrite],
    )
    .await;
    let reader = create_administrator(
        &started.product,
        "acme",
        started.scope,
        "auditor",
        &[Capability::UserRead],
    )
    .await;
    let remove = async |token: &str, person: &str| {
        let bearer = format!("Bearer {token}");
        let path = format!("/admin/v1/realms/acme/users/{person}/authenticator");
        let sent = Sent {
            method: Method::DELETE,
            path: &path,
            head: &[(AUTHORIZATION.as_str(), bearer.as_str())],
            form: None,
        };
        send(&started.product, sent).await.status
    };

    assert_eq!(
        remove(&reader, &person.to_string()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        remove(&writer, "not-an-identifier").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        remove(&writer, &person.to_string()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        remove(&writer, &person.to_string()).await,
        StatusCode::NOT_FOUND
    );

    let sent_to_login = get(
        &started.product,
        &write_authorize_path(&started.product),
        &[],
    )
    .await;
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let signed_in = post(
        &started.product,
        "/realms/acme/login",
        &[(COOKIE.as_str(), &flow)],
        &format!("request={request}&username=ada&password=correct+horse+battery"),
    )
    .await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
}

#[actix_web::test]
async fn only_a_writer_of_people_resumes_the_codes_of_a_person() {
    let started = start().await;
    let person = {
        let mut work = started
            .product
            .storage
            .begin(started.scope)
            .await
            .expect("a unit of work");
        work.read_person_by_username("ada")
            .await
            .expect("a read")
            .expect("ada")
            .id
    };
    let writer = create_administrator(
        &started.product,
        "acme",
        started.scope,
        "operator",
        &[Capability::UserWrite],
    )
    .await;
    let reader = create_administrator(
        &started.product,
        "acme",
        started.scope,
        "auditor",
        &[Capability::UserRead],
    )
    .await;
    let resume = async |token: &str, person: &str| {
        let bearer = format!("Bearer {token}");
        let path = format!("/admin/v1/realms/acme/users/{person}/code-attempts");
        let sent = Sent {
            method: Method::DELETE,
            path: &path,
            head: &[(AUTHORIZATION.as_str(), bearer.as_str())],
            form: None,
        };
        send(&started.product, sent).await.status
    };

    assert_eq!(
        resume(&reader, &person.to_string()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        resume(&writer, "not-an-identifier").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        resume(&writer, &uuid::Uuid::nil().to_string()).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        resume(&writer, &person.to_string()).await,
        StatusCode::NO_CONTENT
    );
}

fn read_key_options(page: &str) -> serde_json::Value {
    let written = read_between(page, "data-options=\"", "\"").expect("the options of a key");
    let text = written
        .replace("&#34;", "\"")
        .replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&#39;", "'")
        .replace("&#38;", "&");
    serde_json::from_str(&text).expect("options written as JSON")
}

/// Writes a value as a form carries it.
fn write_form_value(value: &str) -> String {
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

fn write_key_field(answer: &serde_json::Value) -> String {
    format!("key={}", write_form_value(&answer.to_string()))
}

/// Adds the security key `credential_id` for `ada` on the hosted pages,
/// from her first session.
async fn add_key(started: &Started, credential_id: &str) {
    add_key_in(started, &started.session, credential_id).await;
}

/// Adds the security key `credential_id` for `ada`, from the session of the
/// cookie `session`.
async fn add_key_in(started: &Started, session: &str, credential_id: &str) {
    let cookie = [(COOKIE.as_str(), session)];
    let asked = post(
        &started.product,
        SECURITY_KEY,
        &cookie,
        "password=correct+horse+battery",
    )
    .await;
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    let answer = TrustingKeys::answer_enrollment(&read_key_options(&asked.body), credential_id);
    let added = post(
        &started.product,
        CONFIRM_KEY,
        &cookie,
        &write_key_field(&answer),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.body);
}

/// Starts a sign-in in a new browser and gives the password of `ada`.
/// Returns the request, the flow cookie and the page that came back.
async fn give_password_in_a_new_browser(started: &Started) -> (String, String, Answer) {
    let sent_to_login = get(
        &started.product,
        &write_authorize_path(&started.product),
        &[],
    )
    .await;
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let page = post(
        &started.product,
        LOGIN,
        &[(COOKIE.as_str(), flow.as_str())],
        &format!("request={request}&username=ada&password=correct+horse+battery"),
    )
    .await;
    (request, flow, page)
}

/// Signs `ada` in again on the hosted page, with her password and the key
/// `credential_id`, whose counter is now `counter`. Returns her new session
/// cookie.
async fn sign_in_with_key(started: &Started, credential_id: &str, counter: u64) -> String {
    let (request, flow, asked) = give_password_in_a_new_browser(started).await;
    let answer = TrustingKeys::answer_proof(&read_key_options(&asked.body), credential_id, counter);
    post(
        &started.product,
        LOGIN,
        &[(COOKIE.as_str(), flow.as_str())],
        &format!("request={request}&{}", write_key_field(&answer)),
    )
    .await
    .read_cookie("__Host-saffui_session_acme=")
    .expect("a session")
}

fn runs_the_key_script_and_nothing_else(page: &Answer) -> bool {
    let policy = page.read_header("content-security-policy").unwrap_or("");
    let Some(named) = read_between(policy, "script-src 'nonce-", "'") else {
        return false;
    };
    policy.starts_with("default-src 'none';")
        && page.body.matches("<script").count() == 1
        && page.body.contains(&format!("<script nonce=\"{named}\">"))
}

#[actix_web::test]
async fn a_person_adds_a_security_key_with_their_password_and_the_answer_of_the_key() {
    let started = start().await;
    let cookie = [(COOKIE.as_str(), started.session.as_str())];

    let page = get(&started.product, SECURITY_KEY, &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("No security key is set up"));
    assert_eq!(page.read_header("cache-control"), Some("no-store"));
    assert!(
        !page.body.contains("<script"),
        "a page that asks no key runs nothing"
    );

    let wrong_password = post(
        &started.product,
        SECURITY_KEY,
        &cookie,
        "password=not+the+password",
    )
    .await;
    assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
    assert!(!wrong_password.body.contains("data-options"));

    let asked = post(
        &started.product,
        SECURITY_KEY,
        &cookie,
        "password=correct+horse+battery",
    )
    .await;
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    assert!(asked.body.contains("data-ceremony=\"create\""));
    assert!(
        runs_the_key_script_and_nothing_else(&asked),
        "{}",
        asked.body
    );
    let options = read_key_options(&asked.body);
    assert_eq!(options["user"], "ada");
    let answer = write_key_field(&TrustingKeys::answer_enrollment(&options, "k1"));

    let silent = post(&started.product, CONFIRM_KEY, &cookie, "key=").await;
    assert_eq!(silent.status, StatusCode::BAD_REQUEST);
    assert!(silent.body.contains("The security key did not answer."));
    let added = post(&started.product, CONFIRM_KEY, &cookie, &answer).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.body);
    assert!(added.body.contains("Your security key is set up."));

    let again = post(&started.product, CONFIRM_KEY, &cookie, &answer).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert!(again.body.contains("The security key was not accepted."));
    assert!(again.body.contains("Start again"));
    let page = get(&started.product, SECURITY_KEY, &cookie).await;
    assert!(
        page.body.contains("1 security key is set up"),
        "{}",
        page.body
    );
}

#[actix_web::test]
async fn where_keys_are_not_served_the_page_offers_no_form_and_says_why() {
    let mut started = start().await;
    let cookie = [(COOKIE.as_str(), started.session.as_str())];
    let served = get(&started.product, SECURITY_KEY, &cookie).await;
    assert!(served.body.contains("<form"), "{}", served.body);

    started.product.security_keys = Arc::new(UnservedKeys);

    let page = get(&started.product, SECURITY_KEY, &cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("No security key is set up"));
    assert!(
        page.body.contains("This service cannot use security keys"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<form"), "{}", page.body);
    let posted = post(
        &started.product,
        SECURITY_KEY,
        &cookie,
        "password=correct+horse+battery",
    )
    .await;
    assert_eq!(posted.status, StatusCode::FORBIDDEN, "{}", posted.body);
    assert!(posted.body.contains("cannot use security keys"));
    assert!(!posted.body.contains("data-options"));
}

#[actix_web::test]
async fn the_pages_of_the_security_key_serve_nobody_without_a_session_or_from_another_site() {
    let started = start().await;
    let evil = [
        (COOKIE.as_str(), started.session.as_str()),
        (ORIGIN.as_str(), "https://evil.example.test"),
    ];
    let password = "password=correct+horse+battery";

    let anonymous: [Answer; 3] = [
        get(&started.product, SECURITY_KEY, &[]).await,
        post(&started.product, SECURITY_KEY, &[], password).await,
        post(&started.product, CONFIRM_KEY, &[], "key=%7B%7D").await,
    ];
    let from_another_site: [Answer; 2] = [
        post(&started.product, SECURITY_KEY, &evil, password).await,
        post(&started.product, CONFIRM_KEY, &evil, "key=%7B%7D").await,
    ];

    for refused in anonymous.iter().chain(&from_another_site) {
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        assert!(refused.body.contains("Sign in from an application first."));
        assert!(!refused.body.contains("data-options"));
    }
}

#[actix_web::test]
async fn a_key_form_is_read_after_its_guard_and_within_the_limit_of_the_plane() {
    let started = start().await;
    let cookie = [(COOKIE.as_str(), started.session.as_str())];
    let evil = [
        (COOKIE.as_str(), started.session.as_str()),
        (ORIGIN.as_str(), "https://evil.example.test"),
    ];
    // Well formed, and larger than the forms the plane reads: read whole,
    // the password would be checked, and refused with 401.
    let large = format!("password={}", "a".repeat(9 * 1024));

    for path in [SECURITY_KEY, CONFIRM_KEY] {
        let from_another_site = post(&started.product, path, &evil, &large).await;
        assert_eq!(from_another_site.status, StatusCode::UNAUTHORIZED, "{path}");
        assert!(
            from_another_site
                .body
                .contains("Sign in from an application first."),
            "the guard answers, not the form: {}",
            from_another_site.body
        );

        let from_here = post(&started.product, path, &cookie, &large).await;
        assert_eq!(from_here.status, StatusCode::BAD_REQUEST, "{path}");
        assert!(
            from_here.body.contains("<h1>Security key</h1>"),
            "the page answers: {}",
            from_here.body
        );
    }
}

#[actix_web::test]
async fn a_person_with_a_security_key_signs_in_with_their_password_then_the_key() {
    let started = start().await;
    add_key(&started, "k1").await;

    let (request, flow, asked) = give_password_in_a_new_browser(&started).await;
    let cookie = [(COOKIE.as_str(), flow.as_str())];
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    assert!(asked.body.contains("data-ceremony=\"get\""));
    assert!(!asked.body.contains("name=\"code\""));
    assert!(!asked.body.contains("name=\"password\""));
    assert!(
        runs_the_key_script_and_nothing_else(&asked),
        "{}",
        asked.body
    );
    assert!(
        asked.cookies.is_empty(),
        "no session before the key: {:?}",
        asked.cookies
    );
    let options = read_key_options(&asked.body);
    let answer_as = |credential_id: &str| {
        let answer = TrustingKeys::answer_proof(&options, credential_id, 1);
        format!("request={request}&{}", write_key_field(&answer))
    };

    let silent = post(
        &started.product,
        LOGIN,
        &cookie,
        &format!("request={request}&key="),
    )
    .await;
    assert_eq!(silent.status, StatusCode::BAD_REQUEST);
    assert!(silent.body.contains("The security key did not answer."));
    assert_eq!(
        read_key_options(&silent.body),
        options,
        "the same challenge waits"
    );

    let refused = post(&started.product, LOGIN, &cookie, &answer_as("k2")).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(refused.body.contains("The security key was not accepted."));
    assert!(refused.body.contains("data-ceremony=\"get\""));
    assert!(refused.cookies.is_empty());

    let signed_in = post(&started.product, LOGIN, &cookie, &answer_as("k1")).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    assert!(
        signed_in
            .location
            .as_deref()
            .is_some_and(|location| location.starts_with("https://app.example.test/callback?code=")),
        "{:?}",
        signed_in.location
    );
    assert!(
        signed_in
            .read_cookie("__Host-saffui_session_acme=")
            .is_some()
    );
}

#[actix_web::test]
async fn a_person_with_a_code_and_a_key_is_offered_both_and_let_in_by_the_code() {
    let started = start().await;
    let secret = enroll(&started).await;
    let refused = post(
        &started.product,
        SECURITY_KEY,
        &[(COOKIE.as_str(), started.session.as_str())],
        "password=correct+horse+battery",
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "a session the password alone opened adds no key beside the code"
    );
    started.clock.advance(Duration::from_secs(30));
    let proven = sign_in_with_code(&started, &secret).await;
    add_key_in(&started, &proven, "k1").await;
    started.clock.advance(Duration::from_secs(30));

    let (request, flow, asked) = give_password_in_a_new_browser(&started).await;

    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    assert!(asked.body.contains("name=\"code\""));
    assert!(asked.body.contains("data-ceremony=\"get\""));
    let refused = post(
        &started.product,
        LOGIN,
        &[(COOKIE.as_str(), flow.as_str())],
        &format!("request={request}&code=000000"),
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(
        refused.body.contains("name=\"code\"") && refused.body.contains("data-ceremony=\"get\""),
        "both are still offered: {}",
        refused.body
    );
    let signed_in = post(
        &started.product,
        LOGIN,
        &[(COOKIE.as_str(), flow.as_str())],
        &format!(
            "request={request}&code={}",
            read_code_now(&started, &secret)
        ),
    )
    .await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
}

#[actix_web::test]
async fn the_answer_of_a_key_given_before_any_password_finishes_nothing() {
    let started = start().await;
    add_key(&started, "k1").await;
    let sent_to_login = get(
        &started.product,
        &write_authorize_path(&started.product),
        &[],
    )
    .await;
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
        .read_cookie("__Host-saffui_flow_")
        .expect("a flow cookie");
    let unasked = TrustingKeys::answer_proof(&serde_json::json!({ "challenge": "c" }), "k1", 1);

    for form in [
        format!("request={request}&{}", write_key_field(&unasked)),
        format!("request={request}&key="),
    ] {
        let skipped = post(
            &started.product,
            LOGIN,
            &[(COOKIE.as_str(), flow.as_str())],
            &form,
        )
        .await;

        assert_eq!(skipped.status, StatusCode::BAD_REQUEST);
        assert!(skipped.body.contains("This sign-in has expired."));
        assert!(skipped.cookies.is_empty());
    }
}

#[actix_web::test]
async fn an_administrator_takes_the_security_keys_away_and_the_password_is_enough_again() {
    let started = start().await;
    add_key(&started, "k1").await;
    let proven = sign_in_with_key(&started, "k1", 1).await;
    add_key_in(&started, &proven, "k2").await;
    let person = {
        let mut work = started
            .product
            .storage
            .begin(started.scope)
            .await
            .expect("a unit of work");
        work.read_person_by_username("ada")
            .await
            .expect("a read")
            .expect("ada")
            .id
    };
    let writer = create_administrator(
        &started.product,
        "acme",
        started.scope,
        "operator",
        &[Capability::UserWrite],
    )
    .await;
    let reader = create_administrator(
        &started.product,
        "acme",
        started.scope,
        "auditor",
        &[Capability::UserRead],
    )
    .await;
    let remove = async |token: &str, person: &str| {
        let bearer = format!("Bearer {token}");
        let path = format!("/admin/v1/realms/acme/users/{person}/security-keys");
        let sent = Sent {
            method: Method::DELETE,
            path: &path,
            head: &[(AUTHORIZATION.as_str(), bearer.as_str())],
            form: None,
        };
        send(&started.product, sent).await.status
    };

    assert_eq!(
        remove(&reader, &person.to_string()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        remove(&writer, "not-an-identifier").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        remove(&writer, &person.to_string()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        remove(&writer, &person.to_string()).await,
        StatusCode::NOT_FOUND
    );

    let (_, _, signed_in) = give_password_in_a_new_browser(&started).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
}
