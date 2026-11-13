use actix_web::http::header::{COOKIE, ORIGIN};
use actix_web::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::register::{NewClient, register_client};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{create_administrator, create_person, create_realm};
use saffui_core::testkit::memory::MemoryStorage;

use super::admin::call;
use super::login::{Answer, get, post};

const CALLBACK: &str = "https://app.example.test/callback";
const PASSWORD: &str = "correct horse battery";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CONSENT: &str = "/realms/acme/consent";
const CONSENTS: &str = "/realms/acme/account/consents";
const WITHDRAW: &str = "/realms/acme/account/consents/withdraw";
const EVIL: (&str, &str) = ("origin", "https://evil.example.test");

/// The realm `acme`, the person `ada`, and `partner`, an application that
/// requires the consent of each person, named as whoever registered it chose.
async fn start(name: &str) -> (saffui_core::app::App, RealmScope) {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", PASSWORD).await;
    let scopes = ["openid", "email", "offline_access"].map(str::to_owned);
    let callbacks = [CALLBACK.to_owned()];
    let mut work = product.storage.begin(scope).await.expect("a unit of work");
    register_client(
        &product,
        work.as_mut(),
        NewClient {
            client_id: "partner",
            name,
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            public: true,
            requires_consent: true,
            id_token_signed_response_alg: None,
            created_by: None,
        },
    )
    .await
    .expect("a client");
    work.commit().await.expect("a commit");
    (product, scope)
}

/// Where `partner` sends a browser to ask for `scope`, written for a query.
fn write_authorize_path(product: &saffui_core::app::App, scope: &str) -> String {
    let challenge = URL_SAFE_NO_PAD.encode(product.digester.sha256(VERIFIER.as_bytes()));
    format!(
        "/realms/acme/oauth2/authorize?response_type=code&client_id=partner\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&scope={scope}\
         &state=xyz&code_challenge={challenge}&code_challenge_method=S256"
    )
}

/// What a browser holds once `ada` signed in for `partner`: the request that
/// waits for her answer, and its cookies.
struct Waiting {
    request: String,
    flow: String,
    session: String,
}

impl Waiting {
    fn send_both(&self) -> String {
        format!("{}; {}", self.flow, self.session)
    }

    fn write_answer(&self, decision: &str) -> String {
        format!("request={}&decision={decision}", self.request)
    }
}

async fn sign_in_for_partner(product: &saffui_core::app::App) -> (Waiting, Answer) {
    sign_in_for_partner_asking(product, "openid%20email").await
}

async fn sign_in_for_partner_asking(
    product: &saffui_core::app::App,
    scope: &str,
) -> (Waiting, Answer) {
    let sent_to_login = get(product, &write_authorize_path(product, scope), &[]).await;
    assert_eq!(sent_to_login.status, StatusCode::SEE_OTHER);
    let request = sent_to_login
        .read_location_parameter("request")
        .expect("a pending request");
    let flow = sent_to_login
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
    let session = signed_in
        .read_cookie("__Host-saffui_session_acme=")
        .expect("a session cookie");
    let waiting = Waiting {
        request,
        flow,
        session,
    };
    (waiting, signed_in)
}

#[actix_web::test]
async fn a_person_who_signed_in_is_asked_on_a_page_and_sent_back_with_a_code_once_they_allow() {
    let (product, _) = start("Partner <b>Inc</b>").await;

    let (waiting, signed_in) = sign_in_for_partner(&product).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    assert_eq!(
        signed_in.location.as_deref(),
        Some(format!("{CONSENT}?request={}", waiting.request).as_str())
    );
    assert!(
        signed_in
            .cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-saffui_mark_acme=")),
        "the browser is marked as at any sign-in: {:?}",
        signed_in.cookies
    );
    assert!(
        !signed_in
            .cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-saffui_flow_")),
        "the flow goes on, and keeps its cookie: {:?}",
        signed_in.cookies
    );

    let page_path = format!("{CONSENT}?request={}", waiting.request);
    let both = waiting.send_both();
    let page = get(&product, &page_path, &[(COOKIE.as_str(), &both)]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("Partner &#60;b&#62;Inc&#60;/b&#62;") && !page.body.contains("<b>Inc"),
        "the name is text: {}",
        page.body
    );
    assert!(page.body.contains("<li>email</li>"), "{}", page.body);
    assert!(
        page.read_header("content-security-policy")
            .is_some_and(|policy| policy.contains("frame-ancestors 'none'")),
        "no other site frames the page to have it allowed"
    );

    let allowed = post(
        &product,
        CONSENT,
        &[(COOKIE.as_str(), &both)],
        &waiting.write_answer("allow"),
    )
    .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);
    let back = allowed.location.clone().expect("a location");
    assert!(back.starts_with(&format!("{CALLBACK}?code=")), "{back}");
    assert_eq!(
        allowed.read_location_parameter("state").as_deref(),
        Some("xyz")
    );
    assert!(
        allowed.cookies.iter().any(|cookie| cookie
            .starts_with(&format!("__Host-saffui_flow_{}=;", waiting.request))
            && cookie.contains("Max-Age=0")),
        "the flow is over: {:?}",
        allowed.cookies
    );
    let code = allowed.read_location_parameter("code").expect("a code");
    let exchange = format!(
        "grant_type=authorization_code&client_id=partner&code={code}\
         &redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_verifier={VERIFIER}"
    );
    let tokens = post(&product, "/realms/acme/oauth2/token", &[], &exchange).await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);

    let again = post(
        &product,
        CONSENT,
        &[(COOKIE.as_str(), &both)],
        &waiting.write_answer("deny"),
    )
    .await;
    assert_eq!(
        again.status,
        StatusCode::BAD_REQUEST,
        "a request is answered once"
    );
}

#[actix_web::test]
async fn the_page_answers_only_the_browser_and_the_session_the_request_waits_for() {
    let (product, _) = start("Partner").await;
    let (waiting, _) = sign_in_for_partner(&product).await;
    let page_path = format!("{CONSENT}?request={}", waiting.request);
    let both = waiting.send_both();

    for refused in [
        get(&product, &page_path, &[(COOKIE.as_str(), &waiting.flow)]).await,
        get(&product, &page_path, &[(COOKIE.as_str(), &waiting.session)]).await,
        get(&product, CONSENT, &[(COOKIE.as_str(), &both)]).await,
        post(
            &product,
            CONSENT,
            &[(COOKIE.as_str(), &both), EVIL],
            &waiting.write_answer("allow"),
        )
        .await,
        post(
            &product,
            CONSENT,
            &[(COOKIE.as_str(), &both)],
            &waiting.write_answer("maybe"),
        )
        .await,
    ] {
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
        assert!(refused.location.is_none());
        assert!(
            !refused.body.contains("name=\"decision\""),
            "{}",
            refused.body
        );
    }

    let denied = post(
        &product,
        CONSENT,
        &[
            (COOKIE.as_str(), &both),
            (ORIGIN.as_str(), "https://id.example.test"),
        ],
        &waiting.write_answer("deny"),
    )
    .await;
    assert_eq!(denied.status, StatusCode::SEE_OTHER, "{}", denied.body);
    assert_eq!(
        denied.read_location_parameter("error").as_deref(),
        Some("access_denied"),
        "the request waited, and a refusal goes back to the client"
    );
    assert_eq!(denied.read_location_parameter("code"), None);
}

#[actix_web::test]
async fn a_name_that_changes_direction_is_shown_with_the_change_replaced() {
    use saffui_core::clients::Client;

    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_person(&product, scope, "ada", PASSWORD).await;
    // Written behind the back of the product, which refuses such a name.
    let partner = Client {
        id: uuid::Uuid::from_u128(9),
        client_id: "partner".to_owned(),
        name: "Pay\u{202e}lapyap".to_owned(),
        secret_digest: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec![CALLBACK.to_owned()],
        post_logout_redirect_uris: Vec::new(),
        requires_consent: true,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        enabled: true,
        created_at: product.now(),
    };
    let mut work = product.storage.begin(scope).await.expect("a unit of work");
    work.insert_client(&partner).await.expect("a client");
    work.commit().await.expect("a commit");
    let (waiting, _) = sign_in_for_partner(&product).await;

    let page = get(
        &product,
        &format!("{CONSENT}?request={}", waiting.request),
        &[(COOKIE.as_str(), &waiting.send_both())],
    )
    .await;

    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("Pay\u{fffd}lapyap"), "{}", page.body);
    assert!(!page.body.contains('\u{202e}'));
}

#[actix_web::test]
async fn the_consent_page_reads_its_form_after_its_guard() {
    let (product, _) = start("Partner").await;
    let (waiting, _) = sign_in_for_partner(&product).await;
    let both = waiting.send_both();
    // Well formed, and larger than the forms the plane reads.
    let large = format!(
        "{}&padding={}",
        waiting.write_answer("allow"),
        "a".repeat(9 * 1024)
    );

    let from_elsewhere = post(&product, CONSENT, &[(COOKIE.as_str(), &both), EVIL], &large).await;
    assert!(
        from_elsewhere.body.contains("This sign-in has expired."),
        "refused by its origin, unread: {}",
        from_elsewhere.body
    );
    let from_here = post(&product, CONSENT, &[(COOKIE.as_str(), &both)], &large).await;
    assert_eq!(from_here.status, StatusCode::BAD_REQUEST);
    assert!(
        from_here
            .body
            .contains("The request is missing a parameter or carries one it cannot."),
        "read, and refused as a form: {}",
        from_here.body
    );
    let page = get(
        &product,
        &format!("{CONSENT}?request={}", waiting.request),
        &[(COOKIE.as_str(), &both)],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK, "the request still waits");
}

/// Signs `ada` in for `partner` and allows it: her session cookie.
async fn consent_once(product: &saffui_core::app::App) -> String {
    let (waiting, _) = sign_in_for_partner(product).await;
    let allowed = post(
        product,
        CONSENT,
        &[(COOKIE.as_str(), &waiting.send_both())],
        &waiting.write_answer("allow"),
    )
    .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);
    waiting.session
}

#[actix_web::test]
async fn a_person_withdraws_on_their_account_page_what_they_allowed() {
    let (product, _) = start("Partner <b>Inc</b>").await;
    let session = consent_once(&product).await;
    let cookie = [(COOKIE.as_str(), session.as_str())];

    let listed = get(&product, CONSENTS, &cookie).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert!(
        listed.body.contains("Partner &#60;b&#62;Inc&#60;/b&#62;"),
        "{}",
        listed.body
    );
    assert!(listed.body.contains("value=\"partner\""), "{}", listed.body);
    assert!(listed.body.contains("openid, email"), "{}", listed.body);

    let withdrawn = post(&product, WITHDRAW, &cookie, "client_id=partner").await;
    assert_eq!(withdrawn.status, StatusCode::OK, "{}", withdrawn.body);
    let empty = get(&product, CONSENTS, &cookie).await;
    assert!(
        empty.body.contains("You allowed no application anything."),
        "{}",
        empty.body
    );
    let again = post(&product, WITHDRAW, &cookie, "client_id=partner").await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{}", again.body);
}

#[actix_web::test]
async fn the_account_page_serves_nobody_without_a_session_and_reads_its_form_after_its_guard() {
    let (product, _) = start("Partner").await;
    let session = consent_once(&product).await;
    let evil = [(COOKIE.as_str(), session.as_str()), EVIL];
    // Well formed, and larger than the forms the plane reads.
    let large = format!("client_id={}", "a".repeat(9 * 1024));

    for refused in [
        get(&product, CONSENTS, &[]).await,
        post(&product, WITHDRAW, &[], "client_id=partner").await,
        post(&product, WITHDRAW, &evil, "client_id=partner").await,
        post(&product, WITHDRAW, &evil, &large).await,
    ] {
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);
        assert!(refused.body.contains("Sign in from an application first."));
    }
    let from_here = post(
        &product,
        WITHDRAW,
        &[(COOKIE.as_str(), session.as_str())],
        &large,
    )
    .await;
    assert_eq!(
        from_here.status,
        StatusCode::BAD_REQUEST,
        "{}",
        from_here.body
    );
    let listed = get(&product, CONSENTS, &[(COOKIE.as_str(), session.as_str())]).await;
    assert!(
        listed.body.contains("value=\"partner\""),
        "nothing was withdrawn: {}",
        listed.body
    );
}

#[actix_web::test]
async fn an_administrator_reads_what_a_person_allowed_and_a_writer_of_people_withdraws_it() {
    let (product, scope) = start("Partner").await;
    consent_once(&product).await;
    let reader =
        create_administrator(&product, "acme", scope, "reader", &[Capability::UserRead]).await;
    let writer =
        create_administrator(&product, "acme", scope, "writer", &[Capability::UserWrite]).await;
    let ada = {
        let mut work = product.storage.begin(scope).await.expect("a unit of work");
        work.read_person_by_username("ada")
            .await
            .expect("a read")
            .expect("ada")
            .id
    };
    let listing = format!("/admin/v1/realms/acme/users/{ada}/consents");
    let withdrawal = format!("{listing}/partner");

    let listed = call(&product, Method::GET, &listing, Some(&reader), None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.body["items"][0]["client_id"], "partner");
    assert_eq!(
        listed.body["items"][0]["scopes"],
        serde_json::json!(["openid", "email"])
    );
    let unread = call(&product, Method::GET, &listing, Some(&writer), None).await;
    assert_eq!(unread.status, StatusCode::FORBIDDEN);
    let unwritten = call(&product, Method::DELETE, &withdrawal, Some(&reader), None).await;
    assert_eq!(unwritten.status, StatusCode::FORBIDDEN);

    let withdrawn = call(&product, Method::DELETE, &withdrawal, Some(&writer), None).await;
    assert_eq!(
        withdrawn.status,
        StatusCode::NO_CONTENT,
        "{}",
        withdrawn.body
    );
    let again = call(&product, Method::DELETE, &withdrawal, Some(&writer), None).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    let nobody = call(
        &product,
        Method::GET,
        "/admin/v1/realms/acme/users/not-a-person/consents",
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(nobody.status, StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn the_page_says_in_words_what_offline_access_lets_the_client_do() {
    let (product, _) = start("Partner").await;
    let (waiting, _) = sign_in_for_partner_asking(&product, "openid%20offline_access").await;

    let page = get(
        &product,
        &format!("{CONSENT}?request={}", waiting.request),
        &[(COOKIE.as_str(), &waiting.send_both())],
    )
    .await;

    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("for 90 days, even after you sign out")
            && page.body.contains("withdraw this from your account"),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains("offline_access"),
        "said in words, not as a word of the protocol: {}",
        page.body
    );
}
