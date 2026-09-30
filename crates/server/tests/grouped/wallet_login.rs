use super::support;
use super::support::Plane;
use super::wallet::{
    CREDENTIAL_TYPE, IDENTITY_TYPE, IdentityWallet, Wallet, answered, asked, asked_under,
    encrypted, fetched, identity_answer, mint_request_key, name_pid_issuer, plane_that_verifies,
    read_request, realm_ready_for_identity, realm_ready_to_verify, serve_pid_issuer, served,
};
use actix_web::http::{Method, StatusCode};
use serde_json::{Value, json};
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

/// A password, then a wallet: the flow a person steps up through.
const WALLET_FLOW: &str = "browser-wallet";

/// How the realm knows people in these cases: a PID, by its family name.
fn identity_profile(wallet: &Wallet) -> Value {
    json!({
        "credential_query": {
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "claims": [{ "path": ["family_name"] }, { "path": ["given_name"] }]
        },
        "issuer": format!("{}/pid", wallet.issuer),
        "identifier_path": ["family_name"],
    })
}

/// A browser's call to a public door, carrying the login's cookie.
async fn browsed(
    plane: &Plane,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Vec<String>) {
    use actix_web::{App, test};
    use server::api::config::register;
    let app = test::init_service(
        App::new().configure(register(&served(plane, config::serving::Egress::Outward))),
    )
    .await;
    let mut request = test::TestRequest::default().method(method).uri(path);
    if let Some(cookie) = cookie {
        request = request.insert_header((
            "cookie",
            format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
        ));
    }
    if let Some(body) = body {
        request = request.set_json(body);
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let set = response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let body = test::read_body(response).await;
    (
        status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
        set,
    )
}

/// Open a login for the confidential client, and hand back its cookie.
async fn open_login(plane: &Plane, extra: &[(&str, &str)]) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in [
        ("response_type", "code"),
        ("client_id", support::CONFIDENTIAL),
        ("redirect_uri", support::REDIRECT),
        ("scope", "openid"),
        ("state", "opaque-state"),
    ]
    .iter()
    .chain(extra)
    {
        query.append_pair(key, value);
    }
    let (status, told, set) = browsed(
        plane,
        Method::GET,
        &format!(
            "/realms/{REALM}/protocol/openid-connect/auth?{}",
            query.finish()
        ),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "{told}");
    support::cookie_value(&set, support::AUTH_SESSION_COOKIE).expect("a binding")
}

/// One round with the password, as the page plays every round.
async fn play_password_round(plane: &Plane, cookie: &str) -> (StatusCode, Value) {
    let (status, told, _) = browsed(
        plane,
        Method::POST,
        &format!("/realms/{REALM}/protocol/openid-connect/login"),
        Some(cookie),
        Some(json!({ "username": support::SUBJECT, "password": support::PASSWORD })),
    )
    .await;
    (status, told)
}

/// The same round, posted by a browser running no script: a form carrying
/// what the page was served with.
async fn play_password_round_as_a_form(plane: &Plane, cookie: &str) -> (StatusCode, String) {
    use actix_web::{App, test};
    use server::api::config::register;
    let minted = support::page_token_for(plane, cookie).await;
    let app = test::init_service(
        App::new().configure(register(&served(plane, config::serving::Egress::Outward))),
    )
    .await;
    let request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/login"))
        .insert_header((
            "cookie",
            format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
        ))
        .set_form([
            ("username", support::SUBJECT),
            ("password", support::PASSWORD),
            ("page_token", minted.as_str()),
        ])
        .to_request();
    let response = test::call_service(&app, request).await;
    let location = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (response.status(), location)
}

/// Whether the presentation the login waits on is settled, as the page asks.
async fn read_settled(plane: &Plane, cookie: Option<&str>) -> (StatusCode, Value) {
    let (status, told, _) = browsed(
        plane,
        Method::GET,
        &format!("/realms/{REALM}/protocol/openid-connect/login/wallet"),
        cookie,
        None,
    )
    .await;
    (status, told)
}

/// A wallet as these cases play one: a PID in SD-JWT, or an identity
/// credential in JSON-LD.
#[derive(Clone, Copy)]
enum Holder<'a> {
    Pid(&'a Wallet),
    Identity(&'a IdentityWallet),
}

/// The wallet answering the request a challenge links to, disclosing the
/// claims the realm asks for, and the request's id beside what the realm said.
async fn answer_as(
    plane: &Plane,
    holder: Holder<'_>,
    asks: &Value,
) -> (String, StatusCode, String) {
    let request = read_request(plane, asks["wallet"]["uri"].as_str().expect("a link")).await;
    let client_id = request["client_id"].as_str().expect("a client_id");
    let nonce = request["nonce"].as_str().expect("a nonce");
    let answer = match holder {
        Holder::Pid(wallet) => json!({
            "vp_token": {
                "pid": [wallet.presented_disclosing(client_id, nonce, &["family_name", "given_name"])],
            },
            "state": request["state"],
        }),
        Holder::Identity(wallet) => identity_answer(
            wallet.presented(wallet.issued(), client_id, nonce),
            &request,
        ),
    };
    let (status, told) = answered(
        plane,
        &request,
        &[("response", &encrypted(&request, &answer))],
    )
    .await;
    (
        request["state"].as_str().expect("a state").to_owned(),
        status,
        told,
    )
}

/// The same answer, taken. Hands back the request's id.
async fn present(plane: &Plane, holder: Holder<'_>, asks: &Value) -> String {
    let (request_id, status, told) = answer_as(plane, holder, asks).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    request_id
}

/// The wallet declining the request a challenge links to.
async fn decline(plane: &Plane, asks: &Value) {
    let request = read_request(plane, asks["wallet"]["uri"].as_str().expect("a link")).await;
    let state = request["state"].as_str().expect("a state").to_owned();
    let (status, told) = answered(
        plane,
        &request,
        &[("error", "access_denied"), ("state", &state)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

/// What the challenge shows for a request: the link, and the same link drawn.
fn assert_shows_its_link(asks: &Value) {
    let uri = asks["wallet"]["uri"].as_str().expect("a link");
    assert!(uri.starts_with("openid4vp://authorize?"), "{asks}");
    assert_eq!(
        asks["wallet"]["qr"].as_str(),
        commons::qr::draw_qr_svg(uri).as_deref(),
        "the QR code draws another link"
    );
}

/// Say how the realm knows people, as its administrator.
async fn keep_profile(plane: &Plane, bearer: &str, profile: &Value) -> (StatusCode, Value) {
    asked(
        plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/wallet-identity"),
        bearer,
        Some(profile.clone()),
    )
    .await
}

/// Open the ceremony an application asks for, as far as the wallet's request:
/// the login's cookie, and what its challenge asks.
async fn open_linking(plane: &Plane) -> (String, Value) {
    let cookie = open_login(plane, &[("enrol", "link-wallet-identity")]).await;
    let (status, told) = play_password_round(plane, &cookie).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        (
            &told["status"],
            &told["execution"],
            &told["asks"]["optional"]
        ),
        (
            &json!("challenge"),
            &json!("link-wallet-identity"),
            &json!(true)
        ),
        "{told}"
    );
    assert_shows_its_link(&told["asks"]);
    (cookie, told["asks"].clone())
}

/// Link the subject's identity to their account through the ceremony an
/// application asks for, the way the page and the wallet play it.
async fn link_by_ceremony(plane: &Plane, holder: Holder<'_>) {
    let (cookie, asks) = open_linking(plane).await;
    assert_eq!(
        read_settled(plane, Some(&cookie)).await,
        (StatusCode::OK, json!({ "settled": false }))
    );

    present(plane, holder, &asks).await;
    assert_eq!(
        read_settled(plane, Some(&cookie)).await,
        (StatusCode::OK, json!({ "settled": true }))
    );
    let (status, told) = play_password_round(plane, &cookie).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "{told}"
    );
}

/// What the account console reads of the subject's factors, as it reads them.
async fn read_own_factors(plane: &Plane) -> Value {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    services::realm::provisioning::provision_account_console(
        &transaction,
        support::TENANT,
        REALM,
        &services::realm::provisioning::AccountConsole {
            redirect_uris: vec![services::account::api::compose_account_console_redirect(
                &support::origin().issuer(REALM),
            )],
        },
    )
    .await
    .expect("the account console");
    transaction
        .commit()
        .await
        .expect("the account console kept");
    let bearer = plane.token(&support::account_console_claims());
    let (status, told) = asked(
        plane,
        Method::GET,
        &format!("/realms/{REALM}/account-api/v1/me/credentials"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    told
}

/// The flow a password and then a wallet, bound to the confidential client.
async fn bind_wallet_flow(plane: &Plane) {
    use models::auditable::AuditableModel;
    use models::entities::auth::{
        AuthenticationExecutionMutationModel, AuthenticationFlowMutationModel,
        AuthenticatorRequirement, ExecutionStep,
    };
    use store::providers::realms::auth_flows;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let metadata = || AuditableModel::from_creator(support::TENANT.into(), "root".into());
    let flow = AuthenticationFlowMutationModel {
        alias: WALLET_FLOW.into(),
        provider_id: "basic-flow".into(),
        description: String::new(),
        top_level: Some(true),
        built_in: Some(false),
    }
    .into_model(WALLET_FLOW.into(), REALM.into(), metadata());
    auth_flows::create_flow(&transaction, &flow).await.unwrap();
    for (id, authenticator, priority) in [
        ("exec-wallet-1", "password", 10),
        ("exec-wallet-2", "wallet", 20),
    ] {
        let step = AuthenticationExecutionMutationModel {
            alias: id.into(),
            flow_id: WALLET_FLOW.into(),
            priority,
            step: ExecutionStep::Authenticator {
                authenticator: authenticator.into(),
                config_id: None,
            },
            requirement: AuthenticatorRequirement::Required,
        }
        .into_model(id.into(), REALM.into(), metadata());
        auth_flows::create_execution(&transaction, &step)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
    plane
        .bind_browser_flow(support::CONFIDENTIAL, WALLET_FLOW)
        .await;
}

/// The realm says how it knows people, a person links the identity their
/// wallet proves through the ceremony an application asks for, and then signs
/// in with it as a second factor. What the realm keeps is a digest under its
/// own key, which a rewritten profile keeps answering to; an administrator
/// never reads a login's request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_links_their_wallet_identity_then_signs_in_with_it() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let profile_door = format!("/admin/realms/{REALM}/wallet-identity");

    let (status, told) = asked(&plane, Method::GET, &profile_door, &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.wallet_identity.not_found");
    let profile = identity_profile(&wallet);
    let (status, kept) = keep_profile(&plane, &bearer, &profile).await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    for member in ["credential_query", "issuer", "identifier_path"] {
        assert_eq!(kept[member], profile[member], "{member}");
    }
    let (status, read) = asked(&plane, Method::GET, &profile_door, &bearer, None).await;
    assert_eq!((status, &read), (StatusCode::OK, &kept));

    link_by_ceremony(&plane, Holder::Pid(&wallet)).await;
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let linked =
        store::providers::directory::wallet_identities::of_user(&transaction, support::SUBJECT)
            .await
            .unwrap();
    assert_eq!(
        linked
            .iter()
            .map(|held| held.issuer.as_str())
            .collect::<Vec<_>>(),
        [format!("{}/pid", wallet.issuer)]
    );
    let digest: String = transaction
        .query_one("SELECT digest FROM wallet_identities", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(digest.len(), 64, "{digest}");
    let factors = read_own_factors(&plane).await;
    assert_eq!(factors["wallet_offered"], true, "{factors}");
    assert_eq!(
        factors["wallet_identities"][0]["issuer"],
        json!(format!("{}/pid", wallet.issuer)),
        "{factors}"
    );
    let kept_outcomes: Vec<Option<Value>> = transaction
        .query("SELECT outcome FROM presentation_requests", &[])
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    for outcome in &kept_outcomes {
        let written = format!("{outcome:?}");
        assert!(
            !written.contains("Lovelace"),
            "an identifier was kept: {written}"
        );
    }
    drop(transaction);

    // Rewritten, the profile keeps the key every identity was digested under.
    let (status, told) = keep_profile(&plane, &bearer, &profile).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    bind_wallet_flow(&plane).await;
    let scriptless = open_login(&plane, &[]).await;
    let (status, location) = play_password_round_as_a_form(&plane, &scriptless).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location.ends_with("#wallet-needs-script"),
        "a browser running no script was sent elsewhere: {location}"
    );

    let cookie = open_login(&plane, &[]).await;
    assert_eq!(
        read_settled(&plane, Some(&cookie)).await,
        (StatusCode::NOT_FOUND, json!({ "status": "no-such-login" })),
        "a login waiting on no wallet answered as one"
    );
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        (&told["status"], &told["execution"]),
        (&json!("challenge"), &json!("exec-wallet-2")),
        "{told}"
    );
    assert_shows_its_link(&told["asks"]);
    assert_eq!(told["asks"].get("refused"), None, "{told}");
    let request_id = present(&plane, Holder::Pid(&wallet), &told["asks"]).await;
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/presentations/{request_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        (status, &told["error_code"]),
        (
            StatusCode::NOT_FOUND,
            &json!("realm.presentation.not_found")
        ),
        "an administrator read a login's request"
    );
    assert_eq!(
        read_settled(&plane, None).await,
        (StatusCode::NOT_FOUND, json!({ "status": "no-such-login" })),
        "a browser without the login's cookie read its presentation"
    );
    assert_eq!(
        read_settled(&plane, Some(&cookie)).await,
        (StatusCode::OK, json!({ "settled": true }))
    );
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "{told}"
    );
    // What each request was asked for: the link once, then the factor at
    // each of the two sign ins, the one without a script included.
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let asked_for: Vec<(String, i64)> = transaction
        .query(
            "SELECT purpose, count(*) FROM presentation_requests GROUP BY purpose ORDER BY purpose",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        asked_for,
        [("factor".to_owned(), 2), ("link".to_owned(), 1)]
    );
}

/// A wallet that declines is asked again, saying so, and a wallet proving
/// somebody this account never linked refuses the login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_step_asks_again_after_a_refusal_and_refuses_another_identity() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let (status, told) = keep_profile(&plane, &bearer, &identity_profile(&wallet)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    link_by_ceremony(&plane, Holder::Pid(&wallet)).await;
    bind_wallet_flow(&plane).await;

    let cookie = open_login(&plane, &[]).await;
    let (_, first) = play_password_round(&plane, &cookie).await;
    assert_eq!(first["execution"], "exec-wallet-2", "{first}");
    decline(&plane, &first["asks"]).await;
    assert_eq!(
        read_settled(&plane, Some(&cookie)).await,
        (StatusCode::OK, json!({ "settled": true }))
    );
    let (status, again) = play_password_round(&plane, &cookie).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        (&again["execution"], &again["asks"]["refused"]),
        (&json!("exec-wallet-2"), &json!(true)),
        "{again}"
    );
    assert_shows_its_link(&again["asks"]);
    assert_ne!(
        again["asks"]["wallet"]["uri"], first["asks"]["wallet"]["uri"],
        "a declined request was offered again"
    );

    let somebody_else = wallet.holding_pid_of("Byron");
    present(&plane, Holder::Pid(&somebody_else), &again["asks"]).await;
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::UNAUTHORIZED, &json!("refused")),
        "{told}"
    );
}

/// The profile says what this verifier can check, an issuer the realm names
/// and a claim the credential is asked for, or it is refused in those words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_profile_names_what_can_identify_somebody() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let profile = identity_profile(&wallet);
    let mut unchecked = profile.clone();
    unchecked["credential_query"]["format"] = json!("mso_mdoc");
    let mut unnamed = profile.clone();
    unnamed["issuer"] = json!("https://nowhere.example");
    let mut unasked = profile.clone();
    unasked["identifier_path"] = json!(["birthdate"]);
    for (refused, says) in [
        (
            unchecked,
            "each credential is asked for as dc+sd-jwt or ldp_vc",
        ),
        (
            unnamed,
            "no issuer this realm names answers to https://nowhere.example",
        ),
        (
            unasked,
            "the identifier is one of the claims the credential is asked for, by its path",
        ),
    ] {
        let (status, told) = keep_profile(&plane, &bearer, &refused).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert_eq!(told["message"], says, "{told}");
    }
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/wallet-identity"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused profile was kept: {told}"
    );
}

/// A realm holding no key to sign a wallet's request with could ask no
/// wallet, and every login asking for an identity would be refused: the
/// profile waits for the key, and says which one to mint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_profile_waits_for_the_key_its_requests_are_signed_with() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = name_pid_issuer(&plane, &bearer).await;
    let (status, told) = keep_profile(&plane, &bearer, &identity_profile(&wallet)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "the realm holds no Ed25519 key to sign a request with: mint one under its keys",
        "{told}"
    );
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/wallet-identity"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a profile nothing can ask by was kept: {told}"
    );

    mint_request_key(&plane, &bearer).await;
    let (status, told) = keep_profile(&plane, &bearer, &identity_profile(&wallet)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
}

async fn read_linked_issuers(plane: &Plane) -> Vec<String> {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::directory::wallet_identities::of_user(&transaction, support::SUBJECT)
        .await
        .unwrap()
        .into_iter()
        .map(|linked| linked.issuer)
        .collect()
}

/// A credential from an issuer the realm names, and not the one it knows
/// people by, proves nobody: the ceremony asks again, saying the wallet
/// proved nothing, the request keeps why, and nothing is linked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_credential_from_another_named_issuer_links_nobody() {
    use crypto::jose::jwk::KeyPair;
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let (status, told) = keep_profile(&plane, &bearer, &identity_profile(&wallet)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let other_key = crypto::jose::jwk::alg::ed::EdKeyPair::generate(crypto::jose::jwk::Ed25519)
        .expect("an issuer key");
    let mut public = other_key.to_jwk_public_key();
    public.set_key_id("pid-2026");
    let other = serve_pid_issuer(Value::Object(public.as_ref().clone()));
    let (status, told) = asked_under(
        &plane,
        config::serving::Egress::Anywhere,
        Method::POST,
        &format!("/admin/realms/{REALM}/credential-issuers"),
        &bearer,
        Some(json!({ "name": "Another PID", "issuer": format!("{other}/pid") })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let elsewhere = Wallet::new(other, other_key);

    let (cookie, asks) = open_linking(&plane).await;
    let (_, status, told) = answer_as(&plane, Holder::Pid(&elsewhere), &asks).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{told}");
    assert_eq!(
        serde_json::from_str::<Value>(&told).expect("a JSON refusal")["error_description"],
        "a credential's issuer is not the one the realm knows people by"
    );
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        (&told["execution"], &told["asks"]["refused"]),
        (&json!("link-wallet-identity"), &json!(true)),
        "{told}"
    );
    assert_eq!(read_linked_issuers(&plane).await, Vec::<String>::new());
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let outcome: Value = transaction
        .query_one(
            "SELECT outcome FROM presentation_requests WHERE status = 'failed'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        outcome,
        json!({ "reason": "a credential's issuer is not the one the realm knows people by" })
    );
}

/// A realm that keeps no profile, or that closed the verifier, asks no wallet
/// and links nothing: the ceremony an application asks for passes, and the
/// login goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_not_knowing_people_by_a_wallet_links_nothing() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_to_verify(&plane, &bearer).await;
    let cookie = open_login(&plane, &[("enrol", "link-wallet-identity")]).await;
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "a realm keeping no profile asked a wallet: {told}"
    );

    let (status, told) = keep_profile(&plane, &bearer, &identity_profile(&wallet)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::realms::realm_features::keep_wish(
        &transaction,
        "wallet-verifier",
        false,
        "root",
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let cookie = open_login(&plane, &[("enrol", "link-wallet-identity")]).await;
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "a realm that closed the verifier asked a wallet: {told}"
    );
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let asked: i64 = transaction
        .query_one("SELECT count(*) FROM presentation_requests", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(asked, 0, "a wallet was asked");
    assert_eq!(read_linked_issuers(&plane).await, Vec::<String>::new());
}

/// A JSON-LD credential identifies somebody the same way: the identifier read
/// from what its issuer signed, linked, then proved at the sign in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_json_ld_credential_links_and_proves_an_identity() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_ready_for_identity(&plane, &bearer).await;
    let profile = json!({
        "credential_query": {
            "id": "identity",
            "format": "ldp_vc",
            "meta": { "type_values": [[CREDENTIAL_TYPE, IDENTITY_TYPE]] },
            "claims": [{ "path": ["credentialSubject", "fullName"] }]
        },
        "issuer": wallet.issuer(),
        "identifier_path": ["credentialSubject", "fullName"],
    });
    let (status, told) = keep_profile(&plane, &bearer, &profile).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    link_by_ceremony(&plane, Holder::Identity(&wallet)).await;
    assert_eq!(read_linked_issuers(&plane).await, [wallet.issuer()]);

    bind_wallet_flow(&plane).await;
    let cookie = open_login(&plane, &[]).await;
    let (_, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(told["execution"], "exec-wallet-2", "{told}");
    present(&plane, Holder::Identity(&wallet), &told["asks"]).await;
    let (status, told) = play_password_round(&plane, &cookie).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "{told}"
    );
}

/// The login door, as the page posts to it.
const LOGIN_DOOR: &str = "/realms/main/protocol/openid-connect/login";

/// The flow every realm is offered for signing in with a wallet, a wallet on
/// this device or a password, bound to the confidential client.
async fn bind_offered_wallet_flow(plane: &Plane) {
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    services::realm::provisioning::provision_offered_flows(&transaction, support::TENANT, REALM)
        .await
        .expect("the offered flows");
    transaction.commit().await.unwrap();
    plane
        .bind_browser_flow(support::CONFIDENTIAL, "wallet")
        .await;
}

/// The realm knows people by the PID's family name, and the subject linked
/// theirs; the offered wallet flow is bound. Hands back the wallet.
async fn realm_signing_in_by_wallet(plane: &Plane, bearer: &str, linked: bool) -> Wallet {
    let wallet = realm_ready_to_verify(plane, bearer).await;
    let (status, told) = keep_profile(plane, bearer, &identity_profile(&wallet)).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    if linked {
        link_by_ceremony(plane, Holder::Pid(&wallet)).await;
    }
    bind_offered_wallet_flow(plane).await;
    wallet
}

/// One round asking the wallet on this device, as the page's button plays it:
/// its link, and never a drawing of it.
async fn ask_wallet_here(plane: &Plane, cookie: &str) -> Value {
    let (status, told, _) = browsed(
        plane,
        Method::POST,
        LOGIN_DOOR,
        Some(cookie),
        Some(json!({ "wallet_sign_in": true })),
    )
    .await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("challenge")),
        "{told}"
    );
    let asks = told["asks"].clone();
    assert!(
        asks["wallet"]["uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("openid4vp://authorize?")),
        "{asks}"
    );
    assert_eq!(asks["wallet"]["same_device"], json!(true), "{asks}");
    assert!(
        asks["wallet"].get("qr").is_none(),
        "a sign-in was drawn to scan: {asks}"
    );
    asks
}

/// Where the wallet is told to bring the person back once its answer is
/// taken: the page the login is answered on, the one the deployment names in
/// these suites, with the code in the fragment.
fn read_way_back(told: &str) -> String {
    let told: Value = serde_json::from_str(told).expect("an answer in JSON");
    let back = told["redirect_uri"].as_str().expect("a way back");
    let (page, code) = back
        .split_once("#response_code=")
        .expect("a code in the fragment");
    assert_eq!(Some(page), support::login_ui().answering());
    assert_eq!(code.len(), 43, "not 256 bits written unpadded: {code}");
    code.to_owned()
}

/// One round carrying what the wallet was handed, as the page it brought the
/// person back to plays it.
async fn bring_back(plane: &Plane, cookie: Option<&str>, code: &str) -> (StatusCode, Value) {
    let (status, told, _) = browsed(
        plane,
        Method::POST,
        LOGIN_DOOR,
        cookie,
        Some(json!({ "wallet_response_code": code })),
    )
    .await;
    (status, told)
}

/// One round answering nothing, as a tab left open plays it.
async fn play_empty_round(plane: &Plane, cookie: &str) -> (StatusCode, Value) {
    let (status, told, _) = browsed(
        plane,
        Method::POST,
        LOGIN_DOOR,
        Some(cookie),
        Some(json!({})),
    )
    .await;
    (status, told)
}

/// The doors the sign-in page opens, as its body carries them.
async fn read_doors(plane: &Plane) -> String {
    let (status, page) = fetched(plane, Method::GET, LOGIN_DOOR, None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let from = page.find("data-doors=\"").expect("the doors") + "data-doors=\"".len();
    page[from..][..page[from..].find('"').expect("the doors closed")].to_owned()
}

/// A person who linked their identity signs in with the wallet on the device
/// they sign in from: the page offers it once the realm's flow does, one round
/// asks the wallet, and the wallet brings them back to the page with a code
/// that finishes the login. Answered and not yet brought back, the login waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_signs_in_with_their_wallet_on_this_device() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_signing_in_by_wallet(&plane, &bearer, true).await;
    assert!(
        !read_doors(&plane)
            .await
            .split(' ')
            .any(|door| door == "wallet")
    );
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}"),
        &bearer,
        Some(json!({ "browser_flow": "wallet" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(
        read_doors(&plane)
            .await
            .split(' ')
            .any(|door| door == "wallet"),
        "a realm signing in by wallet offered no way to"
    );

    let cookie = open_login(&plane, &[]).await;
    let asks = ask_wallet_here(&plane, &cookie).await;
    let (_, status, told) = answer_as(&plane, Holder::Pid(&wallet), &asks).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let code = read_way_back(&told);

    let (status, told) = play_empty_round(&plane, &cookie).await;
    assert_eq!(
        (status, &told["status"], &told["asks"]),
        (StatusCode::OK, &json!("challenge"), &asks),
        "an answer nobody brought back finished the login: {told}"
    );
    let (status, told) = bring_back(&plane, Some(&cookie), &code).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "{told}"
    );
    assert!(
        told["redirect_to"]
            .as_str()
            .is_some_and(|to| to.starts_with(support::REDIRECT)),
        "{told}"
    );
}

/// The code finishes the login only in the browser that asked: brought back
/// to a browser holding no login, or another login, it names nobody; the
/// browser that asked finishes nothing without it, or with a guess; and it
/// is spent once. So a link forwarded to somebody else's wallet signs its
/// sender in as nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_sign_in_is_finished_only_by_the_browser_that_asked() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_signing_in_by_wallet(&plane, &bearer, true).await;
    let asking = open_login(&plane, &[]).await;
    let asks = ask_wallet_here(&plane, &asking).await;
    let (_, status, told) = answer_as(&plane, Holder::Pid(&wallet), &asks).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let code = read_way_back(&told);

    let (status, told) = bring_back(&plane, None, &code).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    let other = open_login(&plane, &[]).await;
    let (status, told) = bring_back(&plane, Some(&other), &code).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_ne!(
        told["status"],
        json!("admitted"),
        "another login was finished: {told}"
    );
    let (status, told) = bring_back(&plane, Some(&asking), &"A".repeat(43)).await;
    assert_eq!(
        (status, &told["status"], &told["asks"]),
        (StatusCode::OK, &json!("challenge"), &asks),
        "a guessed code finished the login: {told}"
    );

    let (status, told) = bring_back(&plane, Some(&asking), &code).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "{told}"
    );
    let again = open_login(&plane, &[]).await;
    ask_wallet_here(&plane, &again).await;
    let (status, told) = bring_back(&plane, Some(&again), &code).await;
    assert_ne!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("admitted")),
        "a spent code finished a second login: {told}"
    );
}

/// An identity no account linked names nobody: brought back, the login asks
/// the wallet again and says so, and no account is made. A wallet declining
/// is brought back too, and asked again, saying it shared nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_wallet_sign_in_names_nobody_for_an_identity_nobody_linked() {
    let (plane, bearer) = plane_that_verifies().await;
    let wallet = realm_signing_in_by_wallet(&plane, &bearer, false).await;
    let cookie = open_login(&plane, &[]).await;
    let asks = ask_wallet_here(&plane, &cookie).await;
    let (_, status, told) = answer_as(&plane, Holder::Pid(&wallet), &asks).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = bring_back(&plane, Some(&cookie), &read_way_back(&told)).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("challenge")),
        "{told}"
    );
    assert_eq!(told["asks"]["unlinked"], json!(true), "{told}");
    assert_ne!(
        told["asks"]["wallet"]["uri"], asks["wallet"]["uri"],
        "{told}"
    );
    assert!(
        read_linked_issuers(&plane).await.is_empty(),
        "an identity was linked"
    );

    let asks = told["asks"].clone();
    let request = read_request(&plane, asks["wallet"]["uri"].as_str().expect("a link")).await;
    let state = request["state"].as_str().expect("a state").to_owned();
    let (status, told) = answered(
        &plane,
        &request,
        &[("error", "access_denied"), ("state", &state)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = bring_back(&plane, Some(&cookie), &read_way_back(&told)).await;
    assert_eq!(
        (status, &told["status"]),
        (StatusCode::OK, &json!("challenge")),
        "{told}"
    );
    assert_eq!(told["asks"]["refused"], json!(true), "{told}");
}
