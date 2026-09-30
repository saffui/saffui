use super::support;
use super::support::Plane;
use super::wallet::{
    Wallet, answered, asked, encrypted, plane_that_verifies, read_request, realm_ready_to_verify,
    served,
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

/// The wallet answering the request a challenge links to, disclosing the
/// claims the realm asks for. Hands back the request's id.
async fn present(plane: &Plane, wallet: &Wallet, asks: &Value) -> String {
    let request = read_request(plane, asks["wallet"]["uri"].as_str().expect("a link")).await;
    let client_id = request["client_id"].as_str().expect("a client_id");
    let nonce = request["nonce"].as_str().expect("a nonce");
    let answer = json!({
        "vp_token": {
            "pid": [wallet.presented_disclosing(client_id, nonce, &["family_name", "given_name"])],
        },
        "state": request["state"],
    });
    let (status, told) = answered(
        plane,
        &request,
        &[("response", &encrypted(&request, &answer))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    request["state"].as_str().expect("a state").to_owned()
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

/// Link the subject's PID to their account through the ceremony an
/// application asks for, the way the page and the wallet play it.
async fn link_by_ceremony(plane: &Plane, wallet: &Wallet) {
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
    assert_eq!(
        read_settled(plane, Some(&cookie)).await,
        (StatusCode::OK, json!({ "settled": false }))
    );

    present(plane, wallet, &told["asks"]).await;
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

    link_by_ceremony(&plane, &wallet).await;
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
    let request_id = present(&plane, &wallet, &told["asks"]).await;
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
    link_by_ceremony(&plane, &wallet).await;
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
    present(&plane, &somebody_else, &again["asks"]).await;
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
