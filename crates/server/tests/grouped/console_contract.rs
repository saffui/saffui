use super::support::{self, Plane};
use actix_web::App;
use models::entities::authz::AdminAction;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use server::api::config::{Plane as Mounted, register};
use std::path::Path;
use std::process::Command;
use store::tenancy::TenantContext;

/// A login of ada's the console may end: ending the one the token names would
/// sign the rest of the run out. The contract suite names it too.
const SPARE_SESSION: &str = "session-contract";
/// An app of ada's the console may take away, for the same reason.
const SPARE_APP: &str = "cred-contract";

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

/// What the console lists and the planted world lacks, so a list it reads
/// carries a row to judge: two passkeys beside ada's app, one of them spare,
/// her spare app, a consent she gave, and her spare login with what the app
/// got out of it.
async fn plant_what_the_console_lists(plane: &Plane) {
    plane.enrol_soft_passkey().await;
    plane.enrol_soft_passkey().await;
    plane.enrol_totp(SPARE_APP, support::TOTP_SECRET).await;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    store::providers::consents::keep(
        &transaction,
        support::SUBJECT,
        support::CONFIDENTIAL,
        &["openid".to_owned()],
        chrono::Utc::now(),
    )
    .await
    .expect("a consent");
    store::providers::sessions::open(
        &transaction,
        &UserSessionModel {
            browser_state: None,
            tenant: support::TENANT.into(),
            session_id: SPARE_SESSION.into(),
            realm_id: support::REALM.into(),
            user_id: support::SUBJECT.into(),
            login_username: support::SUBJECT.into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            ip_address: None,
            user_agent: None,
            started_at: chrono::Utc::now().timestamp(),
            auth_time: None,
            loa: None,
            expiration: None,
            state: UserSessionState::LoggedIn,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        },
    )
    .await
    .expect("a spare login");
    store::providers::sessions::open_client_session(
        &transaction,
        &ClientSessionModel {
            tenant: support::TENANT.into(),
            session_id: format!("{SPARE_SESSION}-{}", support::CONFIDENTIAL),
            realm_id: support::REALM.into(),
            user_id: support::SUBJECT.into(),
            user_session_id: SPARE_SESSION.into(),
            client_id: support::CONFIDENTIAL.into(),
            auth_method: None,
            redirect_uri: Some(support::REDIRECT.into()),
            started_at: chrono::Utc::now().timestamp(),
            expiration: None,
            notes: None,
            current_refresh_token: None,
            current_refresh_token_use_count: None,
            offline: None,
            requested_claims: None,
        },
    )
    .await
    .expect("what the app got out of the spare login");
    transaction.commit().await.expect("the world kept");
}

/// A certificate the crypto crate issues for a key it draws, in base64, for the
/// contract's SAML provider to carry in its metadata.
fn issue_contract_certificate() -> String {
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Issuance, issue_certificate};

    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    let certificate = issue_certificate(&Issuance {
        subject_key: &PublicKey::from_der(key.to_der_public_key()),
        subject_name: "saml.example.test",
        issuer_key: &PrivateKey::from_der(key.to_der_private_key()),
        issuer_name: "saml.example.test",
        serial: &[1],
        not_before: 1_789_372_800,
        not_after: 2_104_992_000,
    })
    .expect("a certificate issued by the crypto crate");
    data_encoding::BASE64.encode(&certificate)
}

/// The console's own service calls, run by its contract suite against this
/// server on a real socket. Its mocked transport tests prove what the console
/// does with an answer; this proves the server still gives that answer: every
/// path and body the console sends is taken, and every answer it keeps fits
/// the type the console reads it as.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG) and the console's packages (pnpm install)"]
async fn the_console_contract_holds_against_a_live_server() {
    let plane = Plane::with_actions(AdminAction::ALL).await;
    let bearer = plane.token(&support::claims());
    plant_what_the_console_lists(&plane).await;

    let served = mounted(&plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let server = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(server);

    let saml_certificate = issue_contract_certificate();
    let console = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../admin");
    assert!(
        console.join("node_modules").is_dir(),
        "the console's packages are not installed: run pnpm install"
    );
    let run = tokio::task::spawn_blocking(move || {
        Command::new("pnpm")
            .args(["run", "contract"])
            .current_dir(console)
            .env("SAFFUI_CONTRACT_ORIGIN", format!("http://127.0.0.1:{port}"))
            .env("SAFFUI_CONTRACT_TOKEN", bearer)
            .env("SAFFUI_CONTRACT_REALM", support::REALM)
            .env("SAFFUI_CONTRACT_SAML_CERTIFICATE", saml_certificate)
            .output()
    })
    .await
    .expect("the run comes back")
    .expect("pnpm starts");
    assert!(
        run.status.success(),
        "the console contract broke:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}
