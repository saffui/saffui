//! What only SQL holds of the clients a session served: a line keeps the
//! expiry of its session, a realm reads its own alone, an answer and an ending that run at once never miss each
//! other, through the store as through the endpoint, and a grant without a
//! person records nothing.

use pgcore::pool::PoolSettings;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::app::App;
use saffui_core::clients::authenticate::PresentedSecret;
use saffui_core::error::ErrorCode;
use saffui_core::ids::mint_id;
use saffui_core::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
use saffui_core::login::store::{ServedClients, ServedRecord};
use saffui_core::oidc::authorize::{
    AuthorizationParameters, AuthorizationRefusal, begin_authorization,
};
use saffui_core::oidc::token::{TokenRequest, grant_token};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{
    Application, CodeFlow, create_person, create_realm, create_service_client,
    register_application, run_code_flow,
};
use time::Duration;
use uuid::Uuid;

use crate::support::locks::{ON_A_ROW, wait_for_waiter};
use crate::support::{self, connect};

const CALLBACK: &str = "https://app.example.org/cb";
const PASSWORD: &str = "correct horse battery";
/// The challenge of RFC 7636, appendix B: never spent here.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The realm `name`, its application `portal`, and a session of `ada`.
async fn open_session(app: &App, name: &str) -> (RealmScope, Session) {
    let scope = create_realm(app, name).await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(app, scope, portal).await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let session = Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![3; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.commit().await.expect("a commit");
    (scope, session)
}

async fn record(app: &App, scope: RealmScope, session: Uuid) -> ServedRecord {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let recorded = work
        .record_served_client(session, "portal", app.now())
        .await
        .expect("a record");
    work.commit().await.expect("a commit");
    recorded
}

async fn list(app: &App, scope: RealmScope, session: Uuid) -> ServedClients {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.list_served_clients(session, 10).await.expect("a read")
}

#[tokio::test]
async fn a_realm_reads_the_clients_its_sessions_served_and_none_of_another() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let (scope, session) = open_session(&app, "acme").await;
    let (other, _) = open_session(&app, "globex").await;
    assert_eq!(record(&app, scope, session.id).await, ServedRecord::Written);

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere
            .record_served_client(session.id, "portal", app.now())
            .await,
        Ok(ServedRecord::SessionEnded),
        "a session of another realm is none of this one"
    );
    assert_eq!(
        elsewhere.list_served_clients(session.id, 10).await,
        Ok(ServedClients::default())
    );
    drop(elsewhere);
    // The rows themselves, read with no filter of their own: row security
    // alone keeps them in their realm.
    let serving = connect(&database, APP_ROLE).await;
    let count_under = async |scope: RealmScope| -> i64 {
        serving
            .batch_execute(&format!(
                "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
                 set_config('saffui.realm', '{}', true)",
                scope.tenant().as_uuid(),
                scope.realm().as_uuid()
            ))
            .await
            .expect("a scope");
        let counted = serving
            .query_one("SELECT count(*) FROM session_clients", &[])
            .await
            .expect("a count")
            .get(0);
        serving.batch_execute("ROLLBACK").await.expect("a rollback");
        counted
    };
    assert_eq!(count_under(scope).await, 1);
    assert_eq!(count_under(other).await, 0);
}

/// A line keeps the expiry of the session it was written for: retention
/// finds it by that expiry.
#[tokio::test]
async fn a_line_keeps_the_expiry_of_its_session() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let (scope, session) = open_session(&app, "acme").await;
    assert_eq!(record(&app, scope, session.id).await, ServedRecord::Written);

    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    let kept: bool = maintenance
        .query_one(
            "SELECT line.expires_at = session.expires_at
             FROM session_clients AS line
             JOIN sessions AS session USING (tenant_id, realm_id, session_id)",
            &[],
        )
        .await
        .expect("the line")
        .get(0);
    assert!(kept, "the line expires when its session does");
}

#[tokio::test]
async fn an_answer_to_a_session_that_ended_meanwhile_records_nothing_and_is_refused() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let (scope, session) = open_session(&app, "acme").await;
    let observer = connect(&database, APP_ROLE).await;

    // The ending, held open.
    let mut ending = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(ending.end_session(session.id).await, Ok(true));
    let answer = {
        let app = app.clone();
        tokio::spawn(async move { record(&app, scope, session.id).await })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &answer).await;
    let read_by_the_ending = ending
        .list_served_clients(session.id, 10)
        .await
        .expect("a read");
    ending.commit().await.expect("a commit");

    assert!(waited, "the answer waits on the row of the session");
    assert_eq!(
        answer.await.expect("the answer"),
        ServedRecord::SessionEnded,
        "then reads it ended, and is refused"
    );
    assert_eq!(read_by_the_ending, ServedClients::default());
    assert_eq!(
        list(&app, scope, session.id).await,
        ServedClients::default()
    );
}

#[tokio::test]
async fn an_ending_after_an_answer_in_flight_reads_the_client_it_served() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let (scope, session) = open_session(&app, "acme").await;
    let observer = connect(&database, APP_ROLE).await;

    // The answer, held open once it wrote its line.
    let mut answer = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        answer
            .record_served_client(session.id, "portal", app.now())
            .await,
        Ok(ServedRecord::Written)
    );
    let ending = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            let ended = work.end_session(session.id).await.expect("an end");
            let served = work
                .list_served_clients(session.id, 10)
                .await
                .expect("a read");
            work.commit().await.expect("a commit");
            (ended, served)
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &ending).await;
    answer.commit().await.expect("a commit");

    assert!(
        waited,
        "the ending waits for the answer that holds the session"
    );
    let (ended, served) = ending.await.expect("the ending");
    assert!(ended);
    assert_eq!(
        served
            .first
            .iter()
            .map(|client| client.client_id.as_str())
            .collect::<Vec<_>>(),
        ["portal"],
        "it reads the client the answer recorded"
    );
}

/// The endpoint itself: an answer of a live session to a client it never
/// served waits for an ending in flight, then is refused, and records nothing.
#[tokio::test]
async fn an_answer_of_the_endpoint_waits_for_an_ending_in_flight_then_is_refused() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    for client_id in ["portal", "other"] {
        let application = Application {
            client_id,
            redirect_uri: CALLBACK,
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: false,
        };
        register_application(&app, scope, application).await;
    }
    create_person(&app, scope, "ada", PASSWORD).await;
    let signed_in = run_code_flow(
        &app,
        CodeFlow {
            realm: "acme",
            client_id: "portal",
            client_secret: None,
            redirect_uri: CALLBACK,
            scope: "openid",
            username: "ada",
            password: PASSWORD,
        },
    )
    .await;
    let session = signed_in.ticket.session;
    let observer = connect(&database, APP_ROLE).await;

    // The ending, held open.
    let mut ending = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(ending.end_session(session).await, Ok(true));
    let answer = {
        let app = app.clone();
        tokio::spawn(async move {
            let parameters = AuthorizationParameters {
                response_type: Some("code"),
                client_id: Some("other"),
                redirect_uri: Some(CALLBACK),
                scope: Some("openid"),
                nonce: Some("a-nonce"),
                code_challenge: Some(CHALLENGE),
                code_challenge_method: Some("S256"),
                ..AuthorizationParameters::default()
            };
            match begin_authorization(&app, "acme", parameters, Some(&signed_in.ticket)).await {
                Ok(_) => Ok(()),
                Err(AuthorizationRefusal::Shown(failure)) => Err(Some(failure.code)),
                Err(AuthorizationRefusal::Returned { .. }) => Err(None),
            }
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &answer).await;
    ending.commit().await.expect("a commit");

    assert!(waited, "the answer waits on the row of the session");
    assert_eq!(
        answer.await.expect("the answer"),
        Err(Some(ErrorCode::SessionRequired)),
        "then reads it ended, and is refused"
    );
    let served = list(&app, scope, session).await;
    assert_eq!(
        served
            .first
            .iter()
            .map(|client| client.client_id.as_str())
            .collect::<Vec<_>>(),
        ["portal"],
        "the client refused is not recorded"
    );
}

#[tokio::test]
async fn a_grant_to_a_client_as_itself_records_no_session_client() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let secret = create_service_client(&app, scope, "billing", &["invoices:read"]).await;

    let granted = grant_token(
        &app,
        "acme",
        TokenRequest {
            grant_type: Some("client_credentials"),
            client_id: Some("billing"),
            client_secret: Some(PresentedSecret::Basic(secret)),
            ..TokenRequest::default()
        },
    )
    .await;

    assert!(granted.is_ok(), "a token for the service");
    let lines: i64 = connect(&database, MAINTENANCE_ROLE)
        .await
        .query_one("SELECT count(*) FROM session_clients", &[])
        .await
        .expect("a count")
        .get(0);
    assert_eq!(lines, 0);
}
