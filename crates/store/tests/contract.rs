//! The contract of the core, played on Postgres: the adapter must answer as
//! the double does.

use pgcore::pool::PoolSettings;
use saffui_core::testkit::contract::{
    check_authenticators_contract, check_clients_contract, check_codes_contract,
    check_ended_sessions_contract, check_grants_contract, check_keys_contract,
    check_known_browsers_contract, check_member_groups_contract, check_persons_contract,
    check_policies_contract, check_refresh_contract, check_relations_contract,
    check_roles_contract, check_security_keys_contract, check_sign_in_contract,
    check_tenancy_contract,
};

mod support;

#[tokio::test]
async fn postgres_passes_the_tenancy_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_tenancy_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_keys_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_keys_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_clients_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_clients_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_persons_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_persons_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_sign_in_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_sign_in_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_codes_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_codes_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_refresh_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_refresh_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_authenticators_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_authenticators_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_ended_sessions_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_ended_sessions_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_security_keys_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_security_keys_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_roles_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_roles_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_grants_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_grants_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_relations_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_relations_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_policies_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_policies_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_member_groups_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_member_groups_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_known_browsers_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_known_browsers_contract(&app).await;
}

/// A rotation still in flight when its family is revoked writes a token the
/// revocation cannot see. The family stands revoked for that token all the
/// same: it is not spent, and reads as revoked.
#[tokio::test]
async fn a_token_written_while_its_family_was_revoked_is_not_spent() {
    use std::time::Duration as Wait;

    use saffui_core::ids::mint_id;
    use saffui_core::login::session::{AuthenticationMethod, Session, SessionState};
    use saffui_core::testkit::fixtures::{create_person, create_realm};
    use saffui_core::tokens::store::RefreshToken;
    use time::Duration;

    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "race").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let session = Session {
        id: mint_id(&app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let family = mint_id(&app).expect("an identifier");
    let mint = |digest: u8| RefreshToken {
        token_digest: vec![digest; 32],
        family,
        client_id: "webapp".to_owned(),
        person: ada.id,
        session: session.id,
        scopes: vec!["openid".to_owned()],
        issued_at: now,
        expires_at: now + Duration::minutes(30),
    };
    let (first, next) = (mint(1), mint(2));
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.insert_refresh_token(&first).await.expect("a token");
    work.commit().await.expect("a commit");

    // The rotation spends the first token and writes the next, uncommitted.
    let mut rotation = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        rotation
            .spend_refresh_token(&first.token_digest, "webapp", now)
            .await,
        Ok(Some(first.clone()))
    );
    rotation.insert_refresh_token(&next).await.expect("a token");
    // The revocation waits on the row the rotation holds.
    let storage = app.storage.clone();
    let revocation = tokio::spawn(async move {
        let mut work = storage.begin(scope).await.expect("a unit of work");
        let revoked = work.revoke_refresh_family(family, now).await;
        work.commit().await.expect("a commit");
        revoked
    });
    tokio::time::sleep(Wait::from_millis(300)).await;
    assert!(
        !revocation.is_finished(),
        "the revocation waits for the rotation"
    );
    rotation.commit().await.expect("a commit");
    assert_eq!(
        revocation
            .await
            .expect("the revocation")
            .map(|ended| ended.map(|ended| ended.tokens)),
        Ok(Some(1)),
        "the revocation sees only the token it waited on"
    );

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.spend_refresh_token(&next.token_digest, "webapp", now)
            .await,
        Ok(None),
        "the token the rotation wrote is not spent"
    );
    let stored = work
        .read_refresh_token(&next.token_digest)
        .await
        .expect("a read")
        .expect("the token");
    assert!(stored.revoked_at.is_some(), "it reads as revoked");
    assert!(!stored.is_live(now));
}

/// Two sign-outs of one session at once: the second waits for the first,
/// then finds nothing left to end, so that the session is said ended once.
#[tokio::test]
async fn of_two_endings_of_one_session_at_once_one_ends_it() {
    use std::time::Duration as Wait;

    use saffui_core::ids::mint_id;
    use saffui_core::login::session::{AuthenticationMethod, Session, SessionState};
    use saffui_core::testkit::fixtures::{create_person, create_realm};
    use time::Duration;

    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "endings").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let session = Session {
        id: mint_id(&app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.commit().await.expect("a commit");

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(first.end_session(session.id).await, Ok(true));
    let storage = app.storage.clone();
    let second = tokio::spawn(async move {
        let mut work = storage.begin(scope).await.expect("a unit of work");
        let ended = work.end_session(session.id).await;
        work.commit().await.expect("a commit");
        ended
    });
    tokio::time::sleep(Wait::from_millis(300)).await;
    assert!(!second.is_finished(), "the second waits for the first");
    first.commit().await.expect("a commit");

    assert_eq!(second.await.expect("the second ending"), Ok(false));
}

/// The schema keeps the methods this binary names, and no other: a session
/// proven by nothing, or by a name nobody gave, is not written.
#[tokio::test]
async fn a_session_is_written_with_the_methods_this_binary_names_and_no_other() {
    use saffui_core::login::session::AuthenticationMethod;
    use saffui_core::testkit::fixtures::{create_person, create_realm};
    use tokio_postgres::error::SqlState;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "methods").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let (tenant, realm) = (scope.tenant().as_uuid(), scope.realm().as_uuid());
    let named: Vec<&str> = AuthenticationMethod::ALL
        .iter()
        .map(|method| method.name())
        .collect();
    let every_one = format!("{{{}}}", named.join(","));

    for (methods, refused) in [
        (every_one.as_str(), None),
        ("{pwd,hwk}", Some(SqlState::CHECK_VIOLATION)),
        ("{}", Some(SqlState::CHECK_VIOLATION)),
    ] {
        let writing = owner.transaction().await.expect("a transaction");
        writing
            .execute(
                "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
                &[&tenant.to_string(), &realm.to_string()],
            )
            .await
            .expect("the scope");
        let written = writing
            .execute(
                "INSERT INTO sessions (tenant_id, realm_id, session_id, person_id, secret_digest,
                     state, methods, authenticated_at, expires_at)
                 VALUES ($1, $2, gen_random_uuid(), $3, '\\x00', 'active', $4::text::text[],
                     now(), now() + interval '1 hour')",
                &[&tenant, &realm, &ada.id, &methods],
            )
            .await;
        assert_eq!(
            written.err().and_then(|error| error.code().cloned()),
            refused,
            "{methods}"
        );
    }
}

const CALLBACK: &str = "https://app.example.org/callback";

async fn refresh_as_webapp(
    app: &saffui_core::app::App,
    token: &str,
) -> Result<(), saffui_core::oidc::errors::OAuthError> {
    use saffui_core::oidc::token::{TokenRequest, grant_token};

    let request = TokenRequest {
        grant_type: Some("refresh_token"),
        client_id: Some("webapp"),
        refresh_token: Some(token),
        ..TokenRequest::default()
    };
    grant_token(app, "acme", request)
        .await
        .map(|_| ())
        .map_err(|failure| failure.error)
}

async fn exchange_as_webapp(
    app: &saffui_core::app::App,
    code: &str,
) -> Result<(), saffui_core::oidc::errors::OAuthError> {
    use saffui_core::oidc::token::{TokenRequest, grant_token};

    let request = TokenRequest {
        grant_type: Some("authorization_code"),
        client_id: Some("webapp"),
        code: Some(code),
        redirect_uri: Some(CALLBACK),
        code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        ..TokenRequest::default()
    };
    grant_token(app, "acme", request)
        .await
        .map(|_| ())
        .map_err(|failure| failure.error)
}

/// A family taken back is written no more. Its code or a used token that
/// comes back, or a revocation asked again, reads it revoked and stops: a
/// client that sends them in a loop holds no row and no connection for long.
#[tokio::test]
async fn a_family_taken_back_is_not_written_again_however_often_it_comes_back() {
    use saffui_core::oidc::errors::OAuthError;
    use saffui_core::oidc::revoke::revoke_token;
    use saffui_core::testkit::fixtures::{
        Application, CodeFlow, create_person, create_realm, register_application, run_code_flow,
    };

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    create_person(&app, scope, "ada", "correct horse battery").await;
    let webapp = Application {
        client_id: "webapp",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
    };
    register_application(&app, scope, webapp).await;
    let flow = CodeFlow {
        realm: "acme",
        client_id: "webapp",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid",
        username: "ada",
        password: "correct horse battery",
    };
    let signed_in = run_code_flow(&app, flow).await;
    let first = signed_in.tokens.refresh_token.expect("a refresh token");
    assert_eq!(refresh_as_webapp(&app, &first).await, Ok(()), "a rotation");
    assert_eq!(
        exchange_as_webapp(&app, &signed_in.code).await,
        Err(OAuthError::InvalidGrant),
        "the code presented again takes its family back"
    );

    // From now on, a statement that revokes a refresh token fails.
    database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection")
        .batch_execute(
            "CREATE FUNCTION saffui_test_refuse() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$;
             CREATE TRIGGER saffui_test_refuse BEFORE UPDATE OF revoked_at ON refresh_tokens
                 FOR EACH STATEMENT EXECUTE FUNCTION saffui_test_refuse();",
        )
        .await
        .expect("a trigger that refuses every revocation");

    assert_eq!(
        exchange_as_webapp(&app, &signed_in.code).await,
        Err(OAuthError::InvalidGrant),
        "the code presented once more"
    );
    assert_eq!(
        refresh_as_webapp(&app, &first).await,
        Err(OAuthError::InvalidGrant),
        "the used token presented again"
    );
    assert_eq!(
        revoke_token(&app, "acme", Some("webapp"), None, Some(&first))
            .await
            .map_err(|failure| failure.error),
        Ok(()),
        "a revocation asked again"
    );
}
