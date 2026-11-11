//! The contract of the core, played on Postgres: the adapter must answer as
//! the double does.

use pgcore::pool::PoolSettings;
use saffui_core::consent::ConsentHold;
use saffui_core::testkit::contract::{
    check_authenticators_contract, check_clients_contract, check_codes_contract,
    check_consents_contract, check_ended_sessions_contract, check_grants_contract,
    check_keys_contract, check_known_browsers_contract, check_member_groups_contract,
    check_persons_contract, check_policies_contract, check_refresh_contract,
    check_relations_contract, check_roles_contract, check_security_keys_contract,
    check_sign_in_contract, check_tenancy_contract,
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
async fn postgres_passes_the_consents_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_consents_contract(&app).await;
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

/// Writes into `family`, under the owner, `count` tokens used before `now`,
/// a second apart, older than any other of the family.
async fn plant_used_tokens(
    database: &pgcore::testkit::TestDatabase,
    scope: saffui_core::tenancy::RealmScope,
    planted: &saffui_core::tokens::store::RefreshToken,
    count: i32,
    now: time::OffsetDateTime,
) {
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let (tenant, realm) = (scope.tenant().as_uuid(), scope.realm().as_uuid());
    let writing = owner.transaction().await.expect("a transaction");
    writing
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[&tenant.to_string(), &realm.to_string()],
        )
        .await
        .expect("the scope");
    writing
        .execute(
            "INSERT INTO refresh_tokens (tenant_id, realm_id, token_digest, family_id, client_id,
                 person_id, session_id, scopes, issued_at, expires_at, used_at)
             SELECT $1, $2, sha256(convert_to($3::uuid::text || ':' || n, 'UTF8')), $3, $4, $5, $6,
                    '{openid}',
                    $7::timestamptz - n * interval '1 second', $7 + interval '30 minutes',
                    $7 - n * interval '1 second'
             FROM generate_series(1, $8) AS n",
            &[
                &tenant,
                &realm,
                &planted.family,
                &planted.client_id,
                &planted.person,
                &planted.session,
                &now,
                &count,
            ],
        )
        .await
        .expect("the used tokens of a family");
    writing.commit().await.expect("a commit");
}

/// What takes a family back while a rotation of it is in flight.
#[derive(Clone, Copy)]
enum Revocation {
    /// The family alone, as a revocation or a replay does.
    Family,
    /// The families of its session, as the setting up of a factor does.
    Session,
    /// The families of its client for the person, as a withdrawal does.
    Client,
}

/// A rotation still in flight when its family is revoked writes a token the
/// revocation cannot see, and spends the latest one it waits on. The family
/// stands revoked for that token all the same: it is not spent, and reads as
/// revoked, whatever the length of the family before and whatever took it
/// back.
async fn race_a_rotation_against_a_revocation(revocation: Revocation, used_before: i32) {
    use std::time::Duration as Wait;

    use saffui_core::ids::mint_id;
    use saffui_core::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use saffui_core::testkit::fixtures::{create_person, create_realm};
    use saffui_core::tokens::store::RefreshToken;
    use time::Duration;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "race").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let session = Session {
        id: mint_id(&app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
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
    plant_used_tokens(&database, scope, &first, used_before, now).await;

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
    let (person, held_in) = (ada.id, session.id);
    let revoking = tokio::spawn(async move {
        let mut work = storage.begin(scope).await.expect("a unit of work");
        let counted = match revocation {
            Revocation::Family => work
                .revoke_refresh_family(family, now)
                .await
                .map(|ended| ended.map_or(0, |ended| ended.tokens)),
            Revocation::Session => {
                work.revoke_refresh_tokens_of_sessions(&[held_in], now)
                    .await
            }
            Revocation::Client => work
                .revoke_refresh_families_of_client(person, "webapp", now, 10)
                .await
                .map(|revoked| revoked.tokens),
        };
        work.commit().await.expect("a commit");
        counted
    });
    tokio::time::sleep(Wait::from_millis(300)).await;
    assert!(
        !revoking.is_finished(),
        "the revocation waits for the rotation"
    );
    rotation.commit().await.expect("a commit");
    assert_eq!(
        revoking.await.expect("the revocation"),
        Ok(u64::try_from(used_before).expect("a count") + 1),
        "the revocation counts what it saw, the token it waited on included"
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

#[tokio::test]
async fn a_token_written_while_its_family_was_revoked_is_not_spent() {
    race_a_rotation_against_a_revocation(Revocation::Family, 0).await;
}

#[tokio::test]
async fn a_token_written_while_a_family_of_thousands_was_revoked_is_not_spent() {
    race_a_rotation_against_a_revocation(Revocation::Family, 3_000).await;
}

#[tokio::test]
async fn a_token_written_while_its_session_was_closed_is_not_spent() {
    race_a_rotation_against_a_revocation(Revocation::Session, 3_000).await;
}

#[tokio::test]
async fn a_token_written_while_its_client_was_withdrawn_is_not_spent() {
    race_a_rotation_against_a_revocation(Revocation::Client, 3_000).await;
}

/// How many tokens of a family are written revoked, and one used token of it
/// that is not, read under the owner.
async fn read_written_tokens(
    database: &pgcore::testkit::TestDatabase,
    scope: saffui_core::tenancy::RealmScope,
    family: uuid::Uuid,
) -> (i64, Option<Vec<u8>>) {
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let reading = owner.transaction().await.expect("a transaction");
    reading
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    let row = reading
        .query_one(
            "SELECT (SELECT count(*) FROM refresh_tokens
                     WHERE family_id = $1 AND revoked_at IS NOT NULL),
                    (SELECT token_digest FROM refresh_tokens
                     WHERE family_id = $1 AND used_at IS NOT NULL AND revoked_at IS NULL
                     LIMIT 1)",
            &[&family],
        )
        .await
        .expect("a count");
    (row.get(0), row.get(1))
}

/// A revocation writes the tokens that could still be spent and the latest
/// of a family, never one row for each rotation it went through: a family of
/// thousands of tokens costs two rows, whether one family or all those of a
/// client are taken back.
#[tokio::test]
async fn revoking_a_family_writes_a_row_or_two_however_many_rotations_it_had() {
    use saffui_core::ids::mint_id;
    use saffui_core::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use saffui_core::testkit::fixtures::{create_person, create_realm};
    use saffui_core::tokens::store::{EndedFamily, RefreshToken};
    use time::Duration;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "long-families").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let session = Session {
        id: mint_id(&app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let current = |digest: u8| RefreshToken {
        token_digest: vec![digest; 32],
        family: mint_id(&app).expect("an identifier"),
        client_id: "webapp".to_owned(),
        person: ada.id,
        session: session.id,
        scopes: vec!["openid".to_owned()],
        issued_at: now,
        expires_at: now + Duration::minutes(30),
    };
    let (one, another) = (current(1), current(2));
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.insert_refresh_token(&one).await.expect("a token");
    work.insert_refresh_token(&another).await.expect("a token");
    work.commit().await.expect("a commit");
    plant_used_tokens(&database, scope, &one, 4_000, now).await;
    plant_used_tokens(&database, scope, &another, 4_000, now).await;

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.revoke_refresh_family(one.family, now).await,
        Ok(Some(EndedFamily {
            tokens: 4_001,
            last_issued_at: now,
            last_used_at: Some(now - Duration::seconds(1)),
        })),
        "everything the family told is counted"
    );
    let withdrawn = work
        .revoke_refresh_families_of_client(ada.id, "webapp", now, 10)
        .await
        .expect("a withdrawal");
    work.commit().await.expect("a commit");

    assert_eq!(
        (withdrawn.families, withdrawn.tokens),
        (1, 4_001),
        "the other family, everything it told counted"
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for family in [one.family, another.family] {
        let (written, used) = read_written_tokens(&database, scope, family).await;
        assert_eq!(written, 1, "the latest alone is written");
        let stored = work
            .read_refresh_token(&used.expect("a used token not written"))
            .await
            .expect("a read")
            .expect("a used token");
        assert!(
            stored.revoked_at.is_some(),
            "a used token not written reads revoked with its family"
        );
    }
}

/// Two sign-outs of one session at once: the second waits for the first,
/// then finds nothing left to end, so that the session is said ended once.
#[tokio::test]
async fn of_two_endings_of_one_session_at_once_one_ends_it() {
    use std::time::Duration as Wait;

    use saffui_core::ids::mint_id;
    use saffui_core::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
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
        kind: SessionKind::Browser,
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

/// The schema keeps the methods and the kinds this binary names, and no
/// other: a session proven by nothing, by a name nobody gave, or living
/// nowhere this binary knows, is not written. A session of a browser holds
/// a secret, and an offline one none.
#[tokio::test]
async fn a_session_is_written_with_the_methods_and_the_kind_this_binary_names_and_no_other() {
    use saffui_core::login::session::{AuthenticationMethod, SessionKind};
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

    let (browser, offline) = (SessionKind::Browser.name(), SessionKind::Offline.name());
    let (secret, none) = (vec![7_u8; 32], Vec::new());

    for (methods, kind, digest, refused) in [
        (every_one.as_str(), browser, &secret, None),
        ("{pwd}", offline, &none, None),
        (
            "{pwd,hwk}",
            browser,
            &secret,
            Some(SqlState::CHECK_VIOLATION),
        ),
        ("{}", browser, &secret, Some(SqlState::CHECK_VIOLATION)),
        ("{pwd}", "paper", &secret, Some(SqlState::CHECK_VIOLATION)),
        ("{pwd}", browser, &none, Some(SqlState::CHECK_VIOLATION)),
        ("{pwd}", offline, &secret, Some(SqlState::CHECK_VIOLATION)),
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
                     state, kind, methods, authenticated_at, expires_at)
                 VALUES ($1, $2, gen_random_uuid(), $3, $4, 'active', $5, $6::text::text[],
                     now(), now() + interval '1 hour')",
                &[&tenant, &realm, &ada.id, digest, &kind, &methods],
            )
            .await;
        assert_eq!(
            written.err().and_then(|error| error.code().cloned()),
            refused,
            "{methods} {kind} {} bytes of secret",
            digest.len()
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
        requires_consent: false,
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

/// Two answers of one person to one client at once: the second waits for
/// the first, then adds to what it allowed, so that neither is lost.
#[tokio::test]
async fn of_two_consents_given_at_once_each_keeps_what_it_allowed() {
    use std::time::Duration as Wait;

    use saffui_core::consent::Consent;
    use saffui_core::testkit::fixtures::{
        Application, create_person, create_realm, register_application,
    };

    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "consents").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let partner = Application {
        client_id: "partner",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(&app, scope, partner).await;
    let now = app.now();
    let allow = move |scopes: [&str; 2]| Consent {
        person: ada.id,
        client_id: "partner".to_owned(),
        scopes: scopes.map(str::to_owned).to_vec(),
        granted_at: now,
    };

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    first
        .add_consent(&allow(["openid", "email"]))
        .await
        .expect("a consent");
    let storage = app.storage.clone();
    let second = tokio::spawn(async move {
        let mut work = storage.begin(scope).await.expect("a unit of work");
        work.add_consent(&allow(["openid", "profile"]))
            .await
            .expect("a consent");
        work.commit().await
    });
    tokio::time::sleep(Wait::from_millis(300)).await;
    assert!(!second.is_finished(), "the second waits for the first");
    first.commit().await.expect("a commit");
    assert_eq!(second.await.expect("the second answer"), Ok(()));

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let kept = work
        .read_consent(ada.id, "partner")
        .await
        .expect("a read")
        .expect("the consent");
    assert_eq!(kept.scopes, ["openid", "email", "profile"]);
}

/// The realm `consents-held`, `ada` with a session, and `partner`, which
/// requires consent and was allowed `openid`; an administrator who withdraws.
async fn allow_partner_once(
    app: &saffui_core::app::App,
) -> (
    saffui_core::tenancy::RealmScope,
    saffui_core::directory::Person,
    saffui_core::login::session::Session,
    saffui_core::authz::admin::AdminCaller,
) {
    use saffui_core::authz::admin::authorize_admin_call;
    use saffui_core::authz::capability::Capability;
    use saffui_core::consent::Consent;
    use saffui_core::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use saffui_core::testkit::fixtures::{
        Application, create_administrator, create_person, create_realm, register_application,
    };

    let scope = create_realm(app, "consents-held").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let partner = Application {
        client_id: "partner",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(app, scope, partner).await;
    let token = create_administrator(
        app,
        "consents-held",
        scope,
        "operator",
        &[Capability::UserWrite],
    )
    .await;
    let caller = authorize_admin_call(app, "consents-held", Some(&token), Capability::UserWrite)
        .await
        .expect("an administrator");
    let now = app.now();
    let session = Session {
        id: uuid::Uuid::from_u128(7),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + time::Duration::hours(1),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.add_consent(&Consent {
        person: ada.id,
        client_id: "partner".to_owned(),
        scopes: vec!["openid".to_owned()],
        granted_at: now,
    })
    .await
    .expect("a consent");
    work.commit().await.expect("a commit");
    (scope, ada, session, caller)
}

/// Whether a session of the database comes to wait on a lock before `task`
/// ends, within three seconds: short of what a unit of work waits for one.
async fn wait_for_a_waiter<T>(
    observer: &tokio_postgres::Client,
    task: &tokio::task::JoinHandle<T>,
) -> bool {
    wait_for_waiters(observer, task, 1).await
}

/// As [`wait_for_a_waiter`], until `waiters` sessions wait on locks at once.
async fn wait_for_waiters<T>(
    observer: &tokio_postgres::Client,
    task: &tokio::task::JoinHandle<T>,
    waiters: i64,
) -> bool {
    use std::time::{Duration as Wait, Instant};

    let deadline = Instant::now() + Wait::from_secs(3);
    while !task.is_finished() && Instant::now() < deadline {
        let waiting: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
                &[],
            )
            .await
            .expect("a count")
            .get(0);
        if waiting >= waiters {
            return true;
        }
        tokio::time::sleep(Wait::from_millis(10)).await;
    }
    false
}

/// An exchange holds the consent it relies on until it commits: a withdrawal
/// that comes meanwhile waits for it, then revokes the family it opened.
#[tokio::test]
async fn a_withdrawal_waits_for_an_exchange_that_holds_the_consent_then_ends_its_family() {
    use saffui_core::consent::manage::withdraw_person_consent;
    use saffui_core::tokens::store::RefreshToken;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = database
        .plan(pgcore::APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let (scope, ada, session, caller) = allow_partner_once(&app).await;
    let now = app.now();
    let opened = RefreshToken {
        token_digest: vec![9; 32],
        family: uuid::Uuid::from_u128(8),
        client_id: "partner".to_owned(),
        person: ada.id,
        session: session.id,
        scopes: vec!["openid".to_owned()],
        issued_at: now,
        expires_at: now + time::Duration::hours(1),
    };

    // The second unit of work of an exchange, up to its commit.
    let mut exchange = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        exchange
            .hold_consent(ada.id, "partner", ConsentHold::Shared)
            .await,
        Ok(Some(vec!["openid".to_owned()]))
    );
    exchange
        .insert_refresh_token(&opened)
        .await
        .expect("the first token of a family");
    let withdrawal = {
        let app = app.clone();
        tokio::spawn(async move { withdraw_person_consent(&app, &caller, ada.id, "partner").await })
    };
    assert!(
        wait_for_a_waiter(&observer, &withdrawal).await,
        "the withdrawal waits for the exchange"
    );
    exchange.commit().await.expect("a commit");
    withdrawal
        .await
        .expect("the withdrawal")
        .expect("a withdrawal");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let stored = work
        .read_refresh_token(&opened.token_digest)
        .await
        .expect("a read")
        .expect("the token");
    assert!(
        stored.revoked_at.is_some(),
        "the family the exchange opened is revoked with the rest"
    );
}

/// A withdrawal that came first leaves an exchange nothing to hold: it
/// waits for the withdrawal, then finds no consent.
#[tokio::test]
async fn an_exchange_that_comes_during_a_withdrawal_finds_no_consent_to_hold() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = database
        .plan(pgcore::APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let (scope, ada, _, _) = allow_partner_once(&app).await;

    let mut withdrawal = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(withdrawal.delete_consent(ada.id, "partner").await, Ok(true));
    let exchange = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.hold_consent(ada.id, "partner", ConsentHold::Shared)
                .await
        })
    };
    assert!(
        wait_for_a_waiter(&observer, &exchange).await,
        "the exchange waits for the withdrawal"
    );
    withdrawal.commit().await.expect("a commit");

    assert_eq!(exchange.await.expect("the exchange"), Ok(None));
}

/// A factor set up and an offline token replayed at once. The first ends the
/// sessions the password alone opened, then their tokens; the second ends the
/// offline session of its family, then its tokens. Both lock the session
/// first: neither waits on the other in a circle, and both finish.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one race, read from top to bottom")]
async fn a_factor_set_up_and_an_offline_replay_at_once_both_finish() {
    use saffui_core::login::enroll::{begin_totp_enrollment, confirm_totp_enrollment};
    use saffui_core::oidc::errors::OAuthError;
    use saffui_core::oidc::token::{TokenRequest, grant_token};
    use saffui_core::secret::Secret;
    use saffui_core::testkit::crypto::PredictableCodes;
    use saffui_core::testkit::fixtures::{
        Application, CodeFlow, create_person, create_realm, register_application,
        run_consented_code_flow,
    };

    const PASSWORD: &str = "correct horse battery";

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = database
        .plan(pgcore::APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let scope = create_realm(&app, "acme").await;
    create_person(&app, scope, "ada", PASSWORD).await;
    let partner = Application {
        client_id: "partner",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(&app, scope, partner).await;
    let flow = CodeFlow {
        realm: "acme",
        client_id: "partner",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid offline_access",
        username: "ada",
        password: PASSWORD,
    };
    let granted = run_consented_code_flow(&app, flow).await;
    let first = granted.tokens.refresh_token.expect("a refresh token");
    let refresh = |token: String| {
        let app = app.clone();
        async move {
            let request = TokenRequest {
                grant_type: Some("refresh_token"),
                client_id: Some("partner"),
                refresh_token: Some(&token),
                ..TokenRequest::default()
            };
            grant_token(&app, "acme", request)
                .await
                .map(|_| ())
                .map_err(|failure| failure.error)
        }
    };
    assert_eq!(refresh(first.clone()).await, Ok(()), "a rotation");
    let offered = begin_totp_enrollment(&app, "acme", Some(&granted.ticket))
        .await
        .expect("a secret to enroll");
    let seconds = u64::try_from(app.now().unix_timestamp()).expect("after 1970");
    let code = PredictableCodes::compute_from_text(&offered.typed_secret, seconds);

    // The offline session is held, so that both come to wait on it in turn.
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let holder = owner.transaction().await.expect("a transaction");
    holder
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    let held = holder
        .query(
            "SELECT session_id FROM sessions WHERE kind = 'offline' FOR UPDATE",
            &[],
        )
        .await
        .expect("the offline session");
    assert_eq!(held.len(), 1, "one offline session");
    let enrollment = {
        let app = app.clone();
        let ticket = saffui_core::login::session::SessionTicket {
            session: granted.ticket.session,
            secret: Secret::new(granted.ticket.secret.expose().to_vec()),
        };
        tokio::spawn(async move {
            confirm_totp_enrollment(
                &app,
                "acme",
                Some(&ticket),
                Secret::new(PASSWORD.as_bytes().to_vec()),
                &code,
                None,
                &[],
            )
            .await
            .map_err(|failure| failure.code)
        })
    };
    assert!(
        wait_for_waiters(&observer, &enrollment, 1).await,
        "the setting up of the factor waits on the session"
    );
    let replay = tokio::spawn(refresh(first));
    assert!(
        wait_for_waiters(&observer, &replay, 2).await,
        "the replay waits on the session too, holding no token"
    );
    holder.rollback().await.expect("the session let go");

    assert_eq!(enrollment.await.expect("the enrollment"), Ok(()));
    assert_eq!(
        replay.await.expect("the replay"),
        Err(OAuthError::InvalidGrant),
        "refused for what it is, not for a lock"
    );
}

/// Setting up a factor ends the offline session the password alone opened,
/// and its family as a revocation does: a row or two written, whatever its
/// length, and the chain counts the tokens the family still held.
#[tokio::test]
async fn setting_up_a_factor_writes_a_row_or_two_for_an_offline_family_of_thousands() {
    use saffui_core::login::enroll::{begin_totp_enrollment, confirm_totp_enrollment};
    use saffui_core::secret::Secret;
    use saffui_core::testkit::crypto::PredictableCodes;
    use saffui_core::testkit::fixtures::{
        Application, CodeFlow, create_person, create_realm, register_application,
        run_consented_code_flow,
    };

    const PASSWORD: &str = "correct horse battery";

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    create_person(&app, scope, "ada", PASSWORD).await;
    let partner = Application {
        client_id: "partner",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(&app, scope, partner).await;
    let flow = CodeFlow {
        realm: "acme",
        client_id: "partner",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid offline_access",
        username: "ada",
        password: PASSWORD,
    };
    let granted = run_consented_code_flow(&app, flow).await;
    let latest = app.digester.sha256(
        granted
            .tokens
            .refresh_token
            .expect("a refresh token")
            .as_bytes(),
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let held = work
        .read_refresh_token(&latest)
        .await
        .expect("a read")
        .expect("the token")
        .token;
    drop(work);
    plant_used_tokens(&database, scope, &held, 3_000, app.now()).await;
    let offered = begin_totp_enrollment(&app, "acme", Some(&granted.ticket))
        .await
        .expect("a secret to enroll");
    let seconds = u64::try_from(app.now().unix_timestamp()).expect("after 1970");
    let code = PredictableCodes::compute_from_text(&offered.typed_secret, seconds);

    confirm_totp_enrollment(
        &app,
        "acme",
        Some(&granted.ticket),
        Secret::new(PASSWORD.as_bytes().to_vec()),
        &code,
        None,
        &[],
    )
    .await
    .expect("an authenticator");

    let (written, _) = read_written_tokens(&database, scope, held.family).await;
    assert_eq!(written, 1, "the latest alone is written");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.spend_refresh_token(&latest, "partner", app.now())
            .await,
        Ok(None),
        "the latest is not spent"
    );
    let stored = work
        .read_refresh_token(&latest)
        .await
        .expect("a read")
        .expect("the token");
    assert!(stored.revoked_at.is_some(), "it reads as revoked");
    drop(work);
    let maintenance = database
        .plan(pgcore::MAINTENANCE_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let envelope: String = maintenance
        .query_one(
            "SELECT convert_from(envelope, 'UTF8') FROM audit_events
             WHERE kind = 'authenticator.enrolled'",
            &[],
        )
        .await
        .expect("the enrollment in the chain")
        .get(0);
    let told: serde_json::Value = serde_json::from_str(&envelope).expect("an envelope of JSON");
    assert_eq!(
        told["payload"]["refresh_tokens_revoked"], 3_001,
        "the tokens the family still held: {told}"
    );
}

/// Two exchanges that open an offline grant for one person and one client at
/// once take turns on what the person allowed: the second counts the grant
/// of the first, and the bound holds.
#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one race, read from top to bottom")]
async fn two_offline_exchanges_at_once_leave_no_more_grants_than_the_bound() {
    use saffui_core::oidc::token::{MOST_OFFLINE_GRANTS_PER_CLIENT, TokenRequest, grant_token};
    use saffui_core::testkit::fixtures::{
        Application, CodeFlow, allow_consented_code, create_person, create_realm,
        register_application, run_consented_code_flow,
    };

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = database
        .plan(pgcore::APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
    let scope = create_realm(&app, "acme").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let partner = Application {
        client_id: "partner",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(&app, scope, partner).await;
    let flow = || CodeFlow {
        realm: "acme",
        client_id: "partner",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid offline_access",
        username: "ada",
        password: "correct horse battery",
    };
    for _ in 1..MOST_OFFLINE_GRANTS_PER_CLIENT {
        run_consented_code_flow(&app, flow()).await;
    }
    let (first, _) = allow_consented_code(&app, &flow()).await;
    let (second, _) = allow_consented_code(&app, &flow()).await;
    let exchange = |code: String| {
        let app = app.clone();
        tokio::spawn(async move {
            let request = TokenRequest {
                grant_type: Some("authorization_code"),
                client_id: Some("partner"),
                code: Some(&code),
                redirect_uri: Some(CALLBACK),
                code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                ..TokenRequest::default()
            };
            grant_token(&app, "acme", request)
                .await
                .map(|_| ())
                .map_err(|failure| failure.error)
        })
    };

    // What ada allowed is held, so that both exchanges come to wait on it.
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let holder = owner.transaction().await.expect("a transaction");
    holder
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    holder
        .execute(
            "SELECT 1 FROM consents WHERE person_id = $1 AND client_id = 'partner' FOR UPDATE",
            &[&ada.id],
        )
        .await
        .expect("the consent held");
    let one = exchange(first);
    assert!(
        wait_for_waiters(&observer, &one, 1).await,
        "the first waits"
    );
    let other = exchange(second);
    assert!(
        wait_for_waiters(&observer, &other, 2).await,
        "the second waits too"
    );
    holder.rollback().await.expect("the consent let go");
    assert_eq!(one.await.expect("the first exchange"), Ok(()));
    assert_eq!(other.await.expect("the second exchange"), Ok(()));

    let reading = owner.transaction().await.expect("a transaction");
    reading
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    let standing: i64 = reading
        .query_one(
            "SELECT count(*) FROM sessions WHERE kind = 'offline' AND state = 'active'",
            &[],
        )
        .await
        .expect("a count")
        .get(0);
    assert_eq!(
        standing,
        i64::from(MOST_OFFLINE_GRANTS_PER_CLIENT),
        "the bound holds when two exchanges come at once"
    );
}
