//! The audit chain on Postgres, verified with the digest the binary links:
//! the database hashes each link, and the verification hashes it again.

use pgcore::APP_ROLE;
use saffui_core::app::App;
use saffui_core::audit::EventKind;
use saffui_core::audit::append::record_event;
use saffui_core::audit::verify::{ChainBreak, ChainVerdict, verify_chain};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::contract::check_audit_contract;
use serde_json::json;
use tokio_postgres::error::SqlState;

#[path = "support/product.rs"]
mod product;

use product::{connect_as, create_realm, scope_statement, wire_on_postgres};

const OWNER: &str = "saffui_owner";

#[tokio::test]
async fn postgres_passes_the_audit_contract() {
    let (app, _database) = wire_on_postgres().await;

    check_audit_contract(&app).await;
}

async fn append_event(app: &App, scope: RealmScope, payload: serde_json::Value) {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    record_event(app, work.as_mut(), EventKind::RealmCreated, payload)
        .await
        .expect("an event");
    work.commit().await.expect("a commit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writers_at_once_leave_one_chain_that_verifies_whole_while_they_write() {
    const WRITERS: i64 = 8;
    const EVENTS_EACH: i64 = 12;
    let (app, _database) = wire_on_postgres().await;
    let scope = create_realm(&app, "busy").await;

    let mut writers = Vec::new();
    for writer in 0..WRITERS {
        let app = app.clone();
        writers.push(tokio::spawn(async move {
            for event in 0..EVENTS_EACH {
                append_event(&app, scope, json!({ "writer": writer, "event": event })).await;
            }
        }));
    }
    // Verified while the writers write: each verification reads one chain.
    let mut verdicts = Vec::new();
    while writers.iter().any(|writer| !writer.is_finished()) {
        verdicts.push(verify_chain(&app, scope).await);
    }
    for writer in writers {
        writer.await.expect("a writer that finished");
    }

    assert!(
        !verdicts.is_empty(),
        "the verification ran while they wrote"
    );
    assert!(
        verdicts
            .iter()
            .all(|verdict| matches!(verdict, Ok(ChainVerdict::Intact { .. }))),
        "{verdicts:?}"
    );
    // Then the whole chain: its creation and its first key, then every
    // append, no gap, no fork.
    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Intact {
            events: 2 + WRITERS * EVENTS_EACH
        })
    );
}

#[tokio::test]
async fn an_envelope_changed_behind_the_product_is_found_by_the_verification() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "tampered").await;
    append_event(&app, scope, json!({ "amount": 10 })).await;
    append_event(&app, scope, json!({ "amount": 20 })).await;

    connect_as(&database, OWNER)
        .await
        .batch_execute(&format!(
            "BEGIN; {};
             UPDATE audit_events
             SET envelope = convert_to(replace(convert_from(envelope, 'UTF8'), '\"amount\":10', '\"amount\":99'), 'UTF8')
             WHERE seq = 3;
             COMMIT;",
            scope_statement(scope)
        ))
        .await
        .expect("a hand in the database");

    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Broken {
            at_seq: 3,
            reason: ChainBreak::Altered
        })
    );
}

#[tokio::test]
async fn an_event_removed_behind_the_product_is_found_by_the_verification() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "pruned").await;
    append_event(&app, scope, json!({ "round": 1 })).await;
    append_event(&app, scope, json!({ "round": 2 })).await;

    connect_as(&database, OWNER)
        .await
        .batch_execute(&format!(
            "BEGIN; {}; DELETE FROM audit_events WHERE seq = 3; COMMIT;",
            scope_statement(scope)
        ))
        .await
        .expect("a hand in the database");

    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Broken {
            at_seq: 4,
            reason: ChainBreak::Gap
        })
    );
}

#[tokio::test]
async fn the_serving_role_writes_the_chain_through_the_function_and_no_other_way() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "guarded").await;
    let session = connect_as(&database, APP_ROLE).await;

    for statement in [
        "INSERT INTO audit_events (tenant_id, realm_id, seq, prev_hash, hash, envelope)
         SELECT tenant_id, realm_id, seq + 1, hash, hash, envelope FROM audit_events",
        "UPDATE audit_events SET envelope = envelope",
        "DELETE FROM audit_events",
        "UPDATE audit_chain_heads SET seq = 0",
        "DELETE FROM audit_chain_heads",
    ] {
        session
            .batch_execute(&format!("BEGIN; {}", scope_statement(scope)))
            .await
            .expect("a scoped transaction");
        let refused = session.batch_execute(statement).await.expect_err(statement);
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}"
        );
        session.batch_execute("ROLLBACK").await.expect("a rollback");
    }
}

#[tokio::test]
async fn an_event_is_not_appended_without_a_scope() {
    let (app, database) = wire_on_postgres().await;
    create_realm(&app, "scoped").await;
    let session = connect_as(&database, APP_ROLE).await;

    let refused = session
        .query(
            "SELECT * FROM saffui_append_audit_event(convert_to('{\"id\":\"00000000-0000-0000-0000-000000000001\"}', 'UTF8'))",
            &[],
        )
        .await
        .expect_err("an append outside any scope");

    assert_eq!(refused.code(), Some(&SqlState::INSUFFICIENT_PRIVILEGE));
}

#[tokio::test]
async fn a_realm_with_a_history_is_not_deleted_with_it() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "kept").await;

    let refused = connect_as(&database, pgcore::MAINTENANCE_ROLE)
        .await
        .execute(
            "DELETE FROM realms WHERE realm_id = $1",
            &[&scope.realm().as_uuid()],
        )
        .await
        .expect_err("a realm whose chain has events");

    assert_eq!(refused.code(), Some(&SqlState::FOREIGN_KEY_VIOLATION));
    assert_eq!(
        refused
            .as_db_error()
            .and_then(|refusal| refusal.constraint()),
        Some("audit_chain_heads_tenant_id_realm_id_fkey"),
        "the chain refuses it, not another row of the realm"
    );
    assert_eq!(
        verify_chain(&app, scope).await,
        Ok(ChainVerdict::Intact { events: 2 })
    );
}

/// Waits until `waiters` sessions of the database wait on a lock, ten seconds
/// at most or until `task` is done, and says whether they did.
async fn wait_for_lock_waiters<T>(
    observer: &tokio_postgres::Client,
    waiters: i64,
    task: &tokio::task::JoinHandle<T>,
) -> bool {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(10);
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// An exchange binds its code before it waits on the head of the chain: a
/// hand on the code then waits on the exchange, and never the other way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exchange_binds_its_code_before_it_waits_on_the_head_of_the_chain() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use saffui_core::oidc::authorize::{
        Authorization, AuthorizationParameters, SignInAnswer, TypedSignIn, begin_authorization,
        finish_sign_in,
    };
    use saffui_core::oidc::token::{TokenRequest, grant_token};
    use saffui_core::secret::Secret;
    use saffui_core::testkit::fixtures::{create_application, create_person};

    const CALLBACK: &str = "https://app.example.test/callback";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let (app, database) = wire_on_postgres().await;
    // Of the same role as the product: it sees what its sessions wait on.
    let observer = connect_as(&database, APP_ROLE).await;
    let scope = create_realm(&app, "exchange").await;
    create_person(&app, scope, "ada", "correct horse battery").await;
    create_application(&app, scope, "webapp", CALLBACK, true).await;
    let challenge = URL_SAFE_NO_PAD.encode(app.digester.sha256(VERIFIER.as_bytes()));
    let asked = AuthorizationParameters {
        response_type: Some("code"),
        client_id: Some("webapp"),
        redirect_uri: Some(CALLBACK),
        scope: Some("openid"),
        code_challenge: Some(&challenge),
        code_challenge_method: Some("S256"),
        ..AuthorizationParameters::default()
    };
    let Ok(Authorization::SignInRequired {
        request,
        browser_secret,
    }) = begin_authorization(&app, "exchange", asked, None).await
    else {
        panic!("a person without a session must sign in");
    };
    let typed = TypedSignIn {
        answer: SignInAnswer::Password {
            name: "ada",
            password: Secret::new(b"correct horse battery".to_vec()),
        },
        caller: None,
        known_browsers: &[],
    };
    let signed_in = finish_sign_in(&app, "exchange", request, &browser_secret, typed)
        .await
        .expect("a signed-in person")
        .into_finished()
        .expect("a person who owes no code");
    let code = signed_in
        .location
        .split_once("code=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("a code")
        .to_owned();
    let digest = app.digester.sha256(code.as_bytes());

    // Another writer holds the head of the chain of the realm.
    let mut holder = app.storage.begin(scope).await.expect("a unit of work");
    record_event(&app, holder.as_mut(), EventKind::RealmCreated, json!({}))
        .await
        .expect("an event");
    let exchange = tokio::spawn({
        let app = app.clone();
        async move {
            let exchanged = TokenRequest {
                grant_type: Some("authorization_code"),
                client_id: Some("webapp"),
                code: Some(&code),
                redirect_uri: Some(CALLBACK),
                code_verifier: Some(VERIFIER),
                ..TokenRequest::default()
            };
            grant_token(&app, "exchange", exchanged).await
        }
    });
    assert!(
        wait_for_lock_waiters(&observer, 1, &exchange).await,
        "the exchange waits on the head"
    );
    let hand_on_the_code = tokio::spawn({
        let app = app.clone();
        async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.mark_code_replayed(&digest, "webapp", app.now()).await
        }
    });
    assert!(
        wait_for_lock_waiters(&observer, 2, &hand_on_the_code).await,
        "the code was bound before the exchange waited on the head"
    );

    drop(holder);
    assert!(
        exchange.await.expect("the exchange").is_ok(),
        "the exchange finishes once the head is free"
    );
    let replayed = hand_on_the_code
        .await
        .expect("the hand on the code")
        .expect("a read")
        .expect("the code, spent");
    assert!(replayed.family.is_some(), "and its family is bound");
}

const PASSWORD: &str = "correct horse battery";

/// The realm `realm` with `ada`, signed in through an application, and her
/// session.
async fn start_signed_in(
    app: &App,
    realm: &str,
) -> (RealmScope, saffui_core::login::session::SessionTicket) {
    use saffui_core::testkit::fixtures::{
        CodeFlow, create_application, create_person, run_code_flow,
    };

    const CALLBACK: &str = "https://app.example.test/callback";
    let scope = create_realm(app, realm).await;
    create_person(app, scope, "ada", PASSWORD).await;
    create_application(app, scope, "webapp", CALLBACK, true).await;
    let flow = CodeFlow {
        realm,
        client_id: "webapp",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid",
        username: "ada",
        password: PASSWORD,
    };
    (scope, run_code_flow(app, flow).await.ticket)
}

/// Gives the password of `ada`, and returns what she owes.
async fn owe_second_factor(app: &App, scope: RealmScope) -> saffui_core::login::flow::SecondFactor {
    use saffui_core::login::flow::{FirstStep, sign_in_with_password};
    use saffui_core::secret::Secret;

    let step = sign_in_with_password(
        app,
        scope,
        "ada",
        Secret::new(PASSWORD.as_bytes().to_vec()),
        None,
        &[],
    )
    .await
    .expect("a right password");
    let FirstStep::SecondFactorRequired(owed) = step else {
        panic!("ada set up a second factor: she owes it");
    };
    owed
}

/// An address of its own for each guess: the name and the person count
/// them, and no address locks.
fn name_address(last: u8) -> std::net::IpAddr {
    std::net::IpAddr::from([192, 0, 2, last])
}

/// Runs `refused` while another writer holds the head of the chain, and
/// tells whether it counted its failure under the name before it waited
/// there: a wrong password for the same name then waits on that count. The
/// opening of a session takes the counters, then the head: the other way
/// round, two requests of one browser would wait on each other.
async fn hold_the_head_while(
    app: &App,
    database: &pgcore::testkit::TestDatabase,
    scope: RealmScope,
    refused: impl Future<Output = Result<(), saffui_core::error::ErrorCode>> + Send + 'static,
) -> (bool, Result<(), saffui_core::error::ErrorCode>) {
    use saffui_core::login::flow::sign_in_with_password;
    use saffui_core::secret::Secret;

    let observer = connect_as(database, APP_ROLE).await;
    let mut holder = app.storage.begin(scope).await.expect("a unit of work");
    record_event(app, holder.as_mut(), EventKind::RealmCreated, json!({}))
        .await
        .expect("an event");
    let refused = tokio::spawn(refused);
    assert!(
        wait_for_lock_waiters(&observer, 1, &refused).await,
        "the refused answer waits on the head"
    );
    let guess = tokio::spawn({
        let app = app.clone();
        async move {
            let wrong = Secret::new(b"not the password".to_vec());
            sign_in_with_password(&app, scope, "ada", wrong, Some(name_address(200)), &[])
                .await
                .map(|_| ())
                .map_err(|failure| failure.code)
        }
    });
    let counted_first = wait_for_lock_waiters(&observer, 2, &guess).await;

    drop(holder);
    let answered = refused.await.expect("the refused answer");
    assert_eq!(
        guess.await.expect("the guess"),
        Err(saffui_core::error::ErrorCode::SignInFailed)
    );
    (counted_first, answered)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_code_that_suspends_the_codes_counts_its_failure_before_it_waits_on_the_head() {
    use std::sync::Arc;

    use saffui_core::error::ErrorCode;
    use saffui_core::login::enroll::{begin_totp_enrollment, confirm_totp_enrollment};
    use saffui_core::login::flow::finish_sign_in_with_code;
    use saffui_core::secret::Secret;
    use saffui_core::testkit::crypto::PredictableCodes;

    let (mut app, database) = wire_on_postgres().await;
    app.one_time_codes = Arc::new(PredictableCodes::default());
    let (scope, ticket) = start_signed_in(&app, "codes").await;
    let offered = begin_totp_enrollment(&app, "codes", Some(&ticket))
        .await
        .expect("a secret to enroll");
    let seconds = u64::try_from(app.now().unix_timestamp()).expect("after 1970");
    let code = PredictableCodes::compute_from_text(&offered.typed_secret, seconds);
    confirm_totp_enrollment(
        &app,
        "codes",
        Some(&ticket),
        Secret::new(PASSWORD.as_bytes().to_vec()),
        &code,
        None,
        &[],
    )
    .await
    .expect("a confirmed authenticator");
    let person = owe_second_factor(&app, scope).await.person.id;
    let guess_code = |last: u8| {
        let app = app.clone();
        async move {
            finish_sign_in_with_code(&app, scope, person, "000000", Some(name_address(last)), &[])
                .await
                .map(|_| ())
                .map_err(|failure| failure.code)
        }
    };
    for last in 1..10 {
        assert_eq!(guess_code(last).await, Err(ErrorCode::CodeRejected));
    }

    let (counted_first, answered) =
        hold_the_head_while(&app, &database, scope, guess_code(10)).await;

    assert_eq!(answered, Err(ErrorCode::CodeRejected));
    assert!(
        counted_first,
        "the tenth wrong code counted its failure before it waited on the head"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_a_key_counts_its_failure_before_it_waits_on_the_head() {
    use std::sync::Arc;

    use saffui_core::error::ErrorCode;
    use saffui_core::login::enroll::{begin_key_enrollment, finish_key_enrollment};
    use saffui_core::login::flow::finish_sign_in_with_key;
    use saffui_core::secret::Secret;
    use saffui_core::testkit::crypto::TrustingKeys;

    let (mut app, database) = wire_on_postgres().await;
    app.security_keys = Arc::new(TrustingKeys::default());
    let (scope, ticket) = start_signed_in(&app, "keys").await;
    let options = begin_key_enrollment(
        &app,
        "keys",
        Some(&ticket),
        Secret::new(PASSWORD.as_bytes().to_vec()),
        None,
        &[],
    )
    .await
    .expect("a started enrollment");
    finish_key_enrollment(
        &app,
        "keys",
        Some(&ticket),
        &TrustingKeys::answer_enrollment(&options, "k1"),
    )
    .await
    .expect("an enrolled key");
    let owed = owe_second_factor(&app, scope).await;
    let person = owed.person.id;
    let answer_key = |counter: u64, asked: saffui_core::ports::crypto::KeyCeremony| {
        let app = app.clone();
        async move {
            let answer = TrustingKeys::answer_proof(&asked.options, "k1", counter);
            finish_sign_in_with_key(&app, scope, person, &asked.state, &answer, None, &[])
                .await
                .map(|_| ())
                .map_err(|failure| failure.code)
        }
    };
    assert_eq!(
        answer_key(3, owed.key.expect("a started proof")).await,
        Ok(())
    );
    let asked = owe_second_factor(&app, scope).await.key;

    let copy = answer_key(3, asked.expect("a started proof"));
    let (counted_first, answered) = hold_the_head_while(&app, &database, scope, copy).await;

    assert_eq!(answered, Err(ErrorCode::KeyRejected));
    assert!(
        counted_first,
        "the copy counted its failure before it waited on the head"
    );
}
