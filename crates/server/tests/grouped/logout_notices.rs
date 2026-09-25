#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use serde_json::Value;
use store::providers::protocol::sessions;
use store::tenancy::TenantContext;

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

/// One outbox pass, the way the scheduler runs it, dialling anywhere: the ears
/// here listen on this machine.
async fn walked(plane: &Plane) {
    walked_backing_off(plane, 1).await;
}

/// The same pass, leasing what it claims for `backoff_seconds` per attempt.
async fn walked_backing_off(plane: &Plane, backoff_seconds: i64) {
    scheduler::jobs::deliver_every_realm(
        &plane.tenancy(),
        &support::sealing(),
        &support::origin(),
        backoff_seconds,
    )
    .await;
}

/// The login a posted logout token names.
fn named_login(posted: &str) -> Value {
    let token = posted
        .strip_prefix("logout_token=")
        .expect("a logout token");
    let payload = token.split('.').nth(1).expect("a payload");
    let claims: Value = serde_json::from_slice(
        &data_encoding::BASE64URL_NOPAD
            .decode(payload.as_bytes())
            .expect("base64url"),
    )
    .expect("claims");
    claims["sid"].clone()
}

/// The state and the attempts of the notice a login owes a client, if any.
async fn owed(plane: &Plane, session_id: &str, client_id: &str) -> Option<(String, i32)> {
    let transaction = plane.scoped(&within()).await;
    transaction
        .query_opt(
            "SELECT state, attempts FROM logout_notices WHERE session_id = $1 AND client_id = $2",
            &[&session_id, &client_id],
        )
        .await
        .expect("the notices table")
        .map(|row| (row.get("state"), row.get("attempts")))
}

#[derive(Debug, Clone, Copy)]
enum Ending {
    One,
    AllButOne,
    Person,
    Realm,
}

/// Every way a login ends without the browser logging out owes its clients a
/// notice, and the outbox pass tells them: one login closed, every login but the
/// one in use, every login of the person, every login of the realm.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_way_a_login_ends_tells_its_clients() {
    let plane = Plane::with_actions(&[]).await;
    for ending in [
        Ending::One,
        Ending::AllButOne,
        Ending::Person,
        Ending::Realm,
    ] {
        let (uri, heard) = support::listening_ear();
        plane
            .register_backchannel(support::CONFIDENTIAL, &uri)
            .await;
        let session = format!("session-{ending:?}");
        plane.open_login_of(&session, support::SUBJECT).await;
        plane
            .plant_grant_of(&session, support::SUBJECT, support::CONFIDENTIAL)
            .await;

        let transaction = plane.scoped(&within()).await;
        match ending {
            Ending::One => sessions::close(&transaction, &session).await.map(|_| ()),
            Ending::AllButOne => {
                sessions::end_others_of_user(&transaction, support::SUBJECT, support::SESSION)
                    .await
                    .map(|_| ())
            }
            Ending::Person => sessions::end_all_of_user(&transaction, support::SUBJECT)
                .await
                .map(|_| ()),
            Ending::Realm => sessions::end_all_of_realm(&transaction, support::REALM)
                .await
                .map(|_| ()),
        }
        .expect("the sessions table");
        transaction.commit().await.expect("the ending kept");
        assert_eq!(
            owed(&plane, &session, support::CONFIDENTIAL).await,
            Some(("pending".to_owned(), 0)),
            "{ending:?}: nothing was owed"
        );

        walked(&plane).await;
        let posted = heard
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("{ending:?}: the client was not told"));
        assert_eq!(named_login(&posted), session.as_str(), "{ending:?}");
        assert_eq!(
            owed(&plane, &session, support::CONFIDENTIAL)
                .await
                .map(|(state, _)| state),
            Some("sent".to_owned()),
            "{ending:?}"
        );
    }
}

/// An application whose access an administrator takes back is told, the login
/// going on; the same grant closed because the client revoked its own token owes
/// it nothing, since the client knows.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn access_taken_back_is_told_and_a_revoked_token_is_not() {
    let plane = Plane::with_actions(&[]).await;
    plane
        .register_backchannel(support::CONFIDENTIAL, "https://app.example/logout")
        .await;
    for session in ["session-taken", "session-revoked"] {
        plane.open_login_of(session, support::SUBJECT).await;
        plane
            .plant_grant_of(session, support::SUBJECT, support::CONFIDENTIAL)
            .await;
    }

    let transaction = plane.scoped(&within()).await;
    services::admin::sessions::revoke_grant(
        &transaction,
        support::SUBJECT,
        "session-taken",
        support::CONFIDENTIAL,
    )
    .await
    .expect("the grant taken back");
    sessions::close_client_session_of(&transaction, "session-revoked", support::CONFIDENTIAL)
        .await
        .expect("the grant closed");
    transaction.commit().await.expect("kept");

    assert_eq!(
        owed(&plane, "session-taken", support::CONFIDENTIAL).await,
        Some(("pending".to_owned(), 0)),
        "an application whose access was taken back is owed nothing"
    );
    assert_eq!(
        owed(&plane, "session-revoked", support::CONFIDENTIAL).await,
        None,
        "a client that revoked its own token is owed a notice"
    );
}

/// A client that does not take its notice is tried again on the pass after its
/// lease runs out, and given up on once its attempts do, never dropped on the
/// first failure and never tried forever.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_notice_nobody_takes_is_tried_again_then_given_up() {
    let plane = Plane::with_actions(&[]).await;
    // Nothing listens on the discard port, so every post is refused.
    plane
        .register_backchannel(support::CONFIDENTIAL, "http://127.0.0.1:9/logout")
        .await;
    plane
        .open_login_of("session-unheard", support::SUBJECT)
        .await;
    plane
        .plant_grant_of("session-unheard", support::SUBJECT, support::CONFIDENTIAL)
        .await;
    let transaction = plane.scoped(&within()).await;
    sessions::close(&transaction, "session-unheard")
        .await
        .expect("the sessions table");
    transaction.commit().await.expect("kept");

    // A lease long enough that no machine outruns it between two passes.
    let attempts = services::messaging::notices::NOTICE_ATTEMPTS;
    for attempt in 1..=attempts {
        walked_backing_off(&plane, 60).await;
        let (state, made) = owed(&plane, "session-unheard", support::CONFIDENTIAL)
            .await
            .expect("the notice");
        assert_eq!(made, attempt, "an attempt was skipped or made twice");
        let expected = if attempt < attempts {
            "pending"
        } else {
            "dead"
        };
        assert_eq!(state, expected, "after {attempt} attempts");

        // A second pass inside the lease leaves the notice alone.
        walked_backing_off(&plane, 60).await;
        assert_eq!(
            owed(&plane, "session-unheard", support::CONFIDENTIAL)
                .await
                .map(|(_, made)| made),
            Some(attempt),
            "a pass took a notice another had leased"
        );

        let transaction = plane.scoped(&within()).await;
        transaction
            .execute(
                "UPDATE logout_notices SET next_attempt_at = now() - interval '1 second'",
                &[],
            )
            .await
            .expect("the lease run out");
        transaction.commit().await.expect("kept");
    }
}
