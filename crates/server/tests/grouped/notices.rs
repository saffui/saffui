#[allow(unused_imports)]
use super::support;
use std::sync::Arc;

use super::support::{Plane, Postbox};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use crypto::provider::CryptoProvider as _;
use models::entities::authz::AdminAction;
use models::entities::mail::{MailCredentials, MailSettings};
use secrecy::SecretBox;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use services::messaging::notices::NOTICE_ATTEMPTS;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, REALM)
}

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Anywhere,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Value,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::default()
            .method(method)
            .uri(path)
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(body)
            .to_request(),
    )
    .await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The realm names a mail server to send with.
async fn arrange_mail(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("a keyring");
    store::providers::realms::mail::keep(
        &transaction,
        &ring,
        &sealing.envelope,
        &MailSettings {
            host: "mail.example".to_owned(),
            port: 587,
            from_address: "no-reply@example.test".to_owned(),
            from_name: "Acme".to_owned(),
            reply_to: None,
            implicit_tls: false,
            credentials: Some(MailCredentials {
                username: "acme".to_owned(),
                password: SecretBox::new(Box::new("a-mail-password".to_owned())),
            }),
        },
    )
    .await
    .expect("the settings kept");
    transaction.commit().await.expect("the settings kept");
}

/// One walk of every realm's outbox and of the notices it owes, carried out by
/// `postbox`, or by nothing where the deployment sends nothing. No backoff to wait
/// out: whatever failed is due again on the next walk.
async fn walk(plane: &Plane, postbox: Option<&Postbox>) {
    scheduler::jobs::deliver_every_realm(
        &plane.tenancy(),
        &support::sealing_sending(
            postbox.map(|held| Arc::new(held.clone()) as Arc<dyn auth::messaging::Deliver>),
        ),
        &support::origin(),
        0,
    )
    .await;
}

async fn notice_states(plane: &Plane) -> Vec<String> {
    let transaction = plane.scoped(&within()).await;
    transaction
        .query("SELECT state FROM security_notices ORDER BY event_id", &[])
        .await
        .expect("the notices table")
        .into_iter()
        .map(|row| row.get(0))
        .collect()
}

async fn mark_email_verified(plane: &Plane, verified: bool) {
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::users::set_email_verified(
        &transaction,
        support::SUBJECT,
        verified,
    )
    .await
    .expect("the users table");
    transaction.commit().await.expect("the address kept");
}

async fn switch_notices(plane: &Plane, switched: Option<bool>) {
    let transaction = plane.scoped(&within()).await;
    let mut realm = store::providers::realms::load(&transaction, REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.security_notices_enabled = switched;
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the switch kept");
}

async fn plant_recovery_codes(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::credentials::replace_recovery_codes(
        &transaction,
        support::provider().digest(),
        support::REALM,
        support::SUBJECT,
        &["first-code", "second-code"],
        &["sheet-1", "sheet-2"],
        &models::auditable::AuditableModel::from_creator(
            support::TENANT.to_owned(),
            support::SUBJECT.to_owned(),
        ),
    )
    .await
    .expect("the credentials table");
    transaction.commit().await.expect("the sheet kept");
}

/// A factor added to an account is mailed to the person's verified address once,
/// in plain words and without a link, however many walks follow.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_factor_added_is_mailed_once_to_the_verified_address() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    plane.enrol_totp("app-two", support::TOTP_SECRET).await;
    walk(&plane, Some(&postbox)).await;
    walk(&plane, Some(&postbox)).await;

    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].to, support::SUBJECT_EMAIL);
    assert!(
        held[0]
            .subject
            .ends_with("An authenticator app was added to your account"),
        "{}",
        held[0].subject
    );
    assert!(
        held[0]
            .body
            .contains(&format!("Account: {}\n", support::SUBJECT)),
        "{}",
        held[0].body
    );
    assert!(!held[0].body.contains("http"), "{}", held[0].body);
    assert_eq!(
        notice_states(&plane).await.last().map(String::as_str),
        Some("sent")
    );
}

/// A connector that keeps failing keeps the change's telling pending, and the
/// notice it owed is still mailed once: the notice is settled apart from the
/// telling.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_notice_is_mailed_once_while_a_webhook_keeps_failing() {
    let plane = Plane::with_actions(&[AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    arrange_mail(&plane).await;
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        json!({
            "provider_id": "siem",
            "name": "siem",
            "display_name": "", "description": "", "trust_email": false,
            "configs": {
                "kind": { "Str": "webhook" },
                "url": { "Str": "http://127.0.0.1:9/hook" },
                "filter": { "Str": "credential.changed" },
                "secret": { "Str": "a-webhook-secret-of-decent-length" },
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    walk(&plane, None).await;
    let postbox = Postbox::default();

    plane.enrol_totp("app-two", support::TOTP_SECRET).await;
    walk(&plane, Some(&postbox)).await;
    walk(&plane, Some(&postbox)).await;

    assert_eq!(postbox.held().len(), 1, "{:?}", postbox.held());
    let transaction = plane.scoped(&within()).await;
    let telling = transaction
        .query_one(
            "SELECT state::text, attempts FROM event_outbox WHERE kind = $1 \
             ORDER BY event_id DESC LIMIT 1",
            &[&store::providers::events::outbox::CREDENTIAL_CHANGED],
        )
        .await
        .expect("the outbox");
    assert_eq!(telling.get::<_, String>(0), "pending");
    assert!(telling.get::<_, i32>(1) >= 2, "the telling was not retried");
}

/// A recovery code spent to sign in is mailed as such, with how many codes are
/// left, and not as a sheet given up.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_recovery_code_used_to_sign_in_is_mailed_with_the_codes_left() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    plant_recovery_codes(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    {
        let transaction = plane.scoped(&within()).await;
        let spent = store::providers::directory::credentials::spend_recovery_code(
            &transaction,
            support::provider().digest(),
            support::SUBJECT,
            "first-code",
        )
        .await
        .expect("the credentials table");
        assert!(spent, "the code was not one of the sheet");
        transaction.commit().await.expect("the spending kept");
    }
    walk(&plane, Some(&postbox)).await;

    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert!(
        held[0]
            .subject
            .ends_with("A recovery code was used to sign in to your account"),
        "{}",
        held[0].subject
    );
    assert!(
        held[0].body.contains("Recovery codes left: 1\n"),
        "{}",
        held[0].body
    );
}

/// A notice goes only to a verified address, and only while the realm has not
/// switched its notices off; one that never goes out is settled as skipped.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_notice_goes_only_to_a_verified_address_in_a_realm_that_sends_them() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    mark_email_verified(&plane, false).await;
    plane.enrol_totp("app-two", support::TOTP_SECRET).await;
    walk(&plane, Some(&postbox)).await;
    assert!(
        postbox.held().is_empty(),
        "an unverified address was written to"
    );

    mark_email_verified(&plane, true).await;
    switch_notices(&plane, Some(false)).await;
    plane.enrol_totp("app-three", support::TOTP_SECRET).await;
    walk(&plane, Some(&postbox)).await;
    assert!(
        postbox.held().is_empty(),
        "a realm switched off sent a notice"
    );

    switch_notices(&plane, None).await;
    plane.enrol_totp("app-four", support::TOTP_SECRET).await;
    walk(&plane, Some(&postbox)).await;
    assert_eq!(postbox.held().len(), 1, "{:?}", postbox.held());
    let states = notice_states(&plane).await;
    assert_eq!(states[states.len() - 3..], ["skipped", "skipped", "sent"]);
}

/// An administrator taking a whole sheet away writes an event per code in one
/// transaction, and the person is told once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sheet_revoked_at_once_is_one_notice() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    {
        let transaction = plane.scoped(&within()).await;
        for _ in 0..2 {
            store::providers::events::outbox::emit(
                &transaction,
                store::providers::events::outbox::CREDENTIAL_CHANGED,
                support::SUBJECT,
                &json!({ "credential_type": "recovery-code", "change_type": "revoke" }),
            )
            .await
            .expect("an emission");
        }
        transaction.commit().await.expect("the revocation kept");
    }
    walk(&plane, Some(&postbox)).await;

    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert!(
        held[0]
            .subject
            .ends_with("An administrator removed your recovery codes"),
        "{}",
        held[0].subject
    );
}

/// A mail server that keeps refusing is offered the notice again on each walk,
/// every attempt on the record, until the last allowed gives it up.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_notice_refused_every_time_is_given_up_on_the_record() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let refusing = Postbox::refusing();

    plane.enrol_totp("app-two", support::TOTP_SECRET).await;
    for walked in 1..=NOTICE_ATTEMPTS {
        walk(&plane, Some(&refusing)).await;
        let expected = if walked < NOTICE_ATTEMPTS {
            "pending"
        } else {
            "dead"
        };
        assert_eq!(
            notice_states(&plane).await.last().map(String::as_str),
            Some(expected),
            "after walk {walked}"
        );
    }

    let transaction = plane.scoped(&within()).await;
    let receipts: Vec<_> =
        store::providers::events::deliveries::of_user(&transaction, support::SUBJECT, 50)
            .await
            .expect("the deliveries table")
            .into_iter()
            .filter(|receipt| receipt.purpose == services::messaging::notices::SECURITY_NOTICE)
            .collect();
    assert_eq!(
        receipts.len(),
        NOTICE_ATTEMPTS as usize,
        "an attempt went unrecorded"
    );
    assert!(
        receipts.iter().all(|receipt| !receipt.delivered),
        "a refused notice was recorded as delivered"
    );
}

/// A happening about somebody no longer held owes nothing, and does not stop the
/// walk: the notice another change owes still goes out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_happening_about_nobody_held_does_not_stop_the_walk() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    {
        let transaction = plane.scoped(&within()).await;
        store::providers::events::outbox::emit(
            &transaction,
            store::providers::events::outbox::CREDENTIAL_CHANGED,
            "somebody-gone",
            &json!({ "credential_type": "password", "change_type": "update" }),
        )
        .await
        .expect("an emission");
        transaction.commit().await.expect("the happening kept");
    }
    plane.enrol_totp("app-two", support::TOTP_SECRET).await;
    walk(&plane, Some(&postbox)).await;

    assert_eq!(postbox.held().len(), 1, "{:?}", postbox.held());
}

/// Settled notices leave once their window has passed, and a notice still owed
/// stays however old it is.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn settled_notices_age_out_and_owed_ones_stay() {
    let plane = Plane::with_actions(&[]).await;
    walk(&plane, None).await;
    let settled = notice_states(&plane).await;
    assert!(
        settled.len() >= 2,
        "the planted world owed too few notices: {settled:?}"
    );

    let transaction = plane.scoped(&within()).await;
    transaction
        .batch_execute(
            "UPDATE security_notices SET occurred_at = now() - interval '31 days'; \
             UPDATE security_notices SET state = 'pending' \
             WHERE event_id = (SELECT min(event_id) FROM security_notices)",
        )
        .await
        .expect("the notices aged");
    let swept = services::realm::housekeeping::drop_expired_rows(&transaction, chrono::Utc::now())
        .await
        .expect("a sweep");
    transaction.commit().await.expect("the sweep kept");

    assert_eq!(swept.security_notices, settled.len() as u64 - 1);
    assert_eq!(notice_states(&plane).await, ["pending"]);
}

async fn change_address(plane: &Plane, email: &str, declared_verified: Option<bool>) {
    let transaction = plane.scoped(&within()).await;
    services::admin::users::update(
        &transaction,
        support::SUBJECT,
        &services::admin::users::Spec {
            email: Some(email.to_owned()),
            email_verified: declared_verified,
            ..Default::default()
        },
    )
    .await
    .expect("the address changed");
    transaction.commit().await.expect("the address kept");
}

async fn subject_address_verified(plane: &Plane) -> Option<bool> {
    let transaction = plane.scoped(&within()).await;
    store::providers::directory::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("ada stands")
        .email_verified
}

/// An address moved away from a verified one is told to that old address, with the
/// new one masked and no advice to reset a password whose link would go to the new
/// one, and the new address no longer counts as verified. An update that keeps the
/// address tells nothing and keeps its verification, a move away from an address
/// never verified is told to nobody, and an address declared verified in the same
/// update stays so.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_address_moved_away_from_a_verified_one_is_told_to_it() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    change_address(&plane, support::SUBJECT_EMAIL, None).await;
    walk(&plane, Some(&postbox)).await;
    assert!(
        postbox.held().is_empty(),
        "an address kept was told as moved: {:?}",
        postbox.held()
    );
    assert_eq!(
        subject_address_verified(&plane).await,
        Some(true),
        "an address kept lost its verification"
    );

    change_address(&plane, "ada.lovelace@example.org", None).await;
    walk(&plane, Some(&postbox)).await;
    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].to, support::SUBJECT_EMAIL);
    assert!(
        held[0]
            .subject
            .ends_with("The email address of your account was changed"),
        "{}",
        held[0].subject
    );
    assert!(
        held[0].body.contains("New address: a***@example.org\n"),
        "{}",
        held[0].body
    );
    assert!(!held[0].body.contains("reset"), "{}", held[0].body);
    assert_eq!(
        subject_address_verified(&plane).await,
        Some(false),
        "a moved address stayed verified"
    );

    change_address(&plane, "ada@example.org", Some(true)).await;
    walk(&plane, Some(&postbox)).await;
    assert_eq!(
        postbox.held().len(),
        1,
        "an address never verified was told: {:?}",
        postbox.held()
    );
    assert_eq!(
        subject_address_verified(&plane).await,
        Some(true),
        "an address declared verified was not kept so"
    );
}

/// An upstream account linked by its address to an account that already existed is
/// told to that account with the provider named; an account made by its first
/// sign-in through the provider hears nothing of its own link.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_provider_linked_to_an_existing_account_is_told() {
    let plane = Plane::with_actions(&[]).await;
    arrange_mail(&plane).await;
    walk(&plane, None).await;
    let postbox = Postbox::default();

    {
        let transaction = plane.scoped(&within()).await;
        let provider = models::entities::authz::IdentityProviderModel {
            internal_id: "idp-acme".into(),
            realm_id: REALM.into(),
            provider_id: "acme".into(),
            name: "acme".into(),
            display_name: "Acme Directory".into(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(true),
            configs: None,
            metadata: models::auditable::AuditableModel::from_creator(
                support::TENANT.to_owned(),
                "root".to_owned(),
            ),
        };
        store::providers::federation::brokering::create_provider(&transaction, &provider)
            .await
            .expect("a provider");
        for (upstream, email) in [
            ("upstream-ada", support::SUBJECT_EMAIL),
            ("upstream-newcomer", "newcomer@example.test"),
        ] {
            services::federation::brokering::decide_link(
                &transaction,
                &support::provider(),
                support::TENANT,
                REALM,
                &provider,
                &services::federation::brokering::Arrival {
                    external_user_id: upstream.to_owned(),
                    username: None,
                    email: Some(email.to_owned()),
                    email_verified: true,
                    claims: serde_json::Map::new(),
                },
                chrono::Utc::now(),
            )
            .await
            .expect("a link");
        }
        transaction.commit().await.expect("the links kept");
    }
    walk(&plane, Some(&postbox)).await;

    let held = postbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].to, support::SUBJECT_EMAIL);
    assert!(
        held[0]
            .subject
            .ends_with("An external account was linked to your account"),
        "{}",
        held[0].subject
    );
    assert!(
        held[0].body.contains("Provider: Acme Directory\n"),
        "{}",
        held[0].body
    );
}
