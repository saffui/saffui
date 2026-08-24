mod support;

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::mail::{MailCredentials, MailSettings};
use secrecy::SecretBox;
use server::api::config::{Plane as Mounted, register};
use store::tenancy::TenantContext;
use support::{Plane, Postbox, cookie_value, urlencode};

const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane, postbox: Option<&Postbox>) -> Mounted {
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
        sealing: support::sealing_sending(
            postbox.map(|held| Arc::new(held.clone()) as Arc<dyn services::messaging::Deliver>),
        ),
    }
}

/// A realm that can send, and a flow that offers a link instead of a password.
async fn arrange(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("a keyring");
    store::providers::mail::keep(
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
    services::provisioning::provision_mailed_login(&transaction, support::TENANT, support::REALM)
        .await
        .expect("a mailed login");
    transaction.commit().await.expect("the arrangement kept");
}

/// Open a login and hand back the cookie that names it.
async fn open(plane: &Plane, postbox: &Postbox) -> String {
    let app =
        test::init_service(App::new().configure(register(&mounted(plane, Some(postbox))))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth\
                 ?client_id={}&response_type=code&redirect_uri={}&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

/// Answer the login, and hand back the body.
async fn answer(
    plane: &Plane,
    postbox: &Postbox,
    binding: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let app =
        test::init_service(App::new().configure(register(&mounted(plane, Some(postbox))))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(&body)
            .to_request(),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// The value the message carried.
fn token_in(link: &str) -> String {
    link.rsplit_once("magic_link=")
        .map(|(_, token)| token.trim().to_owned())
        .expect("a link with a token")
}

/// The whole way through: a name, a message, the link followed, a code.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_link_that_arrives_by_post_signs_the_person_in() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane).await;
    let postbox = Postbox::default();

    let binding = open(&plane, &postbox).await;
    let (status, asked) = answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{asked}");
    assert_eq!(asked["status"], "challenge");

    let held = postbox.held();
    assert_eq!(held.len(), 1, "one name asked for one message");
    let message = &held[0];
    assert_eq!(message.to, support::SUBJECT_EMAIL);
    assert!(
        message
            .body
            .contains("/protocol/openid-connect/login?magic_link="),
        "the message carried no link: {}",
        message.body
    );

    let (status, admitted) = answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "magic_link": token_in(&message.body) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{admitted}");
    let landing = admitted["redirect_to"].as_str().expect("somewhere to land");
    assert!(
        landing.starts_with(REDIRECT) && landing.contains("code="),
        "{landing}"
    );
}

/// Once, and only by the login that asked. A link presented twice is a link
/// somebody else may be holding, and one presented by another login is the
/// login somebody else started.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_link_works_once() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane).await;
    let postbox = Postbox::default();

    let binding = open(&plane, &postbox).await;
    answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT }),
    )
    .await;
    let token = token_in(&postbox.held()[0].body);

    // A second login, for the same person, that got as far as naming them.
    // Inside the window nothing new is sent, so what the post still holds is
    // the first login's link, and this login must not be able to spend it.
    let second = open(&plane, &postbox).await;
    answer(
        &plane,
        &postbox,
        &second,
        serde_json::json!({ "username": support::SUBJECT }),
    )
    .await;
    assert_eq!(
        postbox.held().len(),
        1,
        "a second ask inside the window sent a second message"
    );
    let (_, again) = answer(
        &plane,
        &postbox,
        &second,
        serde_json::json!({ "magic_link": token.clone() }),
    )
    .await;
    assert_ne!(
        again["status"], "admitted",
        "a link finished a login it was not asked for"
    );

    let (_, spent) = answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "magic_link": token.clone() }),
    )
    .await;
    assert_eq!(spent["status"], "admitted", "{spent}");

    let third = open(&plane, &postbox).await;
    let (_, replayed) = answer(
        &plane,
        &postbox,
        &third,
        serde_json::json!({ "magic_link": token }),
    )
    .await;
    assert_ne!(replayed["status"], "admitted", "a spent link worked again");
}

/// The page a link lands on spends nothing. What a scanner fetches is a form.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn following_a_link_spends_nothing_until_it_is_submitted() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane).await;
    let postbox = Postbox::default();

    let binding = open(&plane, &postbox).await;
    answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT }),
    )
    .await;
    let token = token_in(&postbox.held()[0].body);

    let app =
        test::init_service(App::new().configure(register(&mounted(&plane, Some(&postbox))))).await;
    let fetched = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login?magic_link={token}",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);
    let page = String::from_utf8(test::read_body(fetched).await.to_vec()).expect("a page");
    assert!(page.contains("<form method=\"post\""), "{page}");

    // And the link still works, which is what fetching it must not have taken.
    let (_, admitted) = answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "magic_link": token }),
    )
    .await;
    assert_eq!(admitted["status"], "admitted", "fetching the page spent it");
}

/// A deployment that cannot send does not leave a login waiting on a message
/// that is never coming: the mailed step fails and the other way in is what
/// the caller is asked for.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_deployment_that_sends_nothing_refuses_rather_than_waits() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane).await;

    let app = test::init_service(App::new().configure(register(&mounted(&plane, None)))).await;
    let opened = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth\
                 ?client_id={}&response_type=code&redirect_uri={}&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode(REDIRECT),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = opened
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(serde_json::json!({ "username": support::SUBJECT }))
            .to_request(),
    )
    .await;
    let told: serde_json::Value = test::read_body_json(response).await;
    // The other way in is still offered, so the login waits on that one.
    assert_eq!(told["status"], "challenge", "{told}");

    // What proves the mailed step refused rather than merely came second: no
    // token was minted. A step that reported a challenge would have left one
    // behind for a message nobody is going to send.
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let minted: i64 = transaction
        .query_one(
            "SELECT count(*) FROM one_time_tokens WHERE purpose = 'magic-link'",
            &[],
        )
        .await
        .expect("a count")
        .get(0);
    assert_eq!(
        minted, 0,
        "a link was minted for a message this deployment cannot send"
    );
}

/// The password never leaves the database in a readable form, and never comes
/// back out of the plane at all.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mail_password_is_sealed_and_never_answered_with() {
    let plane = Plane::with_actions(&[
        models::entities::authz::AdminAction::RealmRead,
        models::entities::authz::AdminAction::RealmWrite,
    ])
    .await;
    arrange(&plane).await;
    let bearer = plane.token(&support::claims());

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let held: Vec<u8> = transaction
        .query_one("SELECT sealed_password FROM realm_mail", &[])
        .await
        .expect("the settings")
        .get(0);
    assert!(
        !String::from_utf8_lossy(&held).contains("a-mail-password"),
        "the password is readable in the column"
    );
    drop(transaction);
    drop(connection);

    let app = test::init_service(App::new().configure(register(&mounted(&plane, None)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/admin/realms/{}/mail", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let shown = String::from_utf8(test::read_body(response).await.to_vec()).expect("a body");
    assert!(
        !shown.contains("a-mail-password") && !shown.contains("password\":\""),
        "the plane answered with a password: {shown}"
    );
    assert!(shown.contains("\"has_password\":true"), "{shown}");
}

/// Writing without one keeps the one held, so editing a host does not blank
/// what nothing asked to change.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn writing_without_a_password_keeps_the_one_held() {
    let plane = Plane::with_actions(&[models::entities::authz::AdminAction::RealmWrite]).await;
    arrange(&plane).await;
    let bearer = plane.token(&support::claims());

    let app = test::init_service(App::new().configure(register(&mounted(&plane, None)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::put()
            .uri(&format!("/admin/realms/{}/mail", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(serde_json::json!({
                "host": "mail2.example",
                "port": 465,
                "from_address": "no-reply@example.test",
                "implicit_tls": true,
                "username": "acme"
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("a keyring");
    let held = store::providers::mail::load(&transaction, &ring, &sealing.envelope)
        .await
        .expect("the settings")
        .expect("settings");
    assert_eq!(held.host, "mail2.example");
    assert!(held.implicit_tls);
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(&held.credentials.expect("credentials kept").password),
        "a-mail-password",
        "the password was blanked by an edit that did not name one"
    );
}

async fn receipts(plane: &Plane) -> Vec<models::messaging::Delivery> {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    store::providers::deliveries::of_user(&transaction, support::SUBJECT, 50)
        .await
        .expect("the deliveries table")
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_message_that_went_out_leaves_a_receipt() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane).await;
    let postbox = Postbox::default();

    let binding = open(&plane, &postbox).await;
    answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT }),
    )
    .await;

    let held = receipts(&plane).await;
    assert_eq!(held.len(), 1, "{held:?}");
    assert!(held[0].delivered, "{held:?}");
    assert_eq!(held[0].purpose, "magic-link");
    assert_eq!(held[0].recipient, support::SUBJECT_EMAIL);
    assert_eq!(held[0].detail, None);
    // The link is what the message carried and what a receipt must not.
    assert!(
        !format!("{held:?}").contains("http"),
        "a receipt carried the link: {held:?}"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_message_the_far_end_refused_leaves_one_saying_so() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane).await;
    let postbox = Postbox::refusing();

    let binding = open(&plane, &postbox).await;
    answer(
        &plane,
        &postbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT }),
    )
    .await;

    assert!(postbox.held().is_empty(), "a refused message was kept");
    let held = receipts(&plane).await;
    assert_eq!(held.len(), 1, "a refusal left no receipt: {held:?}");
    assert!(!held[0].delivered, "{held:?}");
    assert!(
        held[0].detail.is_some(),
        "a refusal said nothing about why: {held:?}"
    );
}
