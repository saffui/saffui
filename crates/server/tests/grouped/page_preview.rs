//! A hosted page shown to be looked at rather than used.

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use models::entities::authz::AdminAction;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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

async fn looked_at(plane: &Plane, uri: &str) -> (StatusCode, String) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::get().uri(uri).to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn drafted(plane: &Plane, bearer: &str, overrides: Value) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::post()
        .uri(&format!("/admin/realms/{REALM}/page-draft"))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .set_json(json!({ "overrides": overrides }))
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn speak_french(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    realm.supported_locales = Some(vec!["fr".to_owned()]);
    realm.default_locale = Some("fr".to_owned());
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the setting kept");
}

/// The whole security of the preview. The draft behind it is an administrator's,
/// but the page is opened by a browser carrying nothing, so the link is as good
/// as public for as long as it lives. A sign-in page that cannot post cannot
/// collect a password.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_page_shown_to_be_looked_at_can_send_nothing_anywhere() {
    let plane = Plane::with_actions(&[]).await;
    let (status, body) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/login"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // No form at all, rather than a form pointed somewhere harmless: one left
    // standing and turned to `get` would serialise a typed password into the
    // address bar, which is a worse place for it than a POST body.
    assert!(
        !body.contains("<form"),
        "a preview still carries a form: {body}"
    );
    assert!(
        body.contains("data-was-a-form"),
        "the form was not unmade, it is simply missing: {body}"
    );
    assert!(
        !body.contains("<script"),
        "a preview still runs a script: {body}"
    );
    assert!(
        body.contains("preview-banner"),
        "a preview does not say it is one: {body}"
    );
}

/// A name no page answers to is a page that is not there, rather than a page
/// chosen for the caller.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_pages_this_build_renders_can_be_looked_at() {
    let plane = Plane::with_actions(&[]).await;
    for which in ["login", "device", "requests", "reset"] {
        let (status, body) = looked_at(
            &plane,
            &format!("/realms/{REALM}/protocol/openid-connect/page-preview/{which}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{which}: {body}");
    }
    let (status, _) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/../../etc"),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
}

/// What the console has not saved yet is what the page shows, which is the
/// whole reason the draft exists.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_draft_is_what_the_page_says_before_anybody_saves_it() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, kept) = drafted(
        &plane,
        &bearer,
        json!({ "en": { "login-title": "Come in, we kept the light on" } }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{kept}");
    let draft = kept["preview_id"].as_str().expect("an identifier");

    let (status, body) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/login?draft={draft}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("Come in, we kept the light on"),
        "the draft is not what the page says: {body}"
    );

    // And the saved page is untouched by anybody looking at a draft.
    let (status, saved) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/login"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert!(!saved.contains("Come in, we kept the light on"), "{saved}");
}

/// Wording is prose, and prose holds no markup. This door renders text an
/// administrator typed, so a draft that could carry a tag would turn the
/// preview into the one thing it was built not to be.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_draft_cannot_write_markup_into_the_page() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, kept) = drafted(
        &plane,
        &bearer,
        json!({ "en": { "login-title": "<script>fetch('https://elsewhere.example')</script>" } }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{kept}");
    let draft = kept["preview_id"].as_str().expect("an identifier");

    let (status, body) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/login?draft={draft}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("&lt;script&gt;"),
        "a draft's markup was not spelled out: {body}"
    );
    assert!(
        !body.contains("<script>fetch"),
        "a draft wrote a script into the page: {body}"
    );
}

/// A draft outlives the minutes it was given and nothing more: the link is as
/// good as public while it lives, so how long it lives is the bound.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_draft_stops_being_read_once_it_has_run_out() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, kept) = drafted(
        &plane,
        &bearer,
        json!({ "en": { "login-title": "Come in, we kept the light on" } }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{kept}");
    assert!(kept["preview_id"].is_string(), "{kept}");

    // A draft already out of time, written the same way the door writes one.
    // Inserted rather than aged, because this table is granted no update: the
    // identifier is drawn and never rewritten.
    let draft = "0123456789abcdef0123456789abcdef";
    plant_a_spent_draft(&plane, draft).await;

    // Shown as saved rather than refused: the page is still the answer to what
    // it looks like, and it is the draft that is gone.
    let (status, body) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/login?draft={draft}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains("Come in, we kept the light on"),
        "a draft was read after it ran out: {body}"
    );
}

/// A draft whose time is already up, on the database's own clock.
async fn plant_a_spent_draft(plane: &Plane, draft: &str) {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &TenantContext::new(support::TENANT, support::REALM),
        )
        .await;
    transaction
        .execute(
            "INSERT INTO page_previews (tenant, realm_id, preview_id, overrides, expires_at) \
             VALUES (current_setting('saffui.current_tenant', true), \
                     current_setting('saffui.current_realm', true), $1, $2, \
                     now() - interval '1 minute')",
            &[
                &draft,
                &serde_json::json!({ "en": { "login-title": "Come in, we kept the light on" } }),
            ],
        )
        .await
        .expect("the previews table");
    transaction.commit().await.expect("the spent draft kept");
}

/// One guard for both doors: a draft that could carry what saving refuses
/// would preview a page nobody can keep.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_draft_is_weighed_exactly_as_saved_wording_is() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    for refused in [
        json!({ "en": { "no-page-reads-this": "hello" } }),
        json!({ "kl": { "login-title": "hello" } }),
        json!({ "en": { "login-title": 12 } }),
        json!(["not an object at all"]),
    ] {
        let (status, told) = drafted(&plane, &bearer, refused.clone()).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{refused} was kept: {told}"
        );
    }
}

/// The page a reset link opens was written in English and only in English, so
/// a realm speaking anything else showed one page nobody there could read.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_reset_page_speaks_the_realm_s_tongue() {
    let plane = Plane::with_actions(&[]).await;
    speak_french(&plane).await;
    let (status, body) = looked_at(
        &plane,
        &format!("/realms/{REALM}/protocol/openid-connect/page-preview/reset"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("Nouveau mot de passe"),
        "the reset page is still English for a French realm: {body}"
    );
    assert!(body.contains(r#"lang="fr""#), "{body}");
}
