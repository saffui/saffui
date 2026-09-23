//! A realm's mark: the one piece of its look that is a file.

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::Value;
use server::api::config::register;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> server::api::config::Plane {
    server::api::config::Plane {
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

/// The mark rides as the picture itself, so the bench posts bytes rather than
/// a field inside an envelope, exactly as the door takes them.
async fn put_mark(plane: &Plane, bearer: &str, bytes: Vec<u8>) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let asking = test::TestRequest::put()
        .uri(&format!("/admin/realms/{REALM}/logo"))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .set_payload(bytes);
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn asked_admin(plane: &Plane, method: Method, at: &str, bearer: &str) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let asking = test::TestRequest::default()
        .method(method)
        .uri(at)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The public door, asked the way a browser drawing the sign-in page asks it.
async fn fetch_mark(plane: &Plane) -> (StatusCode, String, Vec<u8>) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/logo"))
            .to_request(),
    )
    .await;
    let status = response.status();
    let kind = response
        .headers()
        .get("content-type")
        .and_then(|held| held.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let sniffing = response
        .headers()
        .get("x-content-type-options")
        .and_then(|held| held.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = test::read_body(response).await;
    (status, format!("{kind}|{sniffing}"), body.to_vec())
}

fn png() -> Vec<u8> {
    let mut held = b"\x89PNG\r\n\x1a\n".to_vec();
    held.extend_from_slice(&[7; 64]);
    held
}

/// Kept as it arrived and served back the same, under the type weighed on the
/// way in rather than one guessed on the way out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mark_is_served_back_exactly_as_it_was_kept() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    // Nothing kept yet: the door is a picture that is not there, and the page
    // draws its letters instead.
    let (status, ..) = fetch_mark(&plane).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, told) = put_mark(&plane, &bearer, png()).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (status, headers, bytes) = fetch_mark(&plane).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, png(), "the bytes came back changed");
    assert_eq!(
        headers, "image/png|nosniff",
        "the mark is served under a guess, or a browser is left to re-read it"
    );

    let (status, told) = asked_admin(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/logo"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["held"], true, "{told}");
    assert_eq!(told["media_type"], "image/png", "{told}");

    let (status, told) = asked_admin(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/logo"),
        &bearer,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, ..) = fetch_mark(&plane).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the mark outlived its removal"
    );
}

/// The rule that matters. Served from this origin, a drawing that carries a
/// script runs it the moment its own address is opened, so the format is
/// refused rather than cleaned.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_drawing_that_can_carry_a_script_is_never_kept() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    for held in [
        &b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"[..],
        &b"<?xml version=\"1.0\"?><svg/>"[..],
    ] {
        let (status, told) = put_mark(&plane, &bearer, held.to_vec()).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a drawing was kept: {told}"
        );
    }
    let (status, ..) = fetch_mark(&plane).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "something was kept anyway");
}

/// Two refusals, said apart, so an operator is told which rule they hit.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_picture_past_the_cap_is_refused_for_its_size_and_not_its_format() {
    let plane = Plane::with_actions(&[AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let mut huge = png();
    huge.resize(services::theme::LARGEST_LOGO + 1, 0);
    let (status, told) = put_mark(&plane, &bearer, huge).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let said = told["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        said.contains("64 KiB"),
        "the size rule went unnamed: {told}"
    );

    let (_, told) = put_mark(&plane, &bearer, b"not a picture at all".to_vec()).await;
    assert_ne!(
        told["message"].as_str().unwrap_or_default(),
        said,
        "a wrong format and a wrong size say the same thing: {told}"
    );
}
