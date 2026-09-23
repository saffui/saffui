use super::no_connection::{mounted, vouched};
use super::support::{self, Plane};
use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use serde_json::Value;
use server::api::config::register;
use tokio_postgres::NoTls;

/// Take a right from the application role, as the owner of this test's
/// database, so a read fails once the realm is found and the unit of work open.
async fn deny(statement: &str) {
    let (owner, connection) = support::owner().connect(NoTls).await.expect("the owner");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    owner
        .batch_execute(statement)
        .await
        .expect("the right is taken");
}

async fn asked(plane: &Plane, request: test::TestRequest) -> (StatusCode, Value, bool) {
    let app = test::init_service(App::new().configure(register(&mounted(plane.tenancy())))).await;
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let clears = response.headers().contains_key("set-cookie");
    let body = serde_json::from_slice(&test::read_body(response).await).unwrap_or(Value::Null);
    (status, body, clears)
}

fn signing_out(request: test::TestRequest) -> test::TestRequest {
    vouched(request)
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/logout",
            support::REALM
        ))
        .insert_header(("accept", "text/html"))
        .cookie(Cookie::new(support::SSO_COOKIE, support::SESSION))
}

/// A sign-out that could not read the realm's keys ended nothing, and neither
/// says it did nor lets go of the cookies the person needs to try again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sign_out_that_could_not_read_the_keys_claims_none() {
    let plane = Plane::with_actions(&[]).await;
    deny("REVOKE SELECT ON realm_signing_keys FROM saffui_app").await;

    let (status, _, clears) = asked(&plane, signing_out(test::TestRequest::get())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !clears,
        "a sign-out that ended nothing let go of the cookies"
    );
    assert!(plane.login_is_open(support::SESSION).await);
}

/// The ending itself refused by the database: the commit is refused with it,
/// and the page does not say the person is signed out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sign_out_whose_ending_was_not_written_claims_none() {
    let plane = Plane::with_actions(&[]).await;
    deny("REVOKE UPDATE ON user_sessions FROM saffui_app").await;

    let (status, _, clears) = asked(
        &plane,
        signing_out(test::TestRequest::post()).set_form([("confirmed", "yes")]),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !clears,
        "a sign-out that ended nothing let go of the cookies"
    );
    assert!(plane.login_is_open(support::SESSION).await);
}

/// A realm's rule on plain connections that cannot be read is not taken as
/// leave to serve in the clear, whether the realm's row or the resolution
/// failed. A realm nobody holds still passes to the endpoint, as before.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_rule_that_cannot_be_read_does_not_serve_in_the_clear() {
    let certs = |realm: &str| {
        test::TestRequest::get().uri(&format!("/realms/{realm}/protocol/openid-connect/certs"))
    };
    for denied in [
        "REVOKE SELECT ON realms FROM saffui_app",
        "REVOKE EXECUTE ON FUNCTION resolve_realm_by_name(text) FROM saffui_app",
    ] {
        let plane = Plane::with_actions(&[]).await;
        deny(denied).await;
        let (status, body, _) = asked(&plane, certs(support::REALM)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{denied}: {body}");
        assert_eq!(body["error"], "temporarily_unavailable", "{denied}: {body}");
    }

    let plane = Plane::with_actions(&[]).await;
    deny("REVOKE SELECT ON realms FROM saffui_app").await;
    let (status, _, _) = asked(&plane, certs("nowhere")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown realm was answered by the transport"
    );
}

/// A store that fails under a guard is the server's fault, and a console told it
/// is signed out over a failed read would drop a sign-in that still stands.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_store_that_fails_under_a_guard_is_no_missing_token() {
    let admin = |bearer: &str| {
        test::TestRequest::get()
            .uri(&format!("/admin/realms/{}/users", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
    };
    let decision = |bearer: &str| {
        test::TestRequest::post()
            .uri("/authz/decision")
            .insert_header(("authorization", format!("Bearer {bearer}")))
    };
    let account = |bearer: &str| {
        vouched(test::TestRequest::get())
            .uri(&format!("/realms/{}/account-api/v1/me", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
    };
    type Door = dyn Fn(&str) -> test::TestRequest;
    let cases: [(&str, &str, &Door); 7] = [
        (
            "the admin guard reading the keys",
            "realm_signing_keys",
            &admin,
        ),
        (
            "the admin guard asking after a withdrawal",
            "realms",
            &admin,
        ),
        ("the admin guard reading the subject", "users", &admin),
        (
            "the admin guard reading what may be done",
            "users_roles",
            &admin,
        ),
        (
            "the decision point reading the keys",
            "realm_signing_keys",
            &decision,
        ),
        (
            "the decision point asking after a withdrawal",
            "realms",
            &decision,
        ),
        (
            "the account API asking after a withdrawal",
            "realms",
            &account,
        ),
    ];
    for (door, table, request) in cases {
        let plane = Plane::with_actions(&[]).await;
        deny(&format!("REVOKE SELECT ON {table} FROM saffui_app")).await;
        let bearer = plane.token(&support::claims());
        let (status, body, _) = asked(&plane, request(&bearer)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{door}: {body}");
        assert_eq!(body["error_code"], "internal_error", "{door}: {body}");
    }

    // What was a missing token stays one: a realm nobody holds while the keys
    // cannot be read, and a signature that does not check out.
    let plane = Plane::with_actions(&[]).await;
    deny("REVOKE SELECT ON realm_signing_keys FROM saffui_app").await;
    let mut elsewhere = support::claims();
    elsewhere.set_issuer(support::origin().issuer("nowhere"));
    let (status, _, _) = asked(&plane, admin(&plane.token(&elsewhere))).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unknown realm was told apart"
    );

    // A plane holds the database until it is dropped, and shadowing drops nothing.
    drop(plane);
    let plane = Plane::with_actions(&[]).await;
    let mut forged = plane.token(&support::claims());
    let last = forged.pop().expect("a signature");
    forged.push(if last == 'A' { 'B' } else { 'A' });
    for request in [admin(&forged), decision(&forged), account(&forged)] {
        let (status, body, _) = asked(&plane, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
}
