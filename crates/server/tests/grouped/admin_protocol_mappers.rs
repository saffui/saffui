#[allow(unused_imports)]
use super::support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use super::support::{Plane, REDIRECT};

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> Mounted {
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
        sealing: support::sealing(),
    }
}

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

/// Spend a freshly minted code at the token endpoint.
async fn exchanged(plane: &Plane, scope: &str) -> Value {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, scope, None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
        .set_form([
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
        ])
        .insert_header(("authorization", format!("Basic {encoded}")));
    let response = test::call_service(&app, request.to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    test::read_body_json(response).await
}

/// What the userinfo endpoint says to this bearer.
async fn told_of(plane: &Plane, access: &str) -> Value {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let request = test::TestRequest::get()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/userinfo"))
        .insert_header(("authorization", format!("Bearer {access}")));
    let response = test::call_service(&app, request.to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    test::read_body_json(response).await
}

/// Give the planted person an attribute for the mappers to read.
async fn planted_attribute(plane: &Plane, name: &str, value: &str) {
    use models::entities::attributes::AttributeValue;
    use store::tenancy::TenantContext;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let mut person = store::providers::users::load(&transaction, support::SUBJECT)
        .await
        .unwrap()
        .expect("the planted person");
    person
        .attributes
        .get_or_insert_with(Default::default)
        .insert(name.to_owned(), AttributeValue::Str(value.to_owned()));
    assert!(
        store::providers::users::update(&transaction, &person)
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

/// A rule configured over the plane reaches the tokens and the UserInfo
/// answer, exactly where its flags and its scope say, and nowhere else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mapper_shapes_what_the_realm_answers() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/protocol-mappers");
    planted_attribute(&plane, "department", "mines").await;

    // A rule this build does not run is refused, and the refusal names what
    // does run.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "invented", "mapper_type": "oidc-invented-elsewhere" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("oidc-usermodel-attribute-mapper"),
        "the refusal does not say what runs: {told}"
    );

    // A department claim on the client itself, everywhere but UserInfo.
    let (status, department) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "name": "department",
            "mapper_type": "oidc-usermodel-attribute-mapper",
            "configs": {
                "claim.name": { "Str": "department" },
                "user.attribute": { "Str": "department" },
                "userinfo.token.claim": { "Str": "false" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{department}");
    let department_id = department["mapper_id"].as_str().expect("an id").to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/clients/{}/mappers/{department_id}",
            support::CONFIDENTIAL
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    // An audience on the optional address scope: granted only when asked for.
    let (status, audience) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "name": "watcher",
            "mapper_type": "oidc-audience-mapper",
            "configs": { "included.custom.audience": { "Str": "resource-server" } },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{audience}");
    let audience_id = audience["mapper_id"].as_str().expect("an id").to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/client-scopes/address/mappers/{audience_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    // A grant that never asked for the address scope: the department claim
    // lands in both tokens, the audience does not, and UserInfo stays quiet
    // because the rule's own flag said so.
    let body = exchanged(&plane, "openid").await;
    let access = body["access_token"].as_str().expect("an access token");
    let claims = plane.claims_of(access).await;
    assert_eq!(claims["department"], "mines");
    assert_eq!(
        claims["aud"], "app",
        "an unasked optional scope widened aud"
    );
    let identity = plane
        .claims_of(body["id_token"].as_str().expect("an id token"))
        .await;
    assert_eq!(identity["department"], "mines");
    let answer = told_of(&plane, access).await;
    assert_eq!(answer["sub"], support::SUBJECT);
    assert!(
        answer.get("department").is_none(),
        "the rule's userinfo flag said no and was not heard: {answer}"
    );

    // The same grant with the address scope named: the audience mapper now
    // applies, and the token's audience is the union, never a replacement.
    let body = exchanged(&plane, "openid address").await;
    let access = body["access_token"].as_str().expect("an access token");
    let claims = plane.claims_of(access).await;
    let audiences = claims["aud"].as_array().expect("a widened audience");
    assert!(audiences.contains(&json!("app")), "{claims}");
    assert!(audiences.contains(&json!("resource-server")), "{claims}");

    // Held rules are not deleted; released ones are.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{department_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "directory.still_granted");
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!(
            "/admin/realms/{REALM}/clients/{}/mappers/{department_id}",
            support::CONFIDENTIAL
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{department_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // With its rule detached, the next grant stops carrying the claim: the
    // configuration is live, not a copy taken at some earlier time.
    let body = exchanged(&plane, "openid").await;
    let claims = plane
        .claims_of(body["access_token"].as_str().expect("an access token"))
        .await;
    assert!(
        claims.get("department").is_none(),
        "a detached rule kept shaping tokens: {claims}"
    );
}

/// Reading the rules does not grant writing them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_mapper_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/protocol-mappers");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "x", "mapper_type": "oidc-audience-mapper" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
