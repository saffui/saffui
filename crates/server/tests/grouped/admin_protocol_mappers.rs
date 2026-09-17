#[allow(unused_imports)]
use super::support;
use super::support::{Plane, REDIRECT};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use data_encoding::BASE64;
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};

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
        ceiling: support::ceiling(),
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

    // A rule that runs, configured with a key it never reads, or missing one
    // it cannot work without. Neither is caught anywhere downstream: an
    // unreadable key is simply never looked at, so the row would sit in the
    // store reading as configured while writing nothing.
    for (what, body, says) in [
        (
            "a key belonging to another rule",
            json!({
                "name": "strayed",
                "mapper_type": "oidc-usermodel-attribute-mapper",
                "configs": {
                    "claim.name": { "Str": "dept" },
                    "user.attribute": { "Str": "dept" },
                    "included.custom.audience": { "Str": "elsewhere" },
                },
            }),
            "included.custom.audience",
        ),
        (
            "a rule missing the key it reads its value from",
            json!({
                "name": "halfway",
                "mapper_type": "oidc-usermodel-attribute-mapper",
                "configs": { "claim.name": { "Str": "dept" } },
            }),
            "user.attribute",
        ),
        (
            // The one every other rule takes: a client role rule reads no
            // configuration at all, its claim path being fixed.
            "a claim name on the rule whose path is fixed",
            json!({
                "name": "renamed",
                "mapper_type": "oidc-usermodel-client-role-mapper",
                "configs": { "claim.name": { "Str": "roles" } },
            }),
            "claim.name",
        ),
        (
            "an audience rule naming neither spelling",
            json!({ "name": "nowhere", "mapper_type": "oidc-audience-mapper" }),
            "included.client.audience",
        ),
    ] {
        let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(body)).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what} was taken: {told}"
        );
        assert!(
            told["message"].as_str().unwrap_or_default().contains(says),
            "the refusal of {what} does not name {says}: {told}"
        );
    }

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

    // The same weighing on the way in as on the way back: a rule already
    // written cannot be edited into one that reads a key it never consults.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/protocol-mappers/{department_id}"),
        &bearer,
        Some(json!({
            "name": "department",
            "mapper_type": "oidc-usermodel-attribute-mapper",
            "configs": {
                "claim.name": { "Str": "department" },
                "user.attribute": { "Str": "department" },
                "included.client.audience": { "Str": "elsewhere" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .unwrap_or_default()
            .contains("included.client.audience"),
        "the refusal on update does not name the stray key: {told}"
    );
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

/// Rules and scopes are kept per protocol. One of another protocol held by an
/// OpenID Connect client shapes none of its tokens or answers: neither a rule
/// attached to the client, nor the rule a scope of that protocol carries.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_rule_or_a_scope_of_another_protocol_shapes_no_openid_grant() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/protocol-mappers");
    planted_attribute(&plane, "department", "mines").await;

    // A department rule of the docker protocol, held by the client itself.
    let (status, docker_rule) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "name": "docker-department",
            "protocol": "docker",
            "mapper_type": "oidc-usermodel-attribute-mapper",
            "configs": {
                "claim.name": { "Str": "department" },
                "user.attribute": { "Str": "department" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{docker_rule}");
    let docker_rule_id = docker_rule["mapper_id"].as_str().expect("an id").to_owned();

    // A division rule of OpenID Connect, carried by a docker scope the client
    // holds as required.
    let (status, registry) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/client-scopes"),
        &bearer,
        Some(json!({ "name": "registry", "protocol": "docker" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registry}");
    let registry_id = registry["client_scope_id"]
        .as_str()
        .expect("an id")
        .to_owned();
    let (status, division_rule) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "name": "division",
            "mapper_type": "oidc-usermodel-attribute-mapper",
            "configs": {
                "claim.name": { "Str": "division" },
                "user.attribute": { "Str": "department" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{division_rule}");
    let division_rule_id = division_rule["mapper_id"]
        .as_str()
        .expect("an id")
        .to_owned();

    for held in [
        format!(
            "/admin/realms/{REALM}/clients/{}/mappers/{docker_rule_id}",
            support::CONFIDENTIAL
        ),
        format!("/admin/realms/{REALM}/client-scopes/{registry_id}/mappers/{division_rule_id}"),
        format!(
            "/admin/realms/{REALM}/clients/{}/scopes/{registry_id}",
            support::CONFIDENTIAL
        ),
    ] {
        let (status, told) = asked(&plane, Method::PUT, &held, &bearer, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{held}: {told}");
    }

    // Even named by the grant, nothing of the docker protocol shapes it.
    let body = exchanged(&plane, "openid registry").await;
    let access = body["access_token"].as_str().expect("an access token");
    let claims = plane.claims_of(access).await;
    assert!(
        claims.get("department").is_none(),
        "a docker rule shaped the access token: {claims}"
    );
    assert!(
        claims.get("division").is_none(),
        "the rule of a docker scope shaped the access token: {claims}"
    );
    let identity = plane
        .claims_of(body["id_token"].as_str().expect("an id token"))
        .await;
    assert!(
        identity.get("department").is_none() && identity.get("division").is_none(),
        "{identity}"
    );
    let answer = told_of(&plane, access).await;
    assert!(
        answer.get("department").is_none() && answer.get("division").is_none(),
        "{answer}"
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

/// The preview says who would write what, without minting anything: each
/// claim beside the mapper that authors it and the token it lands in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_preview_names_each_claims_author() {
    let plane = Plane::with_actions(&[
        AdminAction::ClientRead,
        AdminAction::ClientWrite,
        AdminAction::UserRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    planted_attribute(&plane, "department", "engineering").await;

    let (status, made) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/protocol-mappers"),
        &bearer,
        Some(json!({
            "name": "department",
            "mapper_type": "oidc-usermodel-attribute-mapper",
            "configs": {
                "claim.name": { "Str": "department" },
                "user.attribute": { "Str": "department" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let mapper_id = made["mapper_id"].as_str().expect("an id").to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/clients/{}/mappers/{mapper_id}",
            support::CONFIDENTIAL
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");

    let (status, previewed) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/preview-token"),
        &bearer,
        Some(json!({
            "user_id": support::SUBJECT,
            "client_id": support::CONFIDENTIAL,
            "scope": "openid",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{previewed}");

    // The body is what issuance would write, not the mapper's part of it: a
    // preview showing only the registered rules would read as a token missing
    // everything that makes it one.
    let body = &previewed["access"]["body"];
    assert_eq!(body["department"], "engineering", "{previewed}");
    for named in ["iss", "sub", "aud", "azp", "scope", "iat", "nbf", "exp", "typ"] {
        assert!(
            !body[named].is_null(),
            "the assembly's own {named} is missing: {previewed}"
        );
    }
    assert_eq!(body["typ"], "Bearer", "{previewed}");
    assert_eq!(previewed["access"]["header"]["typ"], "at+jwt", "{previewed}");
    assert!(
        previewed["access"]["header"]["kid"].is_string(),
        "the header names no key: {previewed}"
    );

    // The scope asked for openid, so the identity token is shown beside it,
    // and it is a different token: an identity token states no typ and no
    // scope, which is what tells a relying party the two are not the same.
    let identity = &previewed["identity"]["body"];
    assert_eq!(identity["department"], "engineering", "{previewed}");
    assert!(identity["typ"].is_null(), "{previewed}");
    assert!(identity["scope"].is_null(), "{previewed}");

    assert_eq!(previewed["authors"]["department"], "department", "{previewed}");

    // Nothing signed leaves this door. A preview that answered with a compact
    // token would hand a usable credential for any person named to whoever may
    // read a client, so the absence is weighed rather than assumed.
    let whole = previewed.to_string();
    assert!(
        !whole.contains("eyJ"),
        "something signed came back from a preview: {previewed}"
    );
}

/// A scope that never asked for openid gets no identity token, exactly as a
/// real grant would decide. Showing one would promise a token this exchange
/// would not produce.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_preview_without_openid_shows_no_identity_token() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());
    let (status, previewed) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/preview-token"),
        &bearer,
        Some(json!({
            "user_id": support::SUBJECT,
            "client_id": support::CONFIDENTIAL,
            "scope": "profile",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{previewed}");
    assert!(previewed["identity"].is_null(), "{previewed}");
    assert_eq!(previewed["access"]["body"]["scope"], "profile", "{previewed}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn token_preview_accepts_the_exact_username_and_user_id() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());
    plane.rename_subject("ada-renamed").await;
    for named in [support::SUBJECT, "ada-renamed"] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/preview-token"),
            &bearer,
            Some(json!({
                "user_id": named,
                "client_id": support::CONFIDENTIAL,
                "scope": "openid",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{named}: {told}");
    }
}

/// The three rules this build learned, and the door that says what each one
/// reads.
///
/// That door is a contract rather than a convenience: a console builds a rule's
/// fields from it, so a table that drifted from the rules would offer fields
/// nothing reads and hide the keys that matter.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_new_rules_are_written_and_the_door_says_what_they_read() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/protocol-mappers");

    let (status, kinds) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/mapper-kinds"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{kinds}");
    let named: Vec<&str> = kinds["kinds"]
        .as_array()
        .expect("kinds")
        .iter()
        .map(|kind| kind["mapper_type"].as_str().unwrap_or_default())
        .collect();
    for kind in [
        "oidc-hardcoded-claim-mapper",
        "oidc-usermodel-group-mapper",
        "oidc-usermodel-organization-mapper",
    ] {
        assert!(named.contains(&kind), "{kind} is not offered: {kinds}");
    }
    let hardcoded = kinds["kinds"]
        .as_array()
        .expect("kinds")
        .iter()
        .find(|kind| kind["mapper_type"] == "oidc-hardcoded-claim-mapper")
        .expect("the hardcoded rule");
    assert_eq!(
        hardcoded["required"],
        serde_json::json!(["claim.name", "claim.value"]),
        "the door does not say what a hardcoded rule cannot work without: {kinds}"
    );
    assert!(
        kinds["target_flags"]
            .as_array()
            .expect("flags")
            .contains(&serde_json::json!({ "key": "id.token.claim", "resting": true })),
        "the flags every rule reads are not named with what their absence means: {kinds}"
    );
    // A switch's resting value is not the same everywhere, and a screen that
    // guessed one for all of them would show a rule as multivalued when the
    // evaluator reads it as single.
    let attribute = kinds["kinds"]
        .as_array()
        .expect("kinds")
        .iter()
        .find(|kind| kind["mapper_type"] == "oidc-usermodel-attribute-mapper")
        .expect("the attribute rule");
    assert_eq!(
        attribute["booleans"],
        serde_json::json!([{ "key": "multivalued", "resting": false }]),
        "the door does not say that multivalued is a switch resting at one value: {kinds}"
    );
    assert_eq!(
        hardcoded["booleans"],
        serde_json::json!([]),
        "a rule with no switch of its own claims one: {kinds}"
    );

    // Written with what each reads, and nothing else.
    for (name, body) in [
        (
            "tier",
            json!({
                "name": "tier",
                "mapper_type": "oidc-hardcoded-claim-mapper",
                "configs": { "claim.name": { "Str": "tier" }, "claim.value": { "Str": "gold" } },
            }),
        ),
        (
            "groups",
            json!({ "name": "groups", "mapper_type": "oidc-usermodel-group-mapper" }),
        ),
        (
            "orgs",
            json!({
                "name": "orgs",
                "mapper_type": "oidc-usermodel-organization-mapper",
                "configs": { "claim.name": { "Str": "orgs" } },
            }),
        ),
    ] {
        let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(body)).await;
        assert_eq!(status, StatusCode::CREATED, "{name} was refused: {told}");
    }

    // And refused where the configuration says something the rule never reads,
    // or lacks what it cannot work without.
    for (what, body, says) in [
        (
            "a hardcoded rule with nothing to write",
            json!({
                "name": "empty",
                "mapper_type": "oidc-hardcoded-claim-mapper",
                "configs": { "claim.name": { "Str": "tier" } },
            }),
            "claim.value",
        ),
        (
            "a group rule carrying a key of another",
            json!({
                "name": "strayed",
                "mapper_type": "oidc-usermodel-group-mapper",
                "configs": { "user.attribute": { "Str": "department" } },
            }),
            "user.attribute",
        ),
    ] {
        let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(body)).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what} was taken: {told}"
        );
        assert!(
            told["message"].as_str().unwrap_or_default().contains(says),
            "the refusal of {what} does not name {says}: {told}"
        );
    }
}
