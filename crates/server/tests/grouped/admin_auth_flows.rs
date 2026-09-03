#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    })))
    .await;
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

/// A flow is composed step by step over the plane, refuses what nothing
/// runs, and the one a login stands on cannot be deleted or emptied.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_flow_is_composed_and_guarded_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::AuthFlowRead, AdminAction::AuthFlowWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/auth/flows");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(
        told.as_array()
            .expect("a listing")
            .iter()
            .any(|flow| flow["alias"] == "browser"),
        "the provisioned flow is not listed: {told}"
    );

    // Born over the plane, and never as a built-in: that word is the
    // provisioner's, whatever the body claims.
    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "alias": "step-up",
            "provider_id": "basic-flow",
            "description": "a second look",
            "top_level": true,
            "built_in": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(
        born["built_in"], false,
        "a caller borrowed the provisioner's word"
    );
    let flow_id = born["flow_id"].as_str().expect("an identity").to_owned();

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "alias": "step-up", "provider_id": "basic-flow", "description": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // A step naming an authenticator nothing runs is refused, and the
    // refusal says what runs.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/{flow_id}/executions"),
        &bearer,
        Some(json!({
            "alias": "guess", "flow_id": "ignored", "priority": 10,
            "requirement": "required",
            "step": { "kind": "authenticator", "authenticator": "smoke-signal", "config_id": null },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("password, totp, webauthn, magic-link")),
        "the catalogue is not named: {told}"
    );

    // A nested step names a flow that exists, or nothing.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("{base}/{flow_id}/executions"),
        &bearer,
        Some(json!({
            "alias": "inner", "flow_id": "ignored", "priority": 20,
            "requirement": "required",
            "step": { "kind": "sub_flow", "flow_id": "nowhere" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Two real steps, then the second is reordered ahead and retired.
    let mut steps = Vec::new();
    for (alias, authenticator, priority) in [("first", "password", 10), ("second", "totp", 20)] {
        let (status, made) = asked(
            &plane,
            Method::POST,
            &format!("{base}/{flow_id}/executions"),
            &bearer,
            Some(json!({
                "alias": alias, "flow_id": "ignored", "priority": priority,
                "requirement": "required",
                "step": { "kind": "authenticator", "authenticator": authenticator, "config_id": null },
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        steps.push(
            made["execution_id"]
                .as_str()
                .expect("an identity")
                .to_owned(),
        );
    }
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{flow_id}/order"),
        &bearer,
        Some(json!({ "order": [
            { "execution_id": steps[1], "priority": 1 },
            { "execution_id": steps[0], "priority": 2 },
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{flow_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let ordered: Vec<&str> = told["executions"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|step| step["execution_id"].as_str().expect("an identity"))
        .collect();
    assert_eq!(ordered, vec![steps[1].as_str(), steps[0].as_str()]);

    // A move naming a step of another flow moves nothing at all.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{flow_id}/order"),
        &bearer,
        Some(json!({ "order": [ { "execution_id": "elsewhere", "priority": 3 } ] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/auth/executions/{}/requirement",
            steps[1]
        ),
        &bearer,
        Some(json!({ "requirement": "alternative" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/auth/executions/{}", steps[1]),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The realm's resting flow is refused deletion, and so is the last step
    // of it: a login has to keep something to run.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/browser"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    let (_, browser) = asked(
        &plane,
        Method::GET,
        &format!("{base}/browser"),
        &bearer,
        None,
    )
    .await;
    let last = browser["executions"][0]["execution_id"]
        .as_str()
        .expect("the provisioned step");
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{REALM}/auth/executions/{last}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("last step")),
        "{told}"
    );

    // A flow no login runs goes quietly, steps and all.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{flow_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{flow_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The registry says what a realm asks of people, the default flag reaches
/// the next person created, and a person can be asked one more thing or
/// released from it over the plane.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn required_actions_reach_the_next_person_and_no_further() {
    let plane = Plane::with_actions(&[
        AdminAction::RequiredActionRead,
        AdminAction::RequiredActionWrite,
        AdminAction::UserRead,
        AdminAction::UserWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/auth/required-actions");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told.as_array().expect("a listing").len(), 0);

    let (status, made) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "provider_id": "totp",
            "action": "configure-totp",
            "name": "configure-totp",
            "display_name": "Configure TOTP",
            "description": "",
            "default_action": true,
            "priority": 1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({
            "provider_id": "totp",
            "action": "configure-totp",
            "name": "again",
            "display_name": "Again",
            "description": "",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "auth.required_action.already_exists");

    // A registration answers for one action and does not become another's.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/configure-totp"),
        &bearer,
        Some(json!({
            "provider_id": "totp",
            "action": "verify-email",
            "name": "configure-totp",
            "display_name": "Configure TOTP",
            "description": "",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/configure-totp"),
        &bearer,
        Some(json!({
            "provider_id": "totp",
            "action": "configure-totp",
            "name": "configure-totp",
            "display_name": "Configure TOTP",
            "description": "asked of everyone new",
            "default_action": true,
            "priority": 1,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(
        told["metadata"]["version"].as_i64().unwrap_or(1) > 1,
        "the rewrite left no trace: {told}"
    );

    // An action spelled outside the catalogue is nobody's.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/interpretive-dance"),
        &bearer,
        Some(
            json!({ "provider_id": "x", "action": "verify-email", "name": "x",
                     "display_name": "x", "description": "" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The default reaches the next person created, unless the caller said
    // what to ask.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/users"),
        &bearer,
        Some(json!({ "user_name": "newcomer", "email": "new@acme.example" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (status, person) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/newcomer"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{person}");
    assert_eq!(
        person["required_actions"],
        json!(["configure-totp"]),
        "the registered default did not reach the newcomer"
    );

    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/users"),
        &bearer,
        Some(
            json!({ "user_name": "settled", "email": "settled@acme.example",
                     "required_actions": [] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, person) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/settled"),
        &bearer,
        None,
    )
    .await;
    assert!(
        person["required_actions"]
            .as_array()
            .is_none_or(|held| held.is_empty()),
        "a caller who said none was given the defaults anyway: {person}"
    );

    // One more thing asked of one person, then released. Asking twice asks
    // once; releasing what was never asked changes nothing.
    let held_by = format!("/admin/realms/{REALM}/users/newcomer/required-actions");
    for _ in 0..2 {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("{held_by}/verify-email"),
            &bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    }
    let (_, person) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/newcomer"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        person["required_actions"],
        json!(["configure-totp", "verify-email"])
    );
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{held_by}/verify-email"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{held_by}/verify-email"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/users/nobody/required-actions/verify-email"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "user.not_found");

    // Unregistered, the default stops at the next person.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/configure-totp"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/users"),
        &bearer,
        Some(json!({ "user_name": "later", "email": "later@acme.example" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, person) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/later"),
        &bearer,
        None,
    )
    .await;
    assert!(
        person["required_actions"]
            .as_array()
            .is_none_or(|held| held.is_empty()),
        "an unregistered default still reached the next person: {person}"
    );
}

/// Reading the flows does not grant rewriting them, and the two families
/// split from each other as well.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_flow_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::AuthFlowRead]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/auth/flows"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/auth/flows"),
        &bearer,
        Some(json!({ "alias": "x", "provider_id": "basic-flow", "description": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Watching flows does not grant reading the action registry.
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/auth/required-actions"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
