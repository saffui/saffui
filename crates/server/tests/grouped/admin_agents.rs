//! The agents door: registered keyless and whole, the root refused at the
//! door in words, and one cut that kills every token already minted.

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
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
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        request = request.set_json(body);
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// Registered whole: the client confidential and keyless, the root held,
/// the service account born and linked; a second registration refuses; a
/// malformed root refuses at the door, in words, and stores nothing.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_agent_is_born_whole_and_keyless_or_not_at_all() {
    use models::entities::authz::AdminAction;
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, born) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/agents"),
        &bearer,
        Some(json!({
            "client_id": "scribe-1",
            "capabilities": ["github.create_issue", "saffui.user.*", "github.create_issue"],
            "session_seconds": 900,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(
        born["keyed"], false,
        "a secret exists where none was asked: {born}"
    );
    assert_eq!(
        born["capabilities"],
        json!(["github.create_issue", "saffui.user.*"]),
        "{born}"
    );

    {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let account = store::providers::users::load_service_account(&transaction, "scribe-1")
            .await
            .unwrap()
            .expect("the service account was born with the agent");
        assert!(account.enabled);
        let client = store::providers::clients::load(&transaction, "scribe-1")
            .await
            .unwrap()
            .expect("the client");
        assert_eq!(client.public_client, Some(false));
        assert_eq!(client.service_account_enabled, Some(true));
        assert!(
            client.secret.is_none(),
            "keyless means no stored credential"
        );
    }

    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/agents"),
        &bearer,
        Some(json!({ "client_id": "scribe-1", "capabilities": ["a.b"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    for (root, said) in [
        (json!(["sp ace"]), "carries no whitespace"),
        (json!(["a.*b"]), "stands only at the end"),
        (json!(["*"]), "grants everything"),
        (json!([]), "names at least one capability"),
    ] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/agents"),
            &bearer,
            Some(json!({ "client_id": "scribe-bad", "capabilities": root })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told["message"].as_str().unwrap_or_default().contains(said)
                || told["detail"].as_str().unwrap_or_default().contains(said),
            "not the door's words for {said}: {told}"
        );
    }
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/agents/scribe-bad"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a refused registration left a trace"
    );

    // Reshape: grant and ungrant one by one; emptying the root refuses in
    // words and changes nothing.
    let (status, held) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/agents/scribe-1"),
        &bearer,
        Some(json!({ "add": ["search.read"], "remove": ["saffui.user.*"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(
        held["capabilities"],
        json!(["github.create_issue", "search.read"]),
        "{held}"
    );
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/agents/scribe-1"),
        &bearer,
        Some(json!({ "remove": ["github.create_issue", "search.read"] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (_, still) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/agents/scribe-1"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        still["capabilities"], held["capabilities"],
        "the refusal wrote anyway"
    );

    // The operator keys the agent deliberately through the rotation door.
    // The rotation stores a hash the client model never surfaces, so this
    // is exactly the shape in which `keyed` once lied.
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/clients/scribe-1/secret"),
        &bearer,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the rotation door refused");
    let (_, keyed) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/agents/scribe-1"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        keyed["keyed"],
        json!(true),
        "the deliberate keying is not visible on the agent: {keyed}"
    );
}

/// The security walk the phase promises: a registered agent mints over MCP
/// with nothing but its platform-shaped token, the operator cuts it with
/// not_before, and the capability token already in the agent's hands dies
/// everywhere at once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_revoked_agents_tokens_die_everywhere_at_once() {
    use crypto::jose::jwt::JwtPayload;
    use models::entities::authz::AdminAction;
    use std::time::{Duration, SystemTime};

    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let (status, _) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/agents"),
        &bearer,
        Some(json!({ "client_id": "scribe-2", "capabilities": ["saffui.user.*"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let account = {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        transaction
            .execute("UPDATE realms SET agent_exchange_enabled = TRUE", &[])
            .await
            .expect("the switch turned");
        let account = store::providers::users::load_service_account(&transaction, "scribe-2")
            .await
            .unwrap()
            .expect("the account");
        transaction.commit().await.expect("kept");
        account
    };

    // The token its platform would leave it holding: the realm's own
    // signature, the agent in azp, the service account as the subject.
    let platform_shaped = {
        let mut payload = JwtPayload::new();
        payload.set_issuer(support::origin().issuer(REALM));
        payload.set_subject(&account.user_id);
        payload.set_audience(vec!["scribe-2"]);
        payload
            .set_claim("azp", Some(json!("scribe-2")))
            .expect("azp");
        payload
            .set_claim("typ", Some(json!("Bearer")))
            .expect("typ");
        payload
            .set_claim("scope", Some(json!("openid")))
            .expect("scope");
        payload.set_expires_at(&(SystemTime::now() + Duration::from_secs(600)));
        plane.token(&payload)
    };

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let minted = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/mcp"))
            .insert_header(("authorization", format!("Bearer {platform_shaped}")))
            .set_json(json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "capability.mint",
                            "arguments": { "capabilities": "saffui.user.read" } },
            }))
            .to_request(),
    )
    .await;
    assert_eq!(minted.status(), StatusCode::OK);
    let answer: Value = test::read_body_json(minted).await;
    let text = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .expect("a tool answer");
    assert_eq!(
        answer.pointer("/result/isError"),
        Some(&json!(false)),
        "{answer}"
    );
    let capability: Value = serde_json::from_str(text).expect("the mint");
    let capability = capability["access_token"]
        .as_str()
        .expect("a token")
        .to_owned();

    // The cut, through the client door the CLI's revoke turns.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/clients/scribe-2"),
        &bearer,
        Some(json!({ "not_before": chrono::Utc::now().timestamp() + 2 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Everywhere at once: the introspection says dead, and the MCP door
    // will not attenuate it.
    let introspected = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/introspect"
            ))
            .insert_header((
                "authorization",
                format!(
                    "Basic {}",
                    data_encoding::BASE64.encode(
                        format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes()
                    )
                ),
            ))
            .set_form([("token", capability.as_str())])
            .to_request(),
    )
    .await;
    let told: Value = test::read_body_json(introspected).await;
    assert_eq!(
        told["active"], false,
        "the cut did not reach introspection: {told}"
    );

    let attenuated = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/mcp"))
            .insert_header(("authorization", format!("Bearer {capability}")))
            .set_json(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "capability.attenuate",
                            "arguments": { "capabilities": "saffui.user.read" } },
            }))
            .to_request(),
    )
    .await;
    assert_eq!(
        attenuated.status(),
        StatusCode::UNAUTHORIZED,
        "a cut token still opened the MCP door"
    );
}
