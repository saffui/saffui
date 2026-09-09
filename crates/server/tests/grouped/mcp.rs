//! The native MCP door: an agent obtains and attenuates its capability
//! tokens over JSON-RPC, under every gate the exchange already holds, and
//! the whole door answers to the realm's switch.

#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use serde_json::{Value, json};
use server::api::config::register;
use store::tenancy::TenantContext;

const REALM: &str = support::REALM;
const REDIRECT: &str = "https://app.example/callback";

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

/// One JSON-RPC call at the door, with or without a bearer.
async fn called(plane: &Plane, body: Value, bearer: Option<&str>) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut request = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/mcp"))
        .set_json(body);
    if let Some(token) = bearer {
        request = request.insert_header(("authorization", format!("Bearer {token}")));
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn rpc(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

/// The world an agent lives in: the client opted into exchanging, carrying
/// a capability root, and the realm's switch turned as asked.
async fn agent_world(plane: &Plane, switch_on: bool) {
    use models::entities::attributes::AttributeValue;
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
        .await
        .unwrap()
        .expect("the client");
    let bag = client.configs.get_or_insert_with(Default::default);
    bag.insert(
        "token.exchange.enabled".to_owned(),
        AttributeValue::Bool(true),
    );
    bag.insert(
        "agent.capabilities".to_owned(),
        AttributeValue::Str("github.create_issue saffui.user.*".to_owned()),
    );
    store::providers::clients::update(&transaction, &client)
        .await
        .unwrap();
    transaction
        .execute(
            "UPDATE realms SET agent_exchange_enabled = $1",
            &[&Some(switch_on)],
        )
        .await
        .expect("the switch turned");
    transaction.commit().await.expect("the world kept");
}

/// A subject token the agent client holds, the way a client gets one.
async fn subject_token(plane: &Plane) -> String {
    let code = plane
        .mint_code(support::CONFIDENTIAL, REDIRECT, "openid profile", None)
        .await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let encoded =
        BASE64.encode(format!("{}:{}", support::CONFIDENTIAL, support::CLIENT_SECRET).as_bytes());
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .insert_header(("authorization", format!("Basic {encoded}")))
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    body["access_token"].as_str().expect("a token").to_owned()
}

/// What a tool call answered, unwrapped: the JSON its text carries when it
/// ran, the words when it refused.
fn unwrapped(answer: &Value) -> (bool, Value) {
    let is_error = answer
        .pointer("/result/isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = answer
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    (
        is_error,
        serde_json::from_str(text).unwrap_or(Value::String(text.to_owned())),
    )
}

/// Off, every method answers the operator's own words at the handshake; on,
/// the door speaks MCP, mints, attenuates down and never up, keeps the act
/// chain growing, and cuts a delegation deeper than five links.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_mcp_door_mints_and_attenuates_under_the_realm_switch() {
    let plane = Plane::with_actions(&[]).await;
    agent_world(&plane, false).await;

    let (status, answer) = called(&plane, rpc("initialize", json!({})), None).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some("this realm does not mint capability tokens"),
        "{answer}"
    );

    agent_world(&plane, true).await;
    let (status, answer) = called(&plane, rpc("initialize", json!({})), None).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("saffui"),
        "{answer}"
    );

    let (_, listed) = called(&plane, rpc("tools/list", json!({})), None).await;
    let names: Vec<&str> = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("tools")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["capability.mint", "capability.attenuate"],
        "{listed}"
    );

    // No bearer, no tool: the transport says how to authenticate.
    let (status, _) = called(
        &plane,
        rpc(
            "tools/call",
            json!({ "name": "capability.mint", "arguments": { "capabilities": "saffui.user.read" } }),
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let subject = subject_token(&plane).await;
    let (status, answer) = called(
        &plane,
        rpc(
            "tools/call",
            json!({ "name": "capability.mint",
                    "arguments": { "capabilities": "saffui.user.read github.create_issue" } }),
        ),
        Some(&subject),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let (is_error, minted) = unwrapped(&answer);
    assert!(!is_error, "{answer}");
    let capability = minted["access_token"].as_str().expect("a token").to_owned();
    let claims = plane.claims_of(&capability).await;
    assert_eq!(
        claims["cap"],
        json!(["saffui.user.read", "github.create_issue"]),
        "{claims}"
    );
    assert_eq!(claims["act"]["sub"], support::CONFIDENTIAL, "{claims}");

    // Attenuation over MCP: narrower passes and the chain grows; wider is
    // one flat refusal though the registration would have allowed it.
    let (_, answer) = called(
        &plane,
        rpc(
            "tools/call",
            json!({ "name": "capability.attenuate",
                    "arguments": { "capabilities": "saffui.user.read" } }),
        ),
        Some(&capability),
    )
    .await;
    let (is_error, narrowed) = unwrapped(&answer);
    assert!(!is_error, "{answer}");
    let narrowed_token = narrowed["access_token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let narrowed_claims = plane.claims_of(&narrowed_token).await;
    assert_eq!(
        narrowed_claims["cap"],
        json!(["saffui.user.read"]),
        "{narrowed_claims}"
    );
    assert_eq!(
        narrowed_claims["act"]["act"]["sub"],
        support::CONFIDENTIAL,
        "the chain did not grow: {narrowed_claims}"
    );

    let (_, answer) = called(
        &plane,
        rpc(
            "tools/call",
            json!({ "name": "capability.attenuate",
                    "arguments": { "capabilities": "github.create_issue" } }),
        ),
        Some(&narrowed_token),
    )
    .await;
    let (is_error, said) = unwrapped(&answer);
    assert!(is_error, "{answer}");
    assert_eq!(
        said,
        Value::String("this client may not use this grant".to_owned())
    );

    // Five links stand; the sixth is a genealogy nobody audits.
    let mut walking = narrowed_token;
    let mut depth = 2;
    loop {
        let (_, answer) = called(
            &plane,
            rpc(
                "tools/call",
                json!({ "name": "capability.attenuate",
                        "arguments": { "capabilities": "saffui.user.read" } }),
            ),
            Some(&walking),
        )
        .await;
        let (is_error, next) = unwrapped(&answer);
        depth += 1;
        if depth <= 5 {
            assert!(!is_error, "link {depth} refused early: {answer}");
            walking = next["access_token"].as_str().expect("a token").to_owned();
        } else {
            assert!(is_error, "link {depth} was minted past the bound: {answer}");
            break;
        }
    }
}
