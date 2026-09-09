#![cfg(feature = "mesh")]

#[allow(unused_imports)]
use super::support;
use super::support::{AUDIENCE, PARTY, Plane, REALM, SCOPE, claims};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use server::grpc::wire::envoy::config::core::v3::header_value_option::HeaderAppendAction;
use server::grpc::wire::envoy::service::auth::v3::authorization_client::AuthorizationClient;
use server::grpc::wire::envoy::service::auth::v3::{
    AttributeContext, CheckRequest, attribute_context, check_response,
};
use server::middleware::admin_policy::AdminPolicy;
use std::collections::HashMap;
use store::tenancy::TenantContext;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![AUDIENCE.to_owned()],
            parties: vec![PARTY.to_owned()],
            scope: SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
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
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The door, on a loopback port of its own, and a client dialling it: the
/// bench speaks the protocol a proxy speaks and nothing shorter.
async fn opened(plane: &Plane) -> AuthorizationClient<tonic::transport::Channel> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let bind = listener.local_addr().expect("an address");
    tokio::spawn(server::grpc::serve(
        listener,
        server::grpc::Door {
            pool: plane.pool(),
            tenancy: plane.tenancy(),
            origin: support::origin(),
        },
    ));
    // The endpoint retries the connect, so the spawn above does not have to
    // be raced with a sleep.
    AuthorizationClient::connect(format!("http://{bind}"))
        .await
        .expect("the door answers")
}

/// One check, in the shape Envoy sends: everything about the request, and
/// nothing about what it means.
fn check(id: &str, method: &str, path: &str, headers: &[(&str, &str)]) -> CheckRequest {
    CheckRequest {
        attributes: Some(AttributeContext {
            source: None,
            destination: None,
            request: Some(attribute_context::Request {
                http: Some(attribute_context::HttpRequest {
                    id: id.to_owned(),
                    method: method.to_owned(),
                    headers: headers
                        .iter()
                        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                        .collect::<HashMap<_, _>>(),
                    path: path.to_owned(),
                    ..attribute_context::HttpRequest::default()
                }),
            }),
            context_extensions: HashMap::new(),
        }),
    }
}

/// The status the proxy is told to answer with, or nothing when the answer
/// permits.
fn denied(answer: &server::grpc::wire::envoy::service::auth::v3::CheckResponse) -> Option<i32> {
    match answer.http_response.as_ref() {
        Some(check_response::HttpResponse::DeniedResponse(held)) => {
            Some(held.status.as_ref().expect("a status").code)
        }
        _ => None,
    }
}

/// The headers the proxy is told to put on the request it forwards, with the
/// action it is told to use.
fn stated(
    answer: &server::grpc::wire::envoy::service::auth::v3::CheckResponse,
) -> Vec<(String, String, i32)> {
    match answer.http_response.as_ref() {
        Some(check_response::HttpResponse::OkResponse(held)) => held
            .headers
            .iter()
            .map(|option| {
                let header = option.header.as_ref().expect("a header");
                (
                    header.key.clone(),
                    header.value.clone(),
                    option.append_action,
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

async fn recorded(plane: &Plane, decision_id: &str) -> Option<(String, String)> {
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::authz_policies::recent(&transaction, 50)
        .await
        .unwrap()
        .into_iter()
        .find(|held| held.decision_id == decision_id)
        .map(|held| (held.resource_ref.unwrap_or_default(), held.action))
}

/// A proxy asks on every request it forwards, and this door answers it the
/// way the enforcement door answers: the realm from the token, the
/// permission from the map, the identity written by overwriting.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_mesh_door_answers_a_proxy_in_its_own_protocol() {
    let plane = Plane::with_actions(&[AdminAction::UmaRead, AdminAction::UmaWrite]).await;
    let admin = plane.token(&claims());
    let mut mine = claims();
    mine.set_audience(vec![support::CONFIDENTIAL]);
    let application = plane.token(&mine);

    // A permissive application, so the answer this bench reads is the
    // reported one: what the door acts on is what the caller is told, and
    // the two part company exactly here.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!(
            "/admin/realms/{REALM}/authz/servers/{}",
            support::CONFIDENTIAL
        ),
        &admin,
        Some(json!({ "enforcement_mode": "permissive", "decision_strategy": "unanimous" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // The route names the resource by the identifier the plane drew for it,
    // the way every grant in this house names what it points at.
    let (status, resource) = asked(
        &plane,
        Method::POST,
        &format!(
            "/admin/realms/{REALM}/authz/servers/{}/resources",
            support::CONFIDENTIAL
        ),
        &admin,
        Some(json!({
            "name": "orders",
            "display_name": "",
            "description": "",
            "resource_uris": ["/api/*"],
            "resource_type": "urn:app:orders",
            "resource_owner": "app",
            "user_managed_access": false,
            "configs": null,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{resource}");
    let orders = resource["resource_id"]
        .as_str()
        .expect("an identifier")
        .to_owned();

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/authz/routes/reads"),
        &admin,
        Some(
            json!({ "method": "GET", "path": "/api/*", "server_id": support::CONFIDENTIAL,
                     "resource": orders, "scope": "read", "action": "read" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let mut door = opened(&plane).await;
    let bearer = |token: &str| format!("Bearer {token}");

    // A request carrying nothing to go on is refused, and the proxy is told
    // which answer to give.
    let answer = door
        .check(check("no-token", "GET", "/api/orders", &[]))
        .await
        .expect("an answer")
        .into_inner();
    assert_eq!(denied(&answer), Some(401), "{answer:?}");

    // A path the realm has said nothing about is not an open one.
    let answer = door
        .check(check(
            "unmapped",
            "GET",
            "/health",
            &[("authorization", &bearer(&application))],
        ))
        .await
        .expect("an answer")
        .into_inner();
    assert_eq!(denied(&answer), Some(403), "{answer:?}");

    // A token minted for another application is not this one's caller,
    // whatever the path says.
    let answer = door
        .check(check(
            "elsewhere",
            "GET",
            "/api/orders",
            &[("authorization", &bearer(&admin))],
        ))
        .await
        .expect("an answer")
        .into_inner();
    assert_eq!(denied(&answer), Some(403), "{answer:?}");

    // The permitted request: the identity the upstream will read is written
    // here, by overwriting, so one the caller sent itself cannot survive
    // beside it.
    let answer = door
        .check(check(
            "allowed",
            "GET",
            "/api/orders",
            &[
                ("authorization", &bearer(&application)),
                ("x-saffui-subject", "somebody-else"),
            ],
        ))
        .await
        .expect("an answer")
        .into_inner();
    assert_eq!(denied(&answer), None, "{answer:?}");
    assert_eq!(answer.status.as_ref().expect("a status").code, 0);
    let written = stated(&answer);
    assert!(
        written.contains(&(
            "x-saffui-subject".to_owned(),
            support::SUBJECT.to_owned(),
            HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        )),
        "the subject header is not overwritten: {written:?}"
    );
    assert!(
        written
            .iter()
            .any(|(key, value, action)| key == "x-saffui-decision-id"
                && value == "mesh-allowed"
                && *action == HeaderAppendAction::OverwriteIfExistsOrAdd as i32),
        "{written:?}"
    );

    // And the decision is in the journal under the map's words, which is
    // what says the route map answered and not the caller.
    assert_eq!(
        recorded(&plane, "mesh-allowed").await,
        Some((format!("{orders}#read"), "read".to_owned()))
    );
    assert!(
        recorded(&plane, "mesh-unmapped").await.is_none(),
        "an unmapped path consulted a rule"
    );
}
