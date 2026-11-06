use actix_web::http::header::{AUTHORIZATION, CONTENT_TYPE};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test, web};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::authz::capability::Capability;
use saffui_core::testkit::fixtures::{
    CodeFlow, create_administrator, create_application, create_person, create_realm,
    create_service_client, run_code_flow,
};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::{Value, json};
use server::api::config::register_data_plane;

use super::admin::call;

const SCHEMA: &str = "definition user {}
definition team {
  relation member: user
}
definition document {
  relation owner: user
  relation reader: user | team#member
  permission read = reader + owner
}";

struct Started {
    product: saffui_core::app::App,
    /// A token of `operator`, granted to write policies and relations.
    operator: String,
    /// What `billing` presents in the Basic scheme.
    billing: String,
    /// The access token `portal` holds for `ada`.
    subject_token: String,
    ada: String,
}

async fn start() -> Started {
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    let ada = create_person(&product, scope, "ada", "correct horse battery").await;
    create_application(
        &product,
        scope,
        "portal",
        "https://app.example.test/cb",
        true,
    )
    .await;
    let secret = create_service_client(&product, scope, "billing", &[]).await;
    let operator = create_administrator(
        &product,
        "acme",
        scope,
        "operator",
        &[Capability::PolicyRead, Capability::PolicyWrite],
    )
    .await;
    let flow = CodeFlow {
        realm: "acme",
        client_id: "portal",
        client_secret: None,
        redirect_uri: "https://app.example.test/cb",
        scope: "openid",
        username: "ada",
        password: "correct horse battery",
    };
    let subject_token = run_code_flow(&product, flow).await.tokens.access_token;
    let billing = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "billing:{}",
            String::from_utf8(secret.expose().to_vec()).expect("a secret in text")
        ))
    );
    Started {
        product,
        operator,
        billing,
        subject_token,
        ada: ada.id.to_string(),
    }
}

impl Started {
    async fn admin(&self, method: Method, path: &str, body: Option<&Value>) -> (StatusCode, Value) {
        let body = body.map(Value::to_string);
        let answer = call(
            &self.product,
            method,
            path,
            Some(&self.operator),
            body.as_deref(),
        )
        .await;
        (answer.status, answer.body)
    }

    async fn ask(&self, authorization: Option<&str>, question: &Value) -> (StatusCode, Value) {
        let app = test::init_service(
            App::new().configure(register_data_plane(web::Data::new(self.product.clone()))),
        )
        .await;
        let mut request = test::TestRequest::default()
            .method(Method::POST)
            .uri("/realms/acme/authz/decide")
            .insert_header((CONTENT_TYPE, "application/json"))
            .set_payload(question.to_string());
        if let Some(authorization) = authorization {
            request = request.insert_header((AUTHORIZATION, authorization.to_owned()));
        }
        let response = test::call_service(&app, request.to_request()).await;
        let status = response.status();
        let cache = response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = test::read_body(response).await;
        if status == StatusCode::OK {
            assert_eq!(cache.as_deref(), Some("no-store"));
        }
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

#[actix_web::test]
async fn a_schema_with_faults_is_refused_with_each_fault_at_its_line() {
    let started = start().await;
    let path = "/admin/v1/realms/acme/relations/schema";

    let (status, body) = started.admin(Method::GET, path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let faulty = json!({ "source": "definition user {}\ndefinition doc {\n  relation owner: robot\n  permission read = owner + share\n}" });
    let (status, body) = started.admin(Method::PUT, path, Some(&faulty)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "authz.relation_schema_invalid");
    assert_eq!(
        body["faults"],
        json!([
            { "line": 3, "message": "no type is named `robot`" },
            { "line": 4, "message": "`doc` has no member `share`" },
        ])
    );

    let (status, body) = started
        .admin(Method::PUT, path, Some(&json!({ "source": SCHEMA })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["types"], json!(["document", "team", "user"]));
    assert_eq!(body["relations_removed"], 0);
    let (status, body) = started.admin(Method::GET, path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["source"], SCHEMA);
}

#[actix_web::test]
async fn a_schema_at_its_bound_is_read_whole_and_one_past_it_is_told_its_fault() {
    use saffui_core::authz::relations::schema::SCHEMA_MAX_BYTES;

    let started = start().await;
    let path = "/admin/v1/realms/acme/relations/schema";
    let put = |body: String| {
        let started = &started;
        async move {
            call(
                &started.product,
                Method::PUT,
                path,
                Some(&started.operator),
                Some(&body),
            )
            .await
        }
    };
    // A source at its bound, each byte of it sent as an escape of six bytes,
    // as an encoder that escapes for HTML sends `&`, `+` or `=`.
    let head = "definition user {}\n//";
    let at_bound = format!("{head}{}", "x".repeat(SCHEMA_MAX_BYTES - head.len()));
    let escaped = at_bound
        .bytes()
        .map(|byte| format!("\\u{byte:04x}"))
        .collect::<Vec<_>>()
        .concat();
    let body = format!(r#"{{"source":"{escaped}"}}"#);
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("a body that reads")["source"],
        at_bound
    );
    assert!(
        body.len() > 5 * SCHEMA_MAX_BYTES + 1024,
        "five bytes for each byte of the source would not hold it"
    );

    let answer = put(body.clone()).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.body["types"], json!(["user"]));
    // The limit of the route, reached with blanks after the object, and passed.
    let limit = 6 * SCHEMA_MAX_BYTES + 1024;
    let padded = |length: usize| format!("{body}{}", " ".repeat(length - body.len()));
    let answer = put(padded(limit)).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let answer = put(padded(limit + 1)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        answer.body["code"], "platform.request_invalid",
        "a body past what a schema at its bound needs is not read"
    );

    let past = format!("{head}{}", "x".repeat(SCHEMA_MAX_BYTES + 1 - head.len()));
    let (status, answer) = started
        .admin(Method::PUT, path, Some(&json!({ "source": past })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        answer["faults"],
        json!([{ "line": 1, "message": format!("a schema is at most {SCHEMA_MAX_BYTES} bytes") }]),
        "{answer}"
    );
}

#[actix_web::test]
async fn a_schema_of_thousands_of_faults_is_told_the_first_ones_in_a_bounded_body() {
    use saffui_core::authz::relations::schema::{MAX_FAULTS_SHOWN, SCHEMA_MAX_BYTES};

    let started = start().await;
    let (head, tail) = ("definition doc {\n permission p = z", "\n}");
    let terms = (SCHEMA_MAX_BYTES - head.len() - tail.len()) / 2 + 1;
    let source = format!("{head}{}{tail}", "+z".repeat(terms - 1));

    let (status, answer) = started
        .admin(
            Method::PUT,
            "/admin/v1/realms/acme/relations/schema",
            Some(&json!({ "source": source })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        answer["faults"].as_array().map(Vec::len),
        Some(MAX_FAULTS_SHOWN)
    );
    assert_eq!(
        answer["faults"][0],
        json!({ "line": 2, "message": "`doc` has no member `z`" })
    );
    assert_eq!(answer["faults_not_shown"], terms - MAX_FAULTS_SHOWN);
    let written = answer.to_string().len();
    assert!(written < 16 * 1024, "the answer takes {written} bytes");
}

#[actix_web::test]
async fn relations_are_written_listed_and_deleted_as_the_schema_admits_them() {
    let started = start().await;
    started
        .admin(
            Method::PUT,
            "/admin/v1/realms/acme/relations/schema",
            Some(&json!({ "source": SCHEMA })),
        )
        .await;
    let relation =
        |subject: &str| format!("/admin/v1/realms/acme/relations/document:q3/reader/{subject}");

    let (status, _) = started
        .admin(Method::PUT, &relation("team:core%23member"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = started
        .admin(Method::PUT, &relation("user:ada"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = started
        .admin(Method::PUT, &relation("robot:r2"), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "authz.relation_invalid");
    let (status, _) = started
        .admin(Method::PUT, &relation("team:core"), None)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the relation admits the members of a team, not the team"
    );

    let (status, body) = started
        .admin(
            Method::GET,
            "/admin/v1/realms/acme/relations/document:q3/reader",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!(["team:core#member", "user:ada"]));
    assert_eq!(body["cut"], false);
    let (status, _) = started
        .admin(Method::DELETE, &relation("user:ada"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = started
        .admin(Method::DELETE, &relation("user:ada"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn a_client_asks_the_point_of_decision_about_the_subject_of_a_token() {
    let started = start().await;
    started
        .admin(
            Method::PUT,
            "/admin/v1/realms/acme/relations/schema",
            Some(&json!({ "source": SCHEMA })),
        )
        .await;
    let owned = format!(
        "/admin/v1/realms/acme/relations/document:q3/owner/user:{}",
        started.ada
    );
    let (status, _) = started.admin(Method::PUT, &owned, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let guard = "/admin/v1/realms/acme/relations/types/document/guards/billing";
    let (status, _) = started.admin(Method::PUT, guard, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let policy = json!({
        "name": "verified-readers",
        "resource_type": "receipt",
        "action": "read",
        "effect": "permit",
        "conditions": [{ "attribute": { "left": { "resource": "owner" }, "operator": "equals", "right": { "subject": "id" } } }],
    });
    let (status, body) = started
        .admin(
            Method::POST,
            "/admin/v1/realms/acme/clients/billing/policies",
            Some(&policy),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let question = |action: &str, resource: Value| json!({ "subject_token": started.subject_token, "action": action, "resource": resource });

    let (status, body) = started
        .ask(
            Some(&started.billing),
            &question("read", json!({ "type": "document", "id": "q3" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "decision": "permit", "reason": "relation" }));
    let (_, body) = started
        .ask(
            Some(&started.billing),
            &question("read", json!({ "type": "document", "id": "q4" })),
        )
        .await;
    assert_eq!(body["decision"], "deny");
    let mine = json!({ "type": "receipt", "attributes": { "owner": started.ada } });
    let (_, body) = started
        .ask(Some(&started.billing), &question("read", mine))
        .await;
    assert_eq!(
        body,
        json!({ "decision": "permit", "reason": "policy", "policy": "verified-readers" })
    );
    let theirs = json!({ "type": "receipt", "attributes": { "owner": "someone-else" } });
    let (_, body) = started
        .ask(Some(&started.billing), &question("read", theirs))
        .await;
    assert_eq!(body, json!({ "decision": "deny", "reason": "no_policy" }));

    let (status, body) = started
        .ask(
            None,
            &question("read", json!({ "type": "document", "id": "q3" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
    let (status, _) = started
        .ask(
            Some(&started.billing),
            &json!({ "subject_token": "t", "action": "read", "resource": { "type": "document" }, "client_secret": "x" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a secret is never read from a body"
    );

    // Without the scheme the body is not read; with it, a body that cannot
    // be read is refused in the dialect of the protocol.
    let unreadable = json!("not a question");
    let (status, body) = started.ask(None, &unreadable).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
    let (status, body) = started.ask(Some(&started.billing), &unreadable).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request", "{body}");
}

#[actix_web::test]
async fn a_policy_is_refused_when_it_cannot_be_read_and_listed_and_deleted_once_written() {
    let started = start().await;
    let policies = "/admin/v1/realms/acme/clients/billing/policies";
    let wanted = |effect: &str, conditions: Value| json!({ "name": "approvers", "resource_type": "invoice", "action": "approve", "effect": effect, "conditions": conditions });
    let present =
        json!([{ "attribute": { "left": { "resource": "amount" }, "operator": "present" } }]);

    let (status, body) = started
        .admin(
            Method::POST,
            policies,
            Some(&wanted("maybe", present.clone())),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "authz.policy_invalid");
    let (status, _) = started
        .admin(
            Method::POST,
            policies,
            Some(&wanted("permit", json!([{ "script": "x" }]))),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, created) = started
        .admin(Method::POST, policies, Some(&wanted("permit", present)))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["combine"], "all");
    let (status, listed) = started.admin(Method::GET, policies, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["items"], json!([created.clone()]));
    let one = format!(
        "{policies}/{}",
        created["id"].as_str().expect("an identifier")
    );
    let (status, _) = started.admin(Method::DELETE, &one, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = started.admin(Method::DELETE, &one, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = started
        .admin(
            Method::GET,
            "/admin/v1/realms/acme/clients/nobody/policies",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn an_administrator_names_the_clients_that_guard_a_type() {
    let started = start().await;
    let guards = "/admin/v1/realms/acme/relations/types/document/guards";

    let (status, _) = started
        .admin(Method::PUT, &format!("{guards}/billing"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = started
        .admin(Method::PUT, &format!("{guards}/nobody"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, body) = started.admin(Method::GET, guards, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!(["billing"]));
    let (status, _) = started
        .admin(Method::DELETE, &format!("{guards}/billing"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = started
        .admin(Method::DELETE, &format!("{guards}/billing"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
