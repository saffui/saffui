use actix_web::http::{Method, StatusCode};
use saffui_core::authz::capability::Capability;
use serde_json::{Value, json};

use super::admin::{Answer, call, start};

const KEYS: &str = "/admin/v1/realms/acme/keys";

/// Whether a published key holds exactly the members of the public half of
/// its type: none that a private key carries, whatever its name.
fn holds_public_members_only(key: &serde_json::Value) -> bool {
    let expected: &[&str] = match key["kty"].as_str() {
        Some("RSA") => &["alg", "e", "kid", "kty", "n", "use"],
        Some("EC") => &["alg", "crv", "kid", "kty", "use", "x", "y"],
        Some("OKP") => &["alg", "crv", "kid", "kty", "use", "x"],
        _ => return false,
    };
    let mut names: Vec<&str> = key
        .as_object()
        .map(|members| members.keys().map(String::as_str).collect())
        .unwrap_or_default();
    names.sort_unstable();
    names == expected
}

struct Operator {
    product: saffui_core::app::App,
    token: String,
}

impl Operator {
    async fn open(capabilities: &[Capability]) -> Self {
        let (product, token) = start(capabilities).await;
        Self { product, token }
    }

    async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> Answer {
        let body = body.map(Value::to_string);
        call(
            &self.product,
            method,
            path,
            Some(&self.token),
            body.as_deref(),
        )
        .await
    }

    /// The status of each key of the realm, by its `kid`.
    async fn list_statuses(&self) -> Vec<(String, String, String)> {
        let listed = self.send(Method::GET, KEYS, None).await;
        assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
        listed.body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| {
                assert!(holds_public_members_only(&item["public_jwk"]), "{item}");
                let read = |name: &str| item[name].as_str().expect(name).to_owned();
                (read("kid"), read("alg"), read("status"))
            })
            .collect()
    }
}

#[actix_web::test]
async fn an_administrator_turns_a_key_over_then_removes_the_one_it_replaced() {
    let operator = Operator::open(&[Capability::KeyRead, Capability::KeyWrite]).await;
    let born = operator.list_statuses().await;
    let algorithms: Vec<(&str, &str)> = born
        .iter()
        .map(|(_, alg, status)| (alg.as_str(), status.as_str()))
        .collect();
    assert_eq!(algorithms, [("ES256", "active"), ("RS256", "active")]);
    // The RSA key: the ES256 one signed the token of the operator.
    let first = born[1].0.clone();

    let made = operator
        .send(Method::POST, KEYS, Some(&json!({ "alg": "RS256" })))
        .await;

    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    assert_eq!(made.body["alg"], "RS256");
    assert_eq!(made.body["status"], "active");
    assert!(
        holds_public_members_only(&made.body["public_jwk"]),
        "{}",
        made.body
    );
    let new = made.body["kid"].as_str().expect("a kid").to_owned();
    let listed = operator.list_statuses().await;
    assert!(listed.contains(&(first.clone(), "RS256".to_owned(), "retired".to_owned())));
    assert!(listed.contains(&(new.clone(), "RS256".to_owned(), "active".to_owned())));

    let kept = operator
        .send(Method::DELETE, &format!("{KEYS}/{new}"), None)
        .await;
    assert_eq!(kept.status, StatusCode::CONFLICT, "{}", kept.body);
    assert_eq!(kept.body["code"], "realm.key_still_active");
    let removed = operator
        .send(Method::DELETE, &format!("{KEYS}/{first}"), None)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{}", removed.body);
    let again = operator
        .send(Method::DELETE, &format!("{KEYS}/{first}"), None)
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{}", again.body);
    assert_eq!(again.body["code"], "realm.key_not_found");
    assert_eq!(operator.list_statuses().await.len(), 2);
}

#[actix_web::test]
async fn an_algorithm_that_is_not_served_is_refused_by_name() {
    let operator = Operator::open(&[Capability::KeyWrite, Capability::ClientWrite]).await;

    for wanted in [
        json!({ "alg": "HS256" }),
        json!({ "alg": "none" }),
        json!({ "alg": "es256" }),
    ] {
        let refused = operator.send(Method::POST, KEYS, Some(&wanted)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{wanted}");
        assert_eq!(refused.body["code"], "realm.algorithm_unknown", "{wanted}");
    }
    let unknown_field = operator
        .send(
            Method::POST,
            KEYS,
            Some(&json!({ "alg": "ES256", "status": "retired" })),
        )
        .await;
    assert_eq!(unknown_field.status, StatusCode::BAD_REQUEST);
    let client = operator
        .send(
            Method::POST,
            "/admin/v1/realms/acme/clients",
            Some(&json!({
                "client_id": "reader",
                "redirect_uris": ["https://app.example.test/callback"],
                "public": true,
                "id_token_signed_response_alg": "HS256",
            })),
        )
        .await;
    assert_eq!(client.status, StatusCode::BAD_REQUEST, "{}", client.body);
    assert_eq!(client.body["code"], "realm.algorithm_unknown");
}

#[actix_web::test]
async fn reading_and_turning_keys_over_are_two_capabilities() {
    let reader = Operator::open(&[Capability::KeyRead]).await;
    let writer = Operator::open(&[Capability::KeyWrite]).await;

    let turned = reader
        .send(Method::POST, KEYS, Some(&json!({ "alg": "ES256" })))
        .await;
    let removed = reader
        .send(Method::DELETE, &format!("{KEYS}/anything"), None)
        .await;
    let listed = writer.send(Method::GET, KEYS, None).await;

    for refused in [turned, removed, listed] {
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{}", refused.body);
        assert_eq!(refused.body["code"], "auth.capability_missing");
    }
}

#[actix_web::test]
async fn a_client_names_an_algorithm_once_the_realm_has_a_key_of_it_and_discovery_says_so() {
    let operator = Operator::open(&[Capability::KeyWrite, Capability::ClientWrite]).await;
    let reader = json!({
        "client_id": "reader",
        "redirect_uris": ["https://app.example.test/callback"],
        "scopes": ["openid"],
        "public": true,
        "id_token_signed_response_alg": "PS256",
    });
    let discover = async || {
        call(
            &operator.product,
            Method::GET,
            "/realms/acme/.well-known/openid-configuration",
            None,
            None,
        )
        .await
        .body["id_token_signing_alg_values_supported"]
            .clone()
    };
    assert_eq!(discover().await, json!(["ES256", "RS256"]));

    let refused = operator
        .send(Method::POST, "/admin/v1/realms/acme/clients", Some(&reader))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["code"], "realm.key_algorithm_unavailable");
    let made = operator
        .send(Method::POST, KEYS, Some(&json!({ "alg": "PS256" })))
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let created = operator
        .send(Method::POST, "/admin/v1/realms/acme/clients", Some(&reader))
        .await;

    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(
        created.body["client"]["id_token_signed_response_alg"],
        "PS256"
    );
    assert_eq!(discover().await, json!(["ES256", "RS256", "PS256"]));
}

#[actix_web::test]
async fn a_rotation_asked_while_its_tenant_makes_a_key_is_answered_503() {
    let operator = Operator::open(&[Capability::KeyWrite]).await;
    let (_name, scope) = saffui_core::tenancy::resolve::resolve_realm(&operator.product, "acme")
        .await
        .expect("the realm");
    let _making = operator
        .product
        .key_shares
        .take(scope.tenant())
        .expect("the share of its tenant");

    let refused = operator
        .send(Method::POST, KEYS, Some(&json!({ "alg": "ES256" })))
        .await;

    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        refused.body
    );
    assert_eq!(refused.body["code"], "realm.key_making_busy");
}
