use actix_web::http::{Method, StatusCode};
use saffui_core::authz::capability::Capability;
use serde_json::{Value, json};

use super::admin::{Answer, call, start};

struct Operator {
    product: saffui_core::app::App,
    token: String,
}

impl Operator {
    async fn open() -> Self {
        let capabilities = [
            Capability::RoleRead,
            Capability::RoleWrite,
            Capability::UserWrite,
        ];
        let (product, token) = start(&capabilities).await;
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

    async fn make(&self, path: &str, body: &Value) -> String {
        let made = self.send(Method::POST, path, Some(body)).await;
        assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
        made.body["id"].as_str().expect("an identifier").to_owned()
    }
}

#[actix_web::test]
async fn an_administrator_makes_roles_lists_them_and_deletes_them() {
    let operator = Operator::open().await;
    let roles = "/admin/v1/realms/acme/roles";

    let admin = operator
        .make(
            roles,
            &json!({ "name": "admin", "description": "runs the place" }),
        )
        .await;
    let taken = operator
        .send(Method::POST, roles, Some(&json!({ "name": "admin" })))
        .await;
    let of_nobody = operator
        .send(
            Method::POST,
            roles,
            Some(&json!({ "name": "admin", "client_id": "nobody" })),
        )
        .await;
    let unreadable = operator
        .send(Method::POST, roles, Some(&json!({ "name": "two words" })))
        .await;
    let listed = operator
        .send(Method::GET, &format!("{roles}?count=true"), None)
        .await;

    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(
        taken.body["code"], "authz.role_name_taken",
        "{}",
        taken.body
    );
    assert_eq!(of_nobody.status, StatusCode::NOT_FOUND);
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST);
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["items"][0]["name"], "admin");
    assert_eq!(listed.body["items"][0]["client_id"], Value::Null);
    assert_eq!(listed.body["items"][0]["description"], "runs the place");
    let delete = async |role: String| {
        operator
            .send(Method::DELETE, &format!("{roles}/{role}"), None)
            .await
            .status
    };
    assert_eq!(delete(admin.clone()).await, StatusCode::NO_CONTENT);
    assert_eq!(delete(admin).await, StatusCode::NOT_FOUND);
    assert_eq!(
        delete("not-an-identifier".to_owned()).await,
        StatusCode::NOT_FOUND
    );
}

#[actix_web::test]
async fn an_administrator_makes_groups_lists_them_and_deletes_them() {
    let operator = Operator::open().await;
    let groups = "/admin/v1/realms/acme/groups";

    let finance = operator
        .make(
            groups,
            &json!({ "name": "finance", "description": "the people of the books" }),
        )
        .await;
    operator.make(groups, &json!({ "name": "audit" })).await;
    let taken = operator
        .send(Method::POST, groups, Some(&json!({ "name": "finance" })))
        .await;
    let unreadable = operator
        .send(Method::POST, groups, Some(&json!({ "name": "two words" })))
        .await;
    let listed = operator
        .send(Method::GET, &format!("{groups}?count=true"), None)
        .await;

    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(
        taken.body["code"], "authz.group_name_taken",
        "{}",
        taken.body
    );
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST);
    assert_eq!(listed.body["total"], 2);
    assert_eq!(listed.body["items"][0]["name"], "audit");
    assert_eq!(
        listed.body["items"][1]["description"],
        "the people of the books"
    );
    let delete = async |group: String| {
        operator
            .send(Method::DELETE, &format!("{groups}/{group}"), None)
            .await
            .status
    };
    assert_eq!(delete(finance.clone()).await, StatusCode::NO_CONTENT);
    assert_eq!(delete(finance).await, StatusCode::NOT_FOUND);
    assert_eq!(
        delete("not-an-identifier".to_owned()).await,
        StatusCode::NOT_FOUND
    );
}

#[actix_web::test]
async fn a_role_held_directly_and_through_a_group_is_listed_with_its_way_and_its_end() {
    let operator = Operator::open().await;
    let person = operator
        .make("/admin/v1/realms/acme/users", &json!({ "username": "ada" }))
        .await;
    let role = operator
        .make(
            "/admin/v1/realms/acme/roles",
            &json!({ "name": "approver" }),
        )
        .await;
    let group = operator
        .make(
            "/admin/v1/realms/acme/groups",
            &json!({ "name": "finance" }),
        )
        .await;
    let until = json!({ "valid_until": "2026-01-02T00:00:00Z", "reason": "the quarter's close" });

    let direct = operator
        .send(
            Method::PUT,
            &format!("/admin/v1/realms/acme/users/{person}/roles/{role}"),
            Some(&until),
        )
        .await;
    let to_group = operator
        .send(
            Method::PUT,
            &format!("/admin/v1/realms/acme/groups/{group}/roles/{role}"),
            Some(&json!({})),
        )
        .await;
    let joined = operator
        .send(
            Method::PUT,
            &format!("/admin/v1/realms/acme/groups/{group}/members/{person}"),
            Some(&json!({ "valid_from": "2020-01-01T00:00:00Z" })),
        )
        .await;
    let held = operator
        .send(
            Method::GET,
            &format!("/admin/v1/realms/acme/users/{person}/roles"),
            None,
        )
        .await;

    assert_eq!(direct.status, StatusCode::OK, "{}", direct.body);
    assert_eq!(direct.body["granted_by"], "operator");
    assert_eq!(direct.body["valid_until"], "2026-01-02T00:00:00Z");
    assert_eq!(direct.body["reason"], "the quarter's close");
    assert_eq!(to_group.status, StatusCode::OK, "{}", to_group.body);
    assert_eq!(
        joined.body["valid_from"], joined.body["granted_at"],
        "a start in the past is the instant of the grant"
    );
    assert_eq!(held.status, StatusCode::OK, "{}", held.body);
    assert_eq!(
        held.body["items"],
        json!([
            {
                "role_id": role,
                "name": "approver",
                "client_id": null,
                "through_group": null,
                "until": "2026-01-02T00:00:00Z",
            },
            {
                "role_id": role,
                "name": "approver",
                "client_id": null,
                "through_group": group,
                "until": null,
            },
        ])
    );
    let revoke = || async {
        operator
            .send(
                Method::DELETE,
                &format!("/admin/v1/realms/acme/users/{person}/roles/{role}"),
                None,
            )
            .await
            .status
    };
    assert_eq!(revoke().await, StatusCode::NO_CONTENT);
    assert_eq!(revoke().await, StatusCode::NOT_FOUND);
    let left = operator
        .send(
            Method::DELETE,
            &format!("/admin/v1/realms/acme/groups/{group}/members/{person}"),
            None,
        )
        .await;
    assert_eq!(left.status, StatusCode::NO_CONTENT);
    let held = operator
        .send(
            Method::GET,
            &format!("/admin/v1/realms/acme/users/{person}/roles"),
            None,
        )
        .await;
    assert_eq!(held.body["items"], json!([]));
}

#[actix_web::test]
async fn terms_that_cannot_be_read_or_end_before_they_start_are_refused() {
    let operator = Operator::open().await;
    let person = operator
        .make("/admin/v1/realms/acme/users", &json!({ "username": "ada" }))
        .await;
    let role = operator
        .make(
            "/admin/v1/realms/acme/roles",
            &json!({ "name": "approver" }),
        )
        .await;
    let path = format!("/admin/v1/realms/acme/users/{person}/roles/{role}");

    for terms in [
        json!({ "valid_until": "tomorrow" }),
        json!({ "valid_until": "2020-01-01T00:00:00Z" }),
        json!({ "valid_from": "2027-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z" }),
    ] {
        let refused = operator.send(Method::PUT, &path, Some(&terms)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{terms}");
        assert_eq!(
            refused.body["code"], "authz.grant_period_invalid",
            "{terms}"
        );
    }
    let unknown = operator
        .send(Method::PUT, &path, Some(&json!({ "forever": true })))
        .await;
    assert_eq!(
        unknown.status,
        StatusCode::BAD_REQUEST,
        "a term this version does not know must not look granted"
    );
    let nobody = operator
        .send(
            Method::PUT,
            &format!("/admin/v1/realms/acme/users/{role}/roles/{role}"),
            Some(&json!({})),
        )
        .await;
    assert_eq!(nobody.status, StatusCode::NOT_FOUND);
    assert_eq!(nobody.body["code"], "user.not_found");
}

#[actix_web::test]
async fn a_reader_of_roles_lists_them_and_writes_none() {
    let (product, token) = start(&[Capability::RoleRead]).await;
    let send = |method: Method, path: &'static str, body: Option<&'static str>| {
        let (product, token) = (product.clone(), token.clone());
        async move {
            call(&product, method, path, Some(&token), body)
                .await
                .status
        }
    };

    assert_eq!(
        send(Method::GET, "/admin/v1/realms/acme/roles", None).await,
        StatusCode::OK
    );
    assert_eq!(
        send(Method::GET, "/admin/v1/realms/acme/groups", None).await,
        StatusCode::OK
    );
    assert_eq!(
        send(
            Method::POST,
            "/admin/v1/realms/acme/roles",
            Some(r#"{"name":"admin"}"#)
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            Method::POST,
            "/admin/v1/realms/acme/groups",
            Some(r#"{"name":"finance"}"#)
        )
        .await,
        StatusCode::FORBIDDEN
    );
}
