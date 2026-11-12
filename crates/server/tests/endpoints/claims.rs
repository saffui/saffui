use actix_web::http::{Method, StatusCode};
use saffui_core::authz::capability::Capability;
use serde_json::{Value, json};

use super::admin::{Answer, call, start};

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
}

#[actix_web::test]
async fn an_administrator_gives_a_client_mappers_lists_them_and_takes_them_away() {
    let operator = Operator::open(&[
        Capability::ClientRead,
        Capability::ClientWrite,
        Capability::UserRead,
    ])
    .await;
    let application = json!({
        "client_id": "portal",
        "scopes": ["openid", "profile"],
        "redirect_uris": ["https://app.example.test/callback"],
        "public": true,
    });
    let made = operator
        .send(
            Method::POST,
            "/admin/v1/realms/acme/clients",
            Some(&application),
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let mappers = "/admin/v1/realms/acme/clients/portal/mappers";
    let department = json!({
        "name": "department",
        "definition": { "kind": "attribute", "attribute": "department" },
        "claim": "dept",
        "targets": ["userinfo", "id_token"],
        "scope": "profile",
    });
    let mapper = |name: &str, claim: &str, scope: &str| {
        json!({
            "name": name,
            "definition": { "kind": "attribute", "attribute": "team" },
            "claim": claim,
            "targets": ["id_token"],
            "scope": scope,
        })
    };

    let created = operator
        .send(Method::POST, mappers, Some(&department))
        .await;
    let mut refused = Vec::new();
    for (wanted, why) in [
        (
            mapper("sneaky", "email_verified", "profile"),
            "a claim of a scope",
        ),
        (
            json!({ "name": "script", "definition": { "kind": "script", "source": "1" }, "claim": "x", "targets": ["id_token"], "scope": "profile" }),
            "a kind this version does not have",
        ),
        (
            json!({ "name": "cookie", "definition": { "kind": "full_name" }, "claim": "x", "targets": ["cookie"], "scope": "profile" }),
            "a target this version does not have",
        ),
        (mapper("two words", "team", "profile"), "a name"),
        (mapper("team", "team", "bad scope"), "a scope"),
        (
            mapper("team", "team", "email"),
            "a scope the client may not be given",
        ),
        (mapper("team", "team", "openid"), "openid"),
    ] {
        refused.push((
            operator.send(Method::POST, mappers, Some(&wanted)).await,
            why,
        ));
    }
    for disguised in [
        "Email_verified",
        "EMAIL",
        "Sub",
        "Phone_number_verified",
        "Realm_Access",
        "realm_access.roles",
        "sub_",
        "_sub",
        "email_",
        "email-verified",
        "e_mail",
        "preferred_username_",
        "given-name",
        "nameid",
        "unique_name",
        "upn",
        "prn",
        "oid",
        "tid",
        "primarysid",
        "winaccountname",
        "actort",
    ] {
        refused.push((
            operator
                .send(
                    Method::POST,
                    mappers,
                    Some(&mapper("team", disguised, "profile")),
                )
                .await,
            disguised,
        ));
    }
    let taken = operator
        .send(Method::POST, mappers, Some(&department))
        .await;
    let listed = operator.send(Method::GET, mappers, None).await;

    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["targets"], json!(["id_token", "userinfo"]));
    assert_eq!(
        created.body["definition"],
        json!({ "kind": "attribute", "attribute": "department" })
    );
    for (answer, why) in refused {
        assert_eq!(
            answer.status,
            StatusCode::BAD_REQUEST,
            "{why}: {}",
            answer.body
        );
        assert_eq!(answer.body["code"], "client.mapper_invalid", "{why}");
    }
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.body["code"], "client.mapper_name_taken");
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["items"].as_array().map(Vec::len), Some(1));
    let id = created.body["id"].as_str().expect("an identifier");
    let delete = async |mapper: &str| {
        operator
            .send(Method::DELETE, &format!("{mappers}/{mapper}"), None)
            .await
            .status
    };
    assert_eq!(delete(id).await, StatusCode::NO_CONTENT);
    assert_eq!(delete(id).await, StatusCode::NOT_FOUND);
    assert_eq!(delete("not-an-identifier").await, StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn an_attribute_policies_read_is_refused_to_a_caller_that_may_not_write_policies() {
    let operator = Operator::open(&[Capability::UserWrite, Capability::UserRead]).await;
    let made = operator
        .send(
            Method::POST,
            "/admin/v1/realms/acme/users",
            Some(&json!({ "username": "ada" })),
        )
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.body);
    let attributes = format!(
        "/admin/v1/realms/acme/users/{}/attributes",
        made.body["id"].as_str().expect("an identifier")
    );
    let put = async |path: &str, written: Value| {
        operator
            .send(Method::PUT, path, Some(&json!({ "attributes": written })))
            .await
    };

    let of_policies = put(&attributes, json!({ "policy.team": "audit" })).await;
    let plain = put(&attributes, json!({ "department": "audit" })).await;
    let unreadable = put(&attributes, json!({ "age": 36 })).await;
    let read = operator.send(Method::GET, &attributes, None).await;
    let nobody = put(
        "/admin/v1/realms/acme/users/00000000-0000-0000-0000-000000000001/attributes",
        json!({}),
    )
    .await;

    assert_eq!(of_policies.status, StatusCode::FORBIDDEN);
    assert_eq!(of_policies.body["code"], "auth.capability_missing");
    assert_eq!(plain.status, StatusCode::NO_CONTENT);
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST);
    assert_eq!(unreadable.body["code"], "user.attributes_invalid");
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(
        read.body,
        json!({ "attributes": { "department": "audit" } })
    );
    assert_eq!(nobody.status, StatusCode::NOT_FOUND);
    assert_eq!(nobody.body["code"], "user.not_found");
}

#[actix_web::test]
async fn a_client_is_given_a_scope_by_a_caller_that_may_read_what_it_makes_tokens_say() {
    let make = async |operator: &Operator, client_id: &str, scope: &str| {
        let wanted = json!({ "client_id": client_id, "scopes": ["openid", scope] });
        operator
            .send(Method::POST, "/admin/v1/realms/acme/clients", Some(&wanted))
            .await
    };
    let writer = Operator::open(&[Capability::ClientWrite]).await;
    let reader = Operator::open(&[
        Capability::ClientWrite,
        Capability::UserRead,
        Capability::RoleRead,
    ])
    .await;

    for scope in ["roles", "profile", "email"] {
        let refused = make(&writer, "portal", scope).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "{scope}: {}",
            refused.body
        );
        assert_eq!(refused.body["code"], "auth.capability_missing", "{scope}");
    }
    for (client_id, scope) in [("one", "roles"), ("two", "profile"), ("three", "email")] {
        let made = make(&reader, client_id, scope).await;
        assert_eq!(made.status, StatusCode::CREATED, "{scope}: {}", made.body);
    }
    let plain = make(&writer, "plain", "invoices:read").await;
    assert_eq!(plain.status, StatusCode::CREATED, "{}", plain.body);
}

/// A person signed in to `webapp` holds 600 roles of 64 characters, and a
/// mapper says them all in the access token: more than a token carries.
#[actix_web::test]
async fn a_client_whose_mappers_write_too_much_is_told_so_and_never_answered_500() {
    use actix_web::http::header::CONTENT_TYPE;
    use actix_web::{App, test, web};
    use saffui_core::authz::admin::authorize_admin_call;
    use saffui_core::authz::grants::{GrantTerms, RoleHolder, grant_role};
    use saffui_core::authz::roles::{NewRole, create_role};
    use saffui_core::claims::manage::create_mapper;
    use saffui_core::claims::{ClaimTarget, MapperKind, NewMapper};
    use saffui_core::error::ErrorCode;
    use saffui_core::testkit::fixtures::{
        Application, CodeFlow, create_administrator, create_person, create_realm,
        register_application, run_code_flow,
    };
    use saffui_core::testkit::memory::MemoryStorage;
    use server::api::config::register_data_plane;

    const CALLBACK: &str = "https://app.example.org/callback";
    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    let ada = create_person(&product, scope, "ada", "correct horse battery").await;
    let webapp = Application {
        client_id: "webapp",
        redirect_uri: CALLBACK,
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(&product, scope, webapp).await;
    let flow = CodeFlow {
        realm: "acme",
        client_id: "webapp",
        client_secret: None,
        redirect_uri: CALLBACK,
        scope: "openid profile",
        username: "ada",
        password: "correct horse battery",
    };
    let refresh_token = run_code_flow(&product, flow)
        .await
        .tokens
        .refresh_token
        .expect("a refresh token");
    let token = create_administrator(&product, "acme", scope, "operator", &Capability::ALL).await;
    let operator = authorize_admin_call(&product, "acme", Some(&token), Capability::RoleWrite)
        .await
        .expect("an operator");
    for index in 0..600 {
        let name = format!("{index:03}-{}", "r".repeat(60));
        let wanted = NewRole {
            name: &name,
            client_id: None,
            description: None,
        };
        let role = create_role(&product, &operator, wanted)
            .await
            .expect("a role");
        grant_role(
            &product,
            &operator,
            role.id,
            RoleHolder::Person(ada.id),
            GrantTerms::default(),
        )
        .await
        .expect("a grant");
    }
    let roles = NewMapper {
        name: "roles",
        kind: MapperKind::RealmRoles,
        claim: Some("roles"),
        targets: &[ClaimTarget::AccessToken],
        scope: Some("profile"),
    };
    create_mapper(&product, &operator, "webapp", roles)
        .await
        .expect("a mapper");

    let app = test::init_service(
        App::new().configure(register_data_plane(web::Data::new(product.clone()))),
    )
    .await;
    let request = test::TestRequest::post()
        .uri("/realms/acme/oauth2/token")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(format!(
            "grant_type=refresh_token&client_id=webapp&refresh_token={refresh_token}"
        ))
        .to_request();
    let response = test::call_service(&app, request).await;
    let status = response.status();
    let body: Value = test::read_body_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(
        body["error_description"],
        ErrorCode::ClaimsTooLarge.message(),
        "the client is told what to fix"
    );
}
