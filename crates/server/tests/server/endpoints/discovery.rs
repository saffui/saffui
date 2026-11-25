use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use saffui_core::ports::storage::StorageUnavailable;
use saffui_core::tenancy::realm::{NewRealm, provision_first_realm};
use saffui_core::testkit::memory::MemoryStorage;
use serde_json::{Value, json};
use server::api::config::register_data_plane;

const ACME: NewRealm<'static> = NewRealm {
    tenant_name: "Acme",
    realm_name: "acme",
};

async fn get_json(product: saffui_core::app::App, path: &str) -> (StatusCode, Value) {
    let app =
        test::init_service(App::new().configure(register_data_plane(web::Data::new(product))))
            .await;
    let response = test::call_service(&app, test::TestRequest::get().uri(path).to_request()).await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

#[actix_web::test]
async fn a_realm_publishes_its_issuer_under_the_public_origin() {
    let (product, _storage) = MemoryStorage::wire();
    provision_first_realm(&product, ACME)
        .await
        .expect("a realm");

    let (status, document) =
        get_json(product, "/realms/acme/.well-known/openid-configuration").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(document["issuer"], "https://id.example.test/realms/acme");
    assert_eq!(
        document["jwks_uri"],
        "https://id.example.test/realms/acme/oauth2/jwks"
    );
    assert_eq!(
        document["token_endpoint"],
        "https://id.example.test/realms/acme/oauth2/token"
    );
}

#[actix_web::test]
async fn an_unknown_realm_a_malformed_name_and_a_disabled_realm_answer_the_same_404() {
    let (product, storage) = MemoryStorage::wire();
    provision_first_realm(&product, ACME)
        .await
        .expect("a realm");
    storage.disable_realm("acme");
    let not_found = json!({
        "code": "realm.not_found",
        "error_code": 100,
        "message": "No such realm.",
    });

    for realm in ["nobody", "Not%20A%20Name", "acme"] {
        let path = format!("/realms/{realm}/.well-known/openid-configuration");
        let (status, body) = get_json(product.clone(), &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body, not_found, "{path}");
    }
}

#[actix_web::test]
async fn a_storage_that_is_down_answers_503_and_says_nothing_of_the_cause() {
    let (product, storage) = MemoryStorage::wire();
    storage.fail_with(StorageUnavailable::Refused);

    let (status, body) = get_json(product, "/realms/acme/.well-known/openid-configuration").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({
            "code": "platform.storage_unavailable",
            "error_code": 2,
            "message": "The service is temporarily unavailable.",
        })
    );
}

#[actix_web::test]
async fn a_realm_publishes_the_claims_of_the_protocol_and_of_the_scopes_and_none_of_a_client() {
    use saffui_core::claims::{ClaimTarget, Mapper, MapperKind};
    use saffui_core::testkit::fixtures::{create_application, create_realm};

    let (product, _storage) = MemoryStorage::wire();
    let scope = create_realm(&product, "acme").await;
    create_application(
        &product,
        scope,
        "portal",
        "https://app.example.test/cb",
        true,
    )
    .await;
    let mut work = product.storage.begin(scope).await.expect("a unit of work");
    for (index, claim, target) in [
        (1, "dept", ClaimTarget::Userinfo),
        (2, "internal", ClaimTarget::AccessToken),
    ] {
        let mapper = Mapper {
            id: uuid::Uuid::from_u128(index),
            client_id: "portal".to_owned(),
            name: claim.to_owned(),
            kind: MapperKind::Attribute {
                attribute: "department".to_owned(),
            },
            claim: Some(claim.to_owned()),
            targets: vec![target],
            scope: Some("profile".to_owned()),
            created_at: product.now(),
        };
        assert_eq!(work.insert_mapper(&mapper).await, Ok(true));
    }
    work.commit().await.expect("a commit");

    let (status, document) =
        get_json(product, "/realms/acme/.well-known/openid-configuration").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(document["claims_parameter_supported"], true);
    let supported: Vec<&str> = document["claims_supported"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for claim in ["sub", "acr", "given_name", "email"] {
        assert!(supported.contains(&claim), "{claim}: {supported:?}");
    }
    for claim in ["dept", "internal"] {
        assert!(
            !supported.contains(&claim),
            "how a client is set up is told to nobody: {supported:?}"
        );
    }
    assert_eq!(document["acr_values_supported"], json!(["1", "2"]));
}
