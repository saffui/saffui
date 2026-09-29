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
        ceiling: support::ceiling(),
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

fn upstream(alias: &str) -> Value {
    json!({
        "provider_id": alias,
        "name": alias,
        "display_name": "An upstream",
        "description": "",
        "trust_email": false,
        "configs": {
            "issuer": { "Str": "https://op.example/realms/main" },
            "authorization_endpoint": { "Str": "https://op.example/auth" },
            "token_endpoint": { "Str": "https://op.example/token" },
            "jwks_uri": { "Str": "https://op.example/certs" },
            "client_id": { "Str": "saffui-at-op" },
            "client_secret": { "Str": "a-shared-secret" },
        },
    })
}

/// A rule is kept within the build's catalogue and within its provider:
/// what the arrival engine would not run is refused at the door, and one
/// provider's rule is not readable through another's path.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_rule_is_kept_within_its_catalogue_and_its_provider() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    for alias in ["acme", "other"] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &format!("/admin/realms/{REALM}/identity-providers"),
            &bearer,
            Some(upstream(alias)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
    }
    let base = format!("/admin/realms/{REALM}/identity-providers/acme/mappers");

    // A rule this build does not run on arrival, one missing what its type
    // reads, a sync mode that is neither word, and a role nobody made: each
    // refused with its reason.
    for (body, holds) in [
        (
            json!({ "name": "x", "mapper_type": "saml-avatar-mapper" }),
            "one of:",
        ),
        (
            json!({ "name": "x", "mapper_type": "oidc-user-attribute-idp-mapper" }),
            "names a claim",
        ),
        (
            json!({ "name": "x", "mapper_type": "oidc-user-attribute-idp-mapper",
                    "configs": { "claim": { "Str": "acr" }, "user.attribute": { "Str": "a" },
                                 "syncMode": { "Str": "sometimes" } } }),
            "import or force",
        ),
        (
            json!({ "name": "x", "mapper_type": "oidc-hardcoded-role-idp-mapper",
                    "configs": { "role": { "Str": "nobody" } } }),
            "no role answers to nobody",
        ),
    ] {
        let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|why| why.contains(holds)),
            "the refusal does not say {holds}: {told}"
        );
    }

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(
            json!({ "name": "carry-acr", "mapper_type": "oidc-user-attribute-idp-mapper",
                     "configs": { "claim": { "Str": "acr" },
                                  "user.attribute": { "Str": "upstream.acr" } } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let mapper_id = born["mapper_id"].as_str().expect("an identity").to_owned();

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told.as_array().expect("rules").len(), 1);

    // Another provider's path does not read this rule.
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/identity-providers/other/mappers/{mapper_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{mapper_id}"),
        &bearer,
        Some(
            json!({ "name": "carry-acr", "mapper_type": "oidc-user-attribute-idp-mapper",
                     "configs": { "claim": { "Str": "acr" },
                                  "user.attribute": { "Str": "upstream.acr" },
                                  "syncMode": { "Str": "force" } } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert!(told["metadata"]["version"].as_i64().unwrap_or(1) > 1);

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{mapper_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{mapper_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A provider is registered with its configuration read at the door, its
/// secret sealed on the way in and never read back, and refused deletion
/// while accounts are linked through it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_provider_is_kept_whole_and_its_secret_is_kept_dark() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/identity-providers");

    // The configuration is read the way a login will read it: a bag missing
    // what decides trust is refused here, naming the field.
    let mut lacking = upstream("half");
    lacking["configs"]
        .as_object_mut()
        .unwrap()
        .remove("token_endpoint");
    let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(lacking)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|held| held.contains("token_endpoint")),
        "the missing field is not named: {told}"
    );

    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(
            json!({ "provider_id": "two words", "name": "x", "display_name": "x",
                     "description": "", "configs": {} }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, born) = asked(&plane, Method::POST, &base, &bearer, Some(upstream("acme"))).await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let bag = born["configs"].as_object().expect("a bag");
    assert!(
        !bag.contains_key("client_secret_sealed"),
        "the sealed bytes rode out over the plane: {born}"
    );
    assert_eq!(born["configs"]["client_secret"]["Str"], "**********");

    let (status, told) = asked(&plane, Method::POST, &base, &bearer, Some(upstream("acme"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "identity_provider.already_exists");

    // A rewrite that says nothing about the secret keeps the sealed one;
    // and a provider answers to one alias.
    let mut renamed = upstream("acme");
    renamed["provider_id"] = json!("elsewhere");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/acme"),
        &bearer,
        Some(renamed),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let mut quiet = upstream("acme");
    quiet["configs"]
        .as_object_mut()
        .unwrap()
        .remove("client_secret");
    quiet["description"] = json!("rewritten");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/acme"),
        &bearer,
        Some(quiet),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["description"], "rewritten");
    assert_eq!(
        told["configs"]["client_secret"]["Str"], "**********",
        "the kept secret is no longer there: {told}"
    );

    // Linked through, the provider stays; released, it goes.
    {
        use models::entities::brokering::FederatedIdentityModel;
        use store::tenancy::TenantContext;
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::federation::brokering::link(
            &transaction,
            &FederatedIdentityModel {
                realm_id: REALM.into(),
                user_id: support::SUBJECT.into(),
                provider_alias: "acme".into(),
                external_user_id: "upstream-ada".into(),
                external_username: "ada@upstream".into(),
                created_at: chrono::Utc::now(),
            },
            false,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/acme"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/users/{}/federated-identities",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    // The route costs user:read, which this plane does not hold.
    assert_eq!(status, StatusCode::FORBIDDEN, "{held}");
}

/// Reading the providers does not grant writing them, and the user's own
/// links read under the user capability.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_idp_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/identity-providers");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, _) = asked(&plane, Method::POST, &base, &bearer, Some(upstream("x"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!(
            "/admin/realms/{REALM}/users/{}/federated-identities",
            support::SUBJECT
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held.as_array().expect("links").len(), 0);
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/users/nobody/federated-identities"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A provider taking `private_key_jwt` and an encrypted userinfo gets its own
/// two keys, drawn at the door: whatever a request says about them is dropped,
/// the private halves never ride out, a rewrite keeps the pair the provider
/// registered, and each opens to the public half it was shown with.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_provider_s_own_keys_are_drawn_here_and_kept_dark() {
    use crypto::jose::jwe::{self, JweHeader, RSA_OAEP_256};
    use crypto::jose::jwk::Jwk;
    use crypto::jose::jws::PS256;
    use services::federation::brokering::{self, ProviderKey};
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/identity-providers");
    let planted = r#"{"kty":"RSA","kid":"planted","n":"AQAB","e":"AQAB"}"#;
    let national = |accepted_acrs: &str| {
        let mut asked_for = upstream("national");
        let bag = asked_for["configs"].as_object_mut().expect("a bag");
        bag.remove("client_secret");
        for (field, value) in [
            ("token_auth", "private_key_jwt"),
            ("userinfo_endpoint", "https://op.example/userinfo"),
            ("userinfo_response", "jwe"),
            ("userinfo_algs", "RS256 PS256"),
            ("accepted_acrs", accepted_acrs),
            ("assertion_key_sealed", "AAAA"),
            ("assertion_jwk", planted),
            ("encryption_key_sealed", "AAAA"),
        ] {
            bag.insert(field.to_owned(), json!({ "Str": value }));
        }
        asked_for
    };

    // A context the realm does not count is refused, naming it.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(national("mosip:idp:acr:biometrics=platinum")),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|why| why.contains("no authentication context named platinum")),
        "{told}"
    );

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(national(&format!(
            "mosip:idp:acr:knowledge={}",
            support::PASSWORD_ACR
        ))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let shown = |answer: &Value, field: &str| -> Value {
        let written = answer["configs"][field]["Str"]
            .as_str()
            .unwrap_or_else(|| panic!("no {field} shown: {answer}"));
        serde_json::from_str(written).expect("a JWK")
    };
    let assertion_jwk = shown(&born, "assertion_jwk");
    let encryption_jwk = shown(&born, "encryption_jwk");
    assert_ne!(assertion_jwk["kid"], "planted", "a planted key was kept");
    assert_eq!(
        (
            &assertion_jwk["kty"],
            &assertion_jwk["alg"],
            &assertion_jwk["use"]
        ),
        (&json!("RSA"), &json!("PS256"), &json!("sig"))
    );
    assert_eq!(
        (
            &encryption_jwk["kty"],
            &encryption_jwk["alg"],
            &encryption_jwk["use"]
        ),
        (&json!("RSA"), &json!("RSA-OAEP-256"), &json!("enc"))
    );
    assert!(
        assertion_jwk.get("d").is_none() && encryption_jwk.get("d").is_none(),
        "a private half was shown: {born}"
    );
    for (method, path) in [
        (Method::GET, format!("{base}/national")),
        (Method::GET, base.clone()),
    ] {
        let (status, told) = asked(&plane, method, &path, &bearer, None).await;
        assert_eq!(status, StatusCode::OK, "{told}");
        let text = told.to_string();
        assert!(
            !text.contains("assertion_key_sealed") && !text.contains("encryption_key_sealed"),
            "a sealed key rode out: {told}"
        );
    }

    // A rewrite, even one naming other keys, keeps the registered pair.
    let (status, rewritten) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/national"),
        &bearer,
        Some(national(&format!(
            "mosip:idp:acr:knowledge={}",
            support::PASSWORD_ACR
        ))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rewritten}");
    assert_eq!(shown(&rewritten, "assertion_jwk"), assertion_jwk);
    assert_eq!(shown(&rewritten, "encryption_jwk"), encryption_jwk);

    // What is sealed is the private half of what was shown.
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let sealing = support::sealing();
    let ring = store::keyring::load(&transaction, &sealing.envelope, support::TENANT, REALM)
        .await
        .expect("the realm's keyring");
    let stored = brokering::read_provider(&transaction, "national")
        .await
        .expect("the store")
        .expect("the provider");
    let opened = |which| brokering::open_provider_key(&ring, &sealing.envelope, &stored, which);
    let signing = opened(ProviderKey::Assertion)
        .await
        .expect("the assertion key");
    assert_eq!(Some(signing.kid.as_str()), assertion_jwk["kid"].as_str());
    let assertion = services::token::assertion::client_assertion(
        &support::provider(),
        &services::token::assertion::AssertionKey {
            kid: &signing.kid,
            private_pem: &signing.private_pem,
            algorithm: services::token::assertion::AssertionAlgorithm::Ps256,
        },
        "saffui-at-op",
        "https://op.example/realms/main",
        chrono::Utc::now(),
    )
    .expect("an assertion");
    let registered: Jwk =
        Jwk::from_bytes(assertion_jwk.to_string().as_bytes()).expect("the shown key");
    crypto::jose::jwt::decode_with_verifier(
        &assertion,
        &PS256.verifier_from_jwk(&registered).expect("a verifier"),
    )
    .expect("an assertion the shown key verifies");

    let opening = opened(ProviderKey::Encryption)
        .await
        .expect("the encryption key");
    let recipient: Jwk =
        Jwk::from_bytes(encryption_jwk.to_string().as_bytes()).expect("the shown key");
    let mut header = JweHeader::new();
    header.set_content_encryption("A256GCM");
    let sealed = jwe::serialize_compact(
        b"for the realm",
        &header,
        &RSA_OAEP_256
            .encrypter_from_jwk(&recipient)
            .expect("an encrypter"),
    )
    .expect("a JWE");
    let (inside, _) = jwe::deserialize_compact(
        &sealed,
        &RSA_OAEP_256
            .decrypter_from_pem(secrecy::ExposeSecret::expose_secret(&opening.private_pem))
            .expect("a decrypter"),
    )
    .expect("a JWE the held key opens");
    assert_eq!(inside, b"for the realm");
    drop(transaction);

    // A provider proving itself with a secret, its userinfo unsigned, holds
    // no key of its own, whatever its request planted.
    let mut plain = upstream("plain");
    let bag = plain["configs"].as_object_mut().expect("a bag");
    for field in ["assertion_key_sealed", "encryption_key_sealed"] {
        bag.insert(field.to_owned(), json!({ "Str": "AAAA" }));
    }
    for field in ["assertion_jwk", "encryption_jwk"] {
        bag.insert(field.to_owned(), json!({ "Str": planted }));
    }
    let (status, plain) = asked(&plane, Method::POST, &base, &bearer, Some(plain)).await;
    assert_eq!(status, StatusCode::CREATED, "{plain}");
    assert!(
        plain["configs"].get("assertion_jwk").is_none()
            && plain["configs"].get("encryption_jwk").is_none(),
        "{plain}"
    );
    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let stored = brokering::read_provider(&transaction, "plain")
        .await
        .expect("the store")
        .expect("the provider");
    let bag = stored.configs.expect("a bag");
    for field in ProviderKey::ALL
        .iter()
        .flat_map(|key| [key.sealed_field_name(), key.public_field_name()])
    {
        assert!(!bag.contains_key(field), "{field} was kept as planted");
    }
}

/// A provider that verifies RS256 alone, as eSignet 1.x does, gets a classic
/// RSA key drawn for RS256, whose assertions its shown half verifies; the
/// algorithm stands with the key, so asking another is refused in words while
/// the same one keeps the key.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_assertion_key_is_drawn_for_the_algorithm_its_provider_verifies() {
    use crypto::jose::jwk::Jwk;
    use crypto::jose::jws::RS256;
    use services::federation::brokering::{self, ProviderKey};
    use services::token::assertion::{AssertionAlgorithm, AssertionKey, client_assertion};
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/identity-providers");
    let signing_with = |alias: &str, algorithm: Option<&str>| {
        let mut asked_for = upstream(alias);
        let bag = asked_for["configs"].as_object_mut().expect("a bag");
        bag.remove("client_secret");
        bag.insert("token_auth".to_owned(), json!({ "Str": "private_key_jwt" }));
        bag.insert(
            "assertion_audience".to_owned(),
            json!({ "Str": "token_endpoint" }),
        );
        if let Some(algorithm) = algorithm {
            bag.insert("assertion_alg".to_owned(), json!({ "Str": algorithm }));
        }
        asked_for
    };
    let shown = |answer: &Value| -> Value {
        let written = answer["configs"]["assertion_jwk"]["Str"]
            .as_str()
            .unwrap_or_else(|| panic!("no assertion key shown: {answer}"));
        serde_json::from_str(written).expect("a JWK")
    };

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(signing_with("older", Some("RS256"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let assertion_jwk = shown(&born);
    assert_eq!(
        (
            &assertion_jwk["kty"],
            &assertion_jwk["alg"],
            &assertion_jwk["use"]
        ),
        (&json!("RSA"), &json!("RS256"), &json!("sig"))
    );

    let transaction = plane
        .scoped(&TenantContext::new(support::TENANT, REALM))
        .await;
    let sealing = support::sealing();
    let ring = store::keyring::load(&transaction, &sealing.envelope, support::TENANT, REALM)
        .await
        .expect("the realm's keyring");
    let stored = brokering::read_provider(&transaction, "older")
        .await
        .expect("the store")
        .expect("the provider");
    let signing =
        brokering::open_provider_key(&ring, &sealing.envelope, &stored, ProviderKey::Assertion)
            .await
            .expect("the assertion key");
    drop(transaction);
    let assertion = client_assertion(
        &support::provider(),
        &AssertionKey {
            kid: &signing.kid,
            private_pem: &signing.private_pem,
            algorithm: AssertionAlgorithm::Rs256,
        },
        "saffui-at-op",
        "https://op.example/token",
        chrono::Utc::now(),
    )
    .expect("an assertion");
    let registered: Jwk =
        Jwk::from_bytes(assertion_jwk.to_string().as_bytes()).expect("the shown key");
    crypto::jose::jwt::decode_with_verifier(
        &assertion,
        &RS256.verifier_from_jwk(&registered).expect("a verifier"),
    )
    .expect("an assertion the shown key verifies");

    for (alias, asked_algorithm, refusal) in [
        (
            "older",
            Some("PS256"),
            "this provider's assertion key signs RS256: signing PS256 takes a new provider, whose key is registered anew where it signs in",
        ),
        (
            "older",
            None,
            "this provider's assertion key signs RS256: signing PS256 takes a new provider, whose key is registered anew where it signs in",
        ),
    ] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("{base}/{alias}"),
            &bearer,
            Some(signing_with(alias, asked_algorithm)),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert_eq!(told["message"], refusal, "{asked_algorithm:?}");
    }
    let (status, kept) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/older"),
        &bearer,
        Some(signing_with("older", Some("RS256"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert_eq!(shown(&kept), assertion_jwk);

    // A provider drawn for PS256 keeps to it the same way.
    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(signing_with("newer", None)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(shown(&born)["alg"], "PS256");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/newer"),
        &bearer,
        Some(signing_with("newer", Some("RS256"))),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert_eq!(
        told["message"],
        "this provider's assertion key signs PS256: signing RS256 takes a new provider, whose key is registered anew where it signs in"
    );
}
