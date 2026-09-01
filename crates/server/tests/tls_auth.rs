mod support;

use actix_web::http::StatusCode;
use actix_web::{App, test};
use data_encoding::BASE64;
use serde_json::Value;
use server::api::config::register;
use store::tenancy::TenantContext;
use support::Plane;

const REALM: &str = support::REALM;
const CERT_HEADER: &str = "x-ssl-client-cert";
const MACHINE: &str = "till-7";
const REDIRECT: &str = "https://till.example/callback";

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
        hops: config::proxying::Proxying::behind_terminating_peers(
            config::proxying::ProxyHeader::XForwardedFor,
            CERT_HEADER,
            vec![config::proxying::Peer::parse("10.0.0.0/8").expect("a peer")],
        ),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

/// A confidential client that authenticates by what its certificate says:
/// no secret to keep, one DNS name registered.
async fn planted_till(plane: &Plane) {
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;
    use models::entities::client::ClientCreateModel;

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let mut client = ClientCreateModel {
        name: MACHINE.into(),
        display_name: MACHINE.into(),
        description: String::new(),
        enabled: Some(true),
    }
    .into_model(
        MACHINE.to_owned(),
        REALM.into(),
        AuditableModel::from_creator(support::TENANT.into(), "root".into()),
    );
    store::providers::clients::create(&transaction, &client)
        .await
        .unwrap();
    client.public_client = Some(false);
    client.client_authenticator_type = Some("tls-client-auth".into());
    client.redirect_uris = Some(vec![REDIRECT.to_owned()]);
    client.standard_flow_enabled = Some(true);
    client.configs.get_or_insert_with(Default::default).insert(
        "tls.san_dns".to_owned(),
        AttributeValue::Str("till-7.shop.example".to_owned()),
    );
    store::providers::clients::update(&transaction, &client)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A self-signed leaf whose SANs say who it is; the proxy would have
/// verified the chain, this deployment reads the names.
fn minted(dns: &str) -> String {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", dns).unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns(dns)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    BASE64.encode(&builder.build().to_der().unwrap())
}

async fn exchanged(plane: &Plane, code: &str, certificate: Option<&str>) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::post()
        .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
        .peer_addr("10.4.5.6:5000".parse().unwrap())
        .set_form([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("client_id", MACHINE),
        ]);
    if let Some(certificate) = certificate {
        asking = asking.insert_header((CERT_HEADER, certificate.to_owned()));
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// RFC 8705 §2: the certificate is the credential. The registered name admits,
/// a stranger's certificate and a bare name are refused with one face, and the
/// minted tokens are certificate-bound as §3 already binds them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_certificate_is_a_client_credential() {
    let plane = Plane::with_actions(&[]).await;
    planted_till(&plane).await;

    let code = plane.mint_code(MACHINE, REDIRECT, "openid", None).await;
    let (status, minted_tokens) =
        exchanged(&plane, &code, Some(&minted("till-7.shop.example"))).await;
    assert_eq!(status, StatusCode::OK, "{minted_tokens}");
    let claims = plane
        .claims_of(minted_tokens["access_token"].as_str().expect("a token"))
        .await;
    assert!(
        claims["cnf"]["x5t#S256"].is_string(),
        "the token does not name the certificate: {claims}"
    );

    // A stranger's certificate, and none at all: one refusal.
    let code = plane.mint_code(MACHINE, REDIRECT, "openid", None).await;
    let (status, told) = exchanged(&plane, &code, Some(&minted("intruder.example"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["error"], "invalid_client", "{told}");
    let (status, told) = exchanged(&plane, &code, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");

    // A secret does not stand in for the certificate: the method is the
    // registration's, not the request's choice.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/protocol/openid-connect/token"))
            .peer_addr("10.4.5.6:5000".parse().unwrap())
            .set_form([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT),
                ("client_id", MACHINE),
                ("client_secret", "a-secret-it-never-registered"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Registered with no name, or with two, the client is misprovisioned and
    // refused whole rather than served loosely.
    {
        use models::entities::attributes::AttributeValue;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut client = store::providers::clients::load(&transaction, MACHINE)
            .await
            .unwrap()
            .expect("the client");
        client.configs.get_or_insert_with(Default::default).insert(
            "tls.san_uri".to_owned(),
            AttributeValue::Str("spiffe://shop/till-7".to_owned()),
        );
        store::providers::clients::update(&transaction, &client)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
    let code = plane.mint_code(MACHINE, REDIRECT, "openid", None).await;
    let (status, _) = exchanged(&plane, &code, Some(&minted("till-7.shop.example"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "two names served anyway");
}
