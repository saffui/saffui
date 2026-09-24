mod support;

use std::sync::Arc;

use chrono::{Duration, Utc};
use crypto::envelope::Envelope;
use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::provider::{CryptoProvider, PrivateKey, PublicKey, SignAlg};
use crypto::x509::{Issuance, issue_certificate};
use models::auditable::AuditableModel;
use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::authz::IdentityProviderMutationModel;
use models::entities::brokering::SamlLoginRequest;
use saml::dsig::Unverified;
use saml::response::Refused;
use services::federation::saml_brokering::{SamlAnswer, SamlUpstream, Untaken, take_answer};
use services::oidc::grant::Signing;
use store::keyring;
use store::tenancy::TenantContext;
use support::{Fixture, provider};

const KEK: &str = "a-deployment-wrapping-key-of-decent-length";
const ISSUER: &str = "https://saffui.test/realms/main";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const THE_BROWSER: &str = "the-browser-that-left";

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

fn envelope() -> Envelope {
    Envelope::new(Arc::new(provider()), KEK).expect("an envelope")
}

/// A SAML provider signing with `key` under a certificate the crypto crate issues
/// for it, with whatever else the administrator set.
fn upstream(key: &RsaKeyPair, more: &[(&str, &str)]) -> SamlUpstream {
    let certificate = issue_certificate(&Issuance {
        subject_key: &PublicKey::from_der(key.to_der_public_key()),
        subject_name: "idp.test",
        issuer_key: &PrivateKey::from_der(key.to_der_private_key()),
        issuer_name: "idp.test",
        serial: &[1],
        not_before: 1_789_372_800,
        not_after: 2_104_992_000,
    })
    .expect("a certificate");
    let metadata = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
        data_encoding::BASE64.encode(&certificate)
    );
    let mut said = vec![("protocol", "saml"), ("idp_metadata", metadata.as_str())];
    said.extend_from_slice(more);
    let configs: AttributesMap = said
        .iter()
        .map(|(name, value)| ((*name).to_owned(), AttributeValue::Str((*value).to_owned())))
        .collect();
    let provider = IdentityProviderMutationModel {
        provider_id: "corp".into(),
        name: "corp".into(),
        display_name: "Corp".into(),
        description: String::new(),
        enabled: Some(true),
        trust_email: Some(false),
        configs: Some(configs),
    }
    .into_model(
        "idp-1".into(),
        "main".into(),
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    SamlUpstream::parse(&provider).expect("a usable provider")
}

/// What an answer says, each part a case may change: by default a persistent name,
/// for the realm's entity for `corp`, at its consumer, for the request.
struct Said {
    request_id: String,
    format: &'static str,
    audience: String,
    recipient: String,
}

impl Said {
    fn answering(request_id: &str) -> Self {
        let base = format!("{ISSUER}/broker/corp/saml");
        Said {
            request_id: request_id.to_owned(),
            format: PERSISTENT,
            audience: format!("{base}/metadata"),
            recipient: format!("{base}/acs"),
        }
    }
}

/// The answer a provider posts: a success naming `AAdzZWNyZXQx` in an assertion of
/// its own identifier, signed with `key`, encoded as the POST binding carries it.
fn answer(key: &RsaKeyPair, said: &Said) -> String {
    let crypto = provider();
    let instant = |offset: i64| {
        (Utc::now() + Duration::seconds(offset))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    let (now, closing) = (instant(0), instant(300));
    let Said {
        request_id,
        format,
        audience,
        recipient,
    } = said;
    let response = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response{request_id}" Version="2.0" IssueInstant="{now}" Destination="{recipient}" InResponseTo="{request_id}"><saml:Issuer>https://idp.test/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion{request_id}" Version="2.0" IssueInstant="{now}"><saml:Issuer>https://idp.test/metadata</saml:Issuer><saml:Subject><saml:NameID Format="{format}">AAdzZWNyZXQx</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{closing}" Recipient="{recipient}" InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{now}" NotOnOrAfter="{closing}"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_session-at-idp"/></saml:Assertion></samlp:Response>"#
    );
    let private = PrivateKey::from_der(key.to_der_private_key());
    let signed = saml::dsig::sign_enveloped(
        &crypto,
        &response,
        &format!("_assertion{request_id}"),
        SignAlg::Rs256,
        &|octets| crypto.signer().sign(SignAlg::Rs256, &private, octets).ok(),
    )
    .expect("the assertion signed");
    data_encoding::BASE64.encode(signed.as_bytes())
}

async fn provision_keyring(fixture: &Fixture, envelope: &Envelope) {
    let transaction = fixture.scoped(&tenant()).await;
    keyring::provision(&transaction, envelope, "acme", "main")
        .await
        .expect("a keyring");
    transaction.commit().await.expect("committed");
}

/// Open a request for `corp` under `request_id`, for the browser that left.
async fn open_request(fixture: &Fixture, request_id: &str) {
    let transaction = fixture.scoped(&tenant()).await;
    store::providers::saml_brokering::open_login_request(
        &transaction,
        &SamlLoginRequest {
            request_id: request_id.to_owned(),
            provider_alias: "corp".to_owned(),
            auth_session: THE_BROWSER.to_owned(),
            expires_at: Utc::now() + Duration::minutes(10),
        },
    )
    .await
    .expect("a request opened");
    transaction.commit().await.expect("committed");
}

/// Take `posted` as `browser` in a transaction of its own, committed only when the
/// answer is taken, as the consumer commits.
async fn take(
    fixture: &Fixture,
    envelope: &Envelope,
    upstream: &SamlUpstream,
    posted: &str,
    browser: &str,
) -> Result<SamlAnswer, Untaken> {
    let crypto = provider();
    let transaction = fixture.scoped(&tenant()).await;
    let ring = keyring::load(&transaction, envelope, "acme", "main")
        .await
        .expect("the realm's keyring");
    let signing = Signing {
        provider: &crypto,
        ring: &ring,
        envelope,
    };
    let taken = take_answer(
        &transaction,
        &signing,
        upstream,
        ISSUER,
        "corp",
        posted,
        browser,
        Utc::now(),
    )
    .await;
    if taken.is_ok() {
        transaction.commit().await.expect("committed");
    }
    taken
}

/// An answer is taken for the browser that left with its request, and once: one
/// naming no request is refused as such without touching the request left open,
/// another browser is refused and leaves the request open, the answer taken spends
/// it, and the same answer to a request opened again under that identifier was
/// already taken. An entity identifier an administrator set is the audience an
/// answer is held to.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_answer_is_taken_once_for_the_browser_that_left() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    provision_keyring(&fixture, &envelope).await;
    let identity_provider = RsaKeyPair::generate(2048).expect("an RSA key");
    let corp = upstream(&identity_provider, &[]);
    let posted = answer(&identity_provider, &Said::answering("_request"));
    open_request(&fixture, "_request").await;

    let unsolicited = String::from_utf8(
        data_encoding::BASE64
            .decode(posted.as_bytes())
            .expect("base64"),
    )
    .expect("UTF-8")
    .replacen(r#" InResponseTo="_request""#, "", 1);
    assert_eq!(
        take(
            &fixture,
            &envelope,
            &corp,
            &data_encoding::BASE64.encode(unsolicited.as_bytes()),
            THE_BROWSER
        )
        .await
        .err(),
        Some(Untaken::NoOpenRequest)
    );

    assert_eq!(
        take(&fixture, &envelope, &corp, &posted, "another-browser")
            .await
            .err(),
        Some(Untaken::OtherBrowser)
    );
    let taken = take(&fixture, &envelope, &corp, &posted, THE_BROWSER)
        .await
        .expect("the answer taken");
    assert_eq!(
        (
            taken.request.request_id.as_str(),
            taken.arrival.external_user_id.as_str(),
            taken.accepted.session_index.as_deref(),
        ),
        ("_request", "AAdzZWNyZXQx", Some("_session-at-idp"))
    );
    assert_eq!(
        take(&fixture, &envelope, &corp, &posted, THE_BROWSER)
            .await
            .err(),
        Some(Untaken::NoOpenRequest)
    );
    open_request(&fixture, "_request").await;
    assert_eq!(
        take(&fixture, &envelope, &corp, &posted, THE_BROWSER)
            .await
            .err(),
        Some(Untaken::Replayed)
    );

    let overridden = upstream(&identity_provider, &[("sp_entity_id", "urn:corp:saffui")]);
    open_request(&fixture, "_overridden").await;
    let to_the_default = answer(&identity_provider, &Said::answering("_overridden"));
    assert_eq!(
        take(
            &fixture,
            &envelope,
            &overridden,
            &to_the_default,
            THE_BROWSER
        )
        .await
        .err(),
        Some(Untaken::Refused(Refused::WrongAudience))
    );
    let to_the_override = answer(
        &identity_provider,
        &Said {
            audience: "urn:corp:saffui".to_owned(),
            ..Said::answering("_overridden")
        },
    );
    assert!(
        take(
            &fixture,
            &envelope,
            &overridden,
            &to_the_override,
            THE_BROWSER
        )
        .await
        .is_ok()
    );
}

/// An answer that does not hold is refused, each for what failed: signed with a key
/// the provider does not sign with, addressed to another entity, sent to another
/// address, naming the person by a name that is not persistent, not a message at
/// all, or answering a request never opened.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_answer_that_does_not_hold_is_refused() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    provision_keyring(&fixture, &envelope).await;
    let identity_provider = RsaKeyPair::generate(2048).expect("an RSA key");
    let stranger = RsaKeyPair::generate(2048).expect("another RSA key");
    let corp = upstream(&identity_provider, &[]);

    let cases = [
        (
            "_stranger",
            answer(&stranger, &Said::answering("_stranger")),
            Untaken::Refused(Refused::Unverified(Unverified::Untrusted)),
        ),
        (
            "_audience",
            answer(
                &identity_provider,
                &Said {
                    audience: "https://elsewhere.test/metadata".to_owned(),
                    ..Said::answering("_audience")
                },
            ),
            Untaken::Refused(Refused::WrongAudience),
        ),
        (
            "_recipient",
            answer(
                &identity_provider,
                &Said {
                    recipient: "https://elsewhere.test/acs".to_owned(),
                    ..Said::answering("_recipient")
                },
            ),
            Untaken::Refused(Refused::WrongDestination),
        ),
        (
            "_transient",
            answer(
                &identity_provider,
                &Said {
                    format: TRANSIENT,
                    ..Said::answering("_transient")
                },
            ),
            Untaken::Unnamed,
        ),
        ("_unreadable", "not base64!".to_owned(), Untaken::Unreadable),
    ];
    for (request_id, _, _) in &cases {
        open_request(&fixture, request_id).await;
    }
    for (request_id, posted, refused) in cases {
        assert_eq!(
            take(&fixture, &envelope, &corp, &posted, THE_BROWSER)
                .await
                .err(),
            Some(refused),
            "{request_id}"
        );
    }
    let never_opened = answer(&identity_provider, &Said::answering("_never-opened"));
    assert_eq!(
        take(&fixture, &envelope, &corp, &never_opened, THE_BROWSER)
            .await
            .err(),
        Some(Untaken::NoOpenRequest)
    );
}
