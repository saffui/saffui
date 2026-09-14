use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::provider::{PrivateKey, PublicKey, SignAlg};
use crypto::x509::{CertifiedKey, Issuance, issue_certificate, read_certificate_facts};
use deadpool_postgres::Transaction;
use models::entities::attributes::AttributesMap;
use models::entities::authz::IdentityProviderModel;
use models::entities::keys::{JweAlgorithm, KeyUse, RealmEncryptionKey, RealmSigningKey};
use saml::metadata::{
    IdentityProvider, Misread, ServiceProvider, describe_service_provider, read_identity_provider,
};
use saml::xml::Limits;
use store::providers::realm_keys;

use crate::brokering::text;
use crate::grant::Signing;

const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const MINIMUM_RSA_BITS: u32 = 2048;
/// Core §8.3.6 bounds an entity identifier to 1024 characters.
const ENTITY_ID_MAX_CHARS: usize = 1024;

/// Whether a provider's configuration names SAML as its protocol.
pub fn is_saml(provider: &IdentityProviderModel) -> bool {
    provider
        .configs
        .as_ref()
        .and_then(|bag| text(bag, "protocol"))
        == Some("saml")
}

/// A SAML identity provider as a realm brokers it, read from what an administrator
/// saved.
#[derive(Debug, Clone)]
pub struct SamlUpstream {
    pub identity_provider: IdentityProvider,
    /// Persistent unless the administrator asked for another format.
    pub name_id_format: String,
    /// The attribute naming the person when the name identifier is not persistent.
    pub principal_attribute: Option<String>,
    pub username_attribute: Option<String>,
    pub email_attribute: Option<String>,
    /// The entity identifier the realm answers to here, when an administrator
    /// overrode the one its alias gives, as a migration needs.
    pub sp_entity_id: Option<String>,
}

/// Why a SAML provider's configuration cannot be used, each naming what failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnusableSaml {
    #[error("the provider names no {0}")]
    Missing(&'static str),
    #[error("the identity provider's metadata cannot be used: {0}")]
    Metadata(Misread),
    #[error("the identity provider's {0} is not an https address")]
    Insecure(&'static str),
    #[error("a signing key of the identity provider is too weak to trust: {0}")]
    WeakKey(&'static str),
    #[error(
        "a name identifier format other than persistent needs principal_attribute, since such a name can be given to someone else"
    )]
    NoPrincipal,
    #[error(
        "principal_attribute names the email attribute, and an address can be given to someone else"
    )]
    EmailAsPrincipal,
    #[error("{0} is not an entity identifier")]
    NotAnEntity(&'static str),
}

impl SamlUpstream {
    /// Read the stored bag the way a login will read it, refusing at the door what
    /// cannot be used: metadata that does not read, an address in clear off this
    /// machine, a signing key too weak to trust, or a name that can be given to
    /// someone else with nothing steadier beside it.
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, UnusableSaml> {
        let empty = AttributesMap::new();
        let bag = provider.configs.as_ref().unwrap_or(&empty);
        let metadata = text(bag, "idp_metadata").ok_or(UnusableSaml::Missing("idp_metadata"))?;
        let identity_provider =
            read_identity_provider(metadata, Limits::MESSAGE).map_err(UnusableSaml::Metadata)?;

        if !commons::address::is_https_or_loopback(&identity_provider.single_sign_on) {
            return Err(UnusableSaml::Insecure("single sign-on address"));
        }
        if let Some(logout) = &identity_provider.single_logout
            && (!commons::address::is_https_or_loopback(&logout.location)
                || logout
                    .response_location
                    .as_deref()
                    .is_some_and(|held| !commons::address::is_https_or_loopback(held)))
        {
            return Err(UnusableSaml::Insecure("single logout address"));
        }

        for certificate in &identity_provider.signing_certificates {
            let facts = read_certificate_facts(certificate)
                .ok_or(UnusableSaml::WeakKey("a certificate that does not read"))?;
            let weakness = match facts.key {
                CertifiedKey::Rsa { bits } if bits < MINIMUM_RSA_BITS => {
                    Some("RSA below 2048 bits")
                }
                CertifiedKey::Rsa { .. } => None,
                CertifiedKey::Ec { curve } => curve
                    .is_none()
                    .then_some("a curve other than P-256, P-384 or P-521"),
                CertifiedKey::Other => Some("a key of a kind not verified here"),
            };
            if let Some(weakness) = weakness {
                return Err(UnusableSaml::WeakKey(weakness));
            }
        }

        let name_id_format = text(bag, "name_id_format")
            .filter(|format| !format.is_empty())
            .unwrap_or(PERSISTENT)
            .to_owned();
        let principal_attribute = read_given(bag, "principal_attribute");
        let email_attribute = read_given(bag, "email_attribute");
        if name_id_format != PERSISTENT && principal_attribute.is_none() {
            return Err(UnusableSaml::NoPrincipal);
        }
        if principal_attribute.is_some() && principal_attribute == email_attribute {
            return Err(UnusableSaml::EmailAsPrincipal);
        }
        let sp_entity_id = read_given(bag, "sp_entity_id");
        if sp_entity_id.as_deref().is_some_and(|entity| {
            entity.trim() != entity || entity.chars().count() > ENTITY_ID_MAX_CHARS
        }) {
            return Err(UnusableSaml::NotAnEntity("sp_entity_id"));
        }

        Ok(Self {
            identity_provider,
            name_id_format,
            principal_attribute,
            username_attribute: read_given(bag, "username_attribute"),
            email_attribute,
            sp_entity_id,
        })
    }
}

/// A value the administrator gave, when they gave one: empty is none.
fn read_given(bag: &AttributesMap, key: &str) -> Option<String> {
    text(bag, key)
        .filter(|given| !given.is_empty())
        .map(str::to_owned)
}

/// RFC 5280 §4.1.2.5: the instant a certificate with no well-defined end carries.
const NO_WELL_DEFINED_END: i64 = 253_402_300_799;
/// The realm encryption keys a SAML provider can encrypt to, in the order offered.
const RSA_ENCRYPTION: [JweAlgorithm; 4] = [
    JweAlgorithm::RsaOaep256,
    JweAlgorithm::RsaOaep,
    JweAlgorithm::RsaOaep384,
    JweAlgorithm::RsaOaep512,
];

/// Why a realm could not describe itself to a SAML provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undescribed {
    #[error("the realm holds no active RSA key to sign with")]
    NoSigningKey,
    #[error("a realm key could not be read as RSA")]
    UnreadableKey,
    #[error("a certificate could not be issued for a realm key")]
    Unissued,
    #[error("the store could not be read")]
    Backend,
}

/// Where a realm takes one SAML provider's messages: the base of its metadata,
/// assertion consumer and logout addresses, under the realm's issuer.
pub fn compose_saml_address(issuer: &str, alias: &str) -> String {
    format!("{issuer}/broker/{alias}/saml")
}

/// The realm keys a SAML provider is shown: the active RSA key the realm signs
/// with, and an active RSA key assertions may be encrypted to when it holds one.
pub async fn load_published_keys(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
) -> Result<(RealmSigningKey, Option<RealmEncryptionKey>), Undescribed> {
    let signing_key = realm_keys::active(
        transaction,
        signing.ring,
        signing.envelope,
        KeyUse::Sig,
        Some(SignAlg::Rs256),
    )
    .await
    .map_err(|_| Undescribed::Backend)?
    .ok_or(Undescribed::NoSigningKey)?;
    for algorithm in RSA_ENCRYPTION {
        let found =
            realm_keys::active_encryption(transaction, signing.ring, signing.envelope, algorithm)
                .await
                .map_err(|_| Undescribed::Backend)?;
        if found.is_some() {
            return Ok((signing_key, found));
        }
    }
    Ok((signing_key, None))
}

/// The realm's metadata as this provider's service provider: the entity identifier
/// it answers to, where responses and logout come, and a certificate for each of
/// its keys issued under its signing key. The same keys give the same bytes, so
/// nothing is stored and a provider that imported them keeps finding them.
pub fn describe_realm(
    upstream: &SamlUpstream,
    issuer: &str,
    alias: &str,
    realm_id: &str,
    signing_key: &RealmSigningKey,
    encryption_key: Option<&RealmEncryptionKey>,
) -> Result<String, Undescribed> {
    let signer =
        RsaKeyPair::from_pem(&signing_key.private_pem).map_err(|_| Undescribed::UnreadableKey)?;
    let signing_certificate = issue_key_certificate(
        &signer,
        &signer,
        realm_id,
        &signing_key.kid,
        signing_key.created_at,
    )?;
    let encryption_certificates = match encryption_key {
        Some(key) => {
            let sealed_to =
                RsaKeyPair::from_pem(&key.private_pem).map_err(|_| Undescribed::UnreadableKey)?;
            vec![issue_key_certificate(
                &sealed_to,
                &signer,
                realm_id,
                &key.kid,
                signing_key.created_at,
            )?]
        }
        None => Vec::new(),
    };
    let base = compose_saml_address(issuer, alias);
    let entity_id = upstream
        .sp_entity_id
        .clone()
        .unwrap_or_else(|| format!("{base}/metadata"));
    Ok(describe_service_provider(&ServiceProvider {
        entity_id: &entity_id,
        assertion_consumer: &format!("{base}/acs"),
        single_logout: &format!("{base}/slo"),
        name_id_format: Some(upstream.name_id_format.as_str()),
        signing_certificates: &[signing_certificate],
        encryption_certificates: &encryption_certificates,
    }))
}

/// A certificate for the subject's key under the signer's, named for the realm, its
/// serial drawn from the key's thumbprint and its start the signing key's.
fn issue_key_certificate(
    subject: &RsaKeyPair,
    signer: &RsaKeyPair,
    realm_id: &str,
    kid: &str,
    not_before: i64,
) -> Result<Vec<u8>, Undescribed> {
    issue_certificate(&Issuance {
        subject_key: &PublicKey::from_der(subject.to_der_public_key()),
        subject_name: realm_id,
        issuer_key: &PrivateKey::from_der(signer.to_der_private_key()),
        issuer_name: realm_id,
        serial: &derive_serial(kid),
        not_before,
        not_after: NO_WELL_DEFINED_END,
    })
    .ok_or(Undescribed::Unissued)
}

/// Sixteen octets of a key's thumbprint, the top bit cleared and the next one set,
/// so the serial is positive, never zero and within the 20 octets RFC 5280 allows.
fn derive_serial(kid: &str) -> Vec<u8> {
    let mut serial = data_encoding::BASE64URL_NOPAD
        .decode(kid.as_bytes())
        .unwrap_or_else(|_| kid.as_bytes().to_vec());
    serial.resize(16, 0);
    serial[0] = (serial[0] & 0x7f) | 0x40;
    serial
}

#[cfg(test)]
mod tests {
    use super::{SamlUpstream, UnusableSaml, is_saml};
    use super::{Undescribed, compose_saml_address, describe_realm};
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
    use crypto::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::SignAlg;
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Issuance, issue_certificate};
    use models::auditable::AuditableModel;
    use models::entities::attributes::{AttributeValue, AttributesMap};
    use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
    use models::entities::keys::{
        JweAlgorithm, KeyStatus, KeyUse, RealmEncryptionKey, RealmSigningKey,
    };
    use saml::metadata::Misread;
    use saml::xml::{Limits, read_message};

    const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    fn rsa_key(bits: u32) -> RsaKeyPair {
        RsaKeyPair::generate(bits).expect("an RSA key")
    }

    /// A certificate for the subject's key, issued by the crypto crate under an RSA
    /// issuer, in base64 as metadata carries it.
    fn certificate_for(subject: &dyn KeyPair, issuer: &RsaKeyPair) -> String {
        let der = issue_certificate(&Issuance {
            subject_key: &PublicKey::from_der(subject.to_der_public_key()),
            subject_name: "idp.test",
            issuer_key: &PrivateKey::from_der(issuer.to_der_private_key()),
            issuer_name: "idp.test",
            serial: &[1],
            not_before: 1_789_372_800,
            not_after: 2_104_992_000,
        })
        .expect("a certificate");
        data_encoding::BASE64.encode(&der)
    }

    /// Metadata signing with one certificate, at the addresses given.
    fn metadata(certificate: &str, sign_on: &str, logout: &str, answers: &str) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{logout}" ResponseLocation="{answers}"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sign_on}"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        )
    }

    fn secure_metadata(certificate: &str) -> String {
        metadata(
            certificate,
            "https://idp.test/sso",
            "https://idp.test/slo",
            "https://idp.test/slo/answers",
        )
    }

    fn provider(said: &[(&str, &str)]) -> IdentityProviderModel {
        let configs: AttributesMap = said
            .iter()
            .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).to_owned())))
            .collect();
        IdentityProviderMutationModel {
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
            AuditableModel::from_creator("local".into(), "root".into()),
        )
    }

    fn saml_provider(idp_metadata: &str, more: &[(&str, &str)]) -> IdentityProviderModel {
        let mut said = vec![("protocol", "saml"), ("idp_metadata", idp_metadata)];
        said.extend_from_slice(more);
        provider(&said)
    }

    /// A SAML provider is read with what the administrator chose, or with a
    /// persistent name and nothing else when they chose nothing, an empty value
    /// counting as none; an elliptic key on a named curve and loopback addresses in
    /// clear are taken, and only a provider naming SAML is read as one.
    #[test]
    fn a_saml_provider_is_read_with_what_the_administrator_chose() {
        let issuer = rsa_key(2048);
        let strong = certificate_for(&issuer, &issuer);
        let elliptic = certificate_for(
            &EcKeyPair::generate(EcCurve::P256).expect("a P-256 key"),
            &issuer,
        );
        let upstream = SamlUpstream::parse(&saml_provider(&secure_metadata(&strong), &[]))
            .expect("a usable provider");
        assert_eq!(
            upstream.identity_provider.entity_id,
            "https://idp.test/metadata"
        );
        assert_eq!(upstream.name_id_format, PERSISTENT);
        assert_eq!(
            (
                upstream.principal_attribute,
                upstream.username_attribute,
                upstream.email_attribute,
                upstream.sp_entity_id
            ),
            (None, None, None, None)
        );

        let chosen = SamlUpstream::parse(&saml_provider(
            &secure_metadata(&strong),
            &[
                ("name_id_format", TRANSIENT),
                ("principal_attribute", "employeeNumber"),
                ("username_attribute", "uid"),
                ("email_attribute", "mail"),
                ("sp_entity_id", "https://old.example/sp"),
            ],
        ))
        .expect("a usable provider");
        assert_eq!(chosen.name_id_format, TRANSIENT);
        assert_eq!(
            (
                chosen.principal_attribute.as_deref(),
                chosen.username_attribute.as_deref(),
                chosen.email_attribute.as_deref(),
                chosen.sp_entity_id.as_deref()
            ),
            (
                Some("employeeNumber"),
                Some("uid"),
                Some("mail"),
                Some("https://old.example/sp")
            )
        );

        let unsaid = SamlUpstream::parse(&saml_provider(
            &secure_metadata(&strong),
            &[("name_id_format", ""), ("principal_attribute", "")],
        ))
        .expect("a usable provider");
        assert_eq!(
            (unsaid.name_id_format.as_str(), unsaid.principal_attribute),
            (PERSISTENT, None)
        );

        for usable in [
            secure_metadata(&elliptic),
            metadata(
                &strong,
                "http://localhost:8080/sso",
                "http://127.0.0.1/slo",
                "http://[::1]/answers",
            ),
        ] {
            assert!(SamlUpstream::parse(&saml_provider(&usable, &[])).is_ok());
        }

        assert!(is_saml(&saml_provider("", &[])));
        assert!(!is_saml(&provider(&[("protocol", "oidc")])));
        assert!(!is_saml(&provider(&[])));
    }

    /// What a login could not use is refused at the door with its reason: no
    /// metadata, metadata that is no identity provider, an address in clear off
    /// this machine, a key too weak or of a kind not verified here, a name that can
    /// be given to someone else with no principal beside it, the email as the
    /// principal, and an entity identifier that is none.
    #[test]
    fn what_a_login_cannot_use_is_refused_at_the_door() {
        let issuer = rsa_key(2048);
        let strong = certificate_for(&issuer, &issuer);
        let short = certificate_for(&rsa_key(1024), &issuer);
        let unnamed_curve = certificate_for(
            &EcKeyPair::generate(EcCurve::Secp256k1).expect("a secp256k1 key"),
            &issuer,
        );
        let edwards = certificate_for(
            &EdKeyPair::generate(EdCurve::Ed25519).expect("an Ed25519 key"),
            &issuer,
        );
        let secure = secure_metadata(&strong);
        let long = format!("https://sp.example/{}", "a".repeat(1006));
        for (refused, reason) in [
            (
                provider(&[("protocol", "saml")]),
                UnusableSaml::Missing("idp_metadata"),
            ),
            (
                saml_provider(
                    r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>"#,
                    &[],
                ),
                UnusableSaml::Metadata(Misread::NotOneEntity),
            ),
            (
                saml_provider(
                    &metadata(
                        &strong,
                        "http://idp.test/sso",
                        "https://idp.test/slo",
                        "https://idp.test/slo/answers",
                    ),
                    &[],
                ),
                UnusableSaml::Insecure("single sign-on address"),
            ),
            (
                saml_provider(
                    &metadata(
                        &strong,
                        "https://idp.test/sso",
                        "http://idp.test/slo",
                        "https://idp.test/slo/answers",
                    ),
                    &[],
                ),
                UnusableSaml::Insecure("single logout address"),
            ),
            (
                saml_provider(
                    &metadata(
                        &strong,
                        "https://idp.test/sso",
                        "https://idp.test/slo",
                        "http://idp.test/slo/answers",
                    ),
                    &[],
                ),
                UnusableSaml::Insecure("single logout address"),
            ),
            (
                saml_provider(&secure_metadata(&short), &[]),
                UnusableSaml::WeakKey("RSA below 2048 bits"),
            ),
            (
                saml_provider(&secure_metadata(&unnamed_curve), &[]),
                UnusableSaml::WeakKey("a curve other than P-256, P-384 or P-521"),
            ),
            (
                saml_provider(&secure_metadata(&edwards), &[]),
                UnusableSaml::WeakKey("a key of a kind not verified here"),
            ),
            (
                saml_provider(&secure, &[("name_id_format", TRANSIENT)]),
                UnusableSaml::NoPrincipal,
            ),
            (
                saml_provider(
                    &secure,
                    &[("principal_attribute", "mail"), ("email_attribute", "mail")],
                ),
                UnusableSaml::EmailAsPrincipal,
            ),
            (
                saml_provider(&secure, &[("sp_entity_id", " https://sp.example")]),
                UnusableSaml::NotAnEntity("sp_entity_id"),
            ),
            (
                saml_provider(&secure, &[("sp_entity_id", &long)]),
                UnusableSaml::NotAnEntity("sp_entity_id"),
            ),
        ] {
            assert_eq!(SamlUpstream::parse(&refused).err(), Some(reason));
        }
        assert!(
            SamlUpstream::parse(&saml_provider(&secure, &[("sp_entity_id", &long[..1024])]))
                .is_ok()
        );
    }

    /// The realm describes itself to a provider under the entity identifier its
    /// alias gives, or the one an administrator set, with its consumer, its logout
    /// and the format asked, a certificate for its signing key issued by that key and
    /// one for its encryption key issued by the signing key, the same bytes every
    /// time; without an encryption key it offers none, and a key that is not RSA is
    /// not described.
    #[test]
    fn a_realm_describes_itself_with_certificates_for_its_keys() {
        let provider_key = rsa_key(2048);
        let provider_certificate = certificate_for(&provider_key, &provider_key);
        let upstream =
            SamlUpstream::parse(&saml_provider(&secure_metadata(&provider_certificate), &[]))
                .expect("a usable provider");
        let signer = rsa_key(2048);
        let sealed_to = rsa_key(2048);
        let signing_key = RealmSigningKey {
            tenant: "acme".into(),
            realm_id: "main".into(),
            kid: "8PDw8PDw8PDw8PDw8PDw8PDw".into(),
            algorithm: SignAlg::Rs256,
            key_use: KeyUse::Sig,
            status: KeyStatus::Active,
            priority: 100,
            private_pem: signer.to_pem_private_key(),
            public_jwk: serde_json::Value::Null,
            created_at: 1_789_372_800,
        };
        let encryption_key = RealmEncryptionKey {
            kid: "ZW5jcnlwdGlvbi1rZXktdGh1bWJwcmludC0wMDAwMA".into(),
            algorithm: JweAlgorithm::RsaOaep256,
            private_pem: sealed_to.to_pem_private_key(),
            public_jwk: serde_json::Value::Null,
        };
        let issuer = "https://id.test/realms/main";
        let base = "https://id.test/realms/main/broker/corp/saml";
        assert_eq!(compose_saml_address(issuer, "corp"), base);

        let written = describe_realm(
            &upstream,
            issuer,
            "corp",
            "main",
            &signing_key,
            Some(&encryption_key),
        )
        .expect("a description");
        assert_eq!(
            describe_realm(
                &upstream,
                issuer,
                "corp",
                "main",
                &signing_key,
                Some(&encryption_key)
            ),
            Ok(written.clone())
        );
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let entity = document.root_element();
        assert_eq!(
            entity.attribute("entityID"),
            Some(format!("{base}/metadata").as_str())
        );
        let role = entity.first_element_child().expect("a role");
        let located = |name: &str| {
            role.children()
                .filter(|node| node.tag_name().name() == name)
                .filter_map(|node| node.attribute("Location"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(located("AssertionConsumerService"), [format!("{base}/acs")]);
        assert_eq!(
            located("SingleLogoutService"),
            [format!("{base}/slo"), format!("{base}/slo")]
        );
        let formats: Vec<_> = role
            .children()
            .filter(|node| node.tag_name().name() == "NameIDFormat")
            .filter_map(|node| node.text())
            .collect();
        assert_eq!(formats, [upstream.name_id_format.as_str()]);

        let published = |usage: &str| {
            role.children()
                .filter(|node| node.attribute("use") == Some(usage))
                .flat_map(|node| node.descendants())
                .filter(|node| node.tag_name().name() == "X509Certificate")
                .filter_map(|node| node.text())
                .map(|text| {
                    data_encoding::BASE64
                        .decode(text.as_bytes())
                        .expect("base64")
                })
                .collect::<Vec<_>>()
        };
        let issued_by_signer = |subject: &RsaKeyPair, kid: &str| {
            issue_certificate(&Issuance {
                subject_key: &PublicKey::from_der(subject.to_der_public_key()),
                subject_name: "main",
                issuer_key: &PrivateKey::from_der(signer.to_der_private_key()),
                issuer_name: "main",
                serial: &super::derive_serial(kid),
                not_before: 1_789_372_800,
                not_after: 253_402_300_799,
            })
            .expect("a certificate")
        };
        assert_eq!(
            published("signing"),
            [issued_by_signer(&signer, &signing_key.kid)]
        );
        assert_eq!(
            published("encryption"),
            [issued_by_signer(&sealed_to, &encryption_key.kid)]
        );
        let serial = super::derive_serial(&signing_key.kid);
        assert_eq!((serial.len(), serial[0] & 0xc0), (16, 0x40));

        let overridden = SamlUpstream {
            sp_entity_id: Some("https://old.example/sp".into()),
            ..upstream.clone()
        };
        let written = describe_realm(&overridden, issuer, "corp", "main", &signing_key, None)
            .expect("a description");
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        assert_eq!(
            document.root_element().attribute("entityID"),
            Some("https://old.example/sp")
        );
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.tag_name().name() == "KeyDescriptor")
                .count(),
            1
        );

        let elliptic = RealmSigningKey {
            private_pem: EcKeyPair::generate(EcCurve::P256)
                .expect("a P-256 key")
                .to_pem_private_key(),
            ..signing_key.clone()
        };
        assert_eq!(
            describe_realm(&upstream, issuer, "corp", "main", &elliptic, None),
            Err(Undescribed::UnreadableKey)
        );
    }
}
