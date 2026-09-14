use crypto::x509::{CertifiedKey, read_certificate_facts};
use models::entities::attributes::AttributesMap;
use models::entities::authz::IdentityProviderModel;
use saml::metadata::{IdentityProvider, Misread, read_identity_provider};
use saml::xml::Limits;

use crate::brokering::text;

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

#[cfg(test)]
mod tests {
    use super::{SamlUpstream, UnusableSaml, is_saml};
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
    use crypto::jose::jwk::alg::ed::{EdCurve, EdKeyPair};
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Issuance, issue_certificate};
    use models::auditable::AuditableModel;
    use models::entities::attributes::{AttributeValue, AttributesMap};
    use models::entities::authz::{IdentityProviderModel, IdentityProviderMutationModel};
    use saml::metadata::Misread;

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
}
