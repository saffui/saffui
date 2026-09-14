use roxmltree::Node;

use crate::xml::{
    Limits, Unreadable, base64_content_of, children_named, is_named, push_attribute, push_text,
    read_message, strict_text_of,
};

const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// Authenticated content ciphers only, then the key transports decryption takes.
const ENCRYPTION_METHODS_OFFERED: [&str; 4] = [
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
];
/// Core §8.3.6 bounds an entity identifier to 1024 characters.
const ENTITY_ID_MAX_CHARS: usize = 1024;

/// Why an identity provider's metadata was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Misread {
    #[error("the metadata is not readable XML")]
    Unreadable(#[from] Unreadable),
    #[error("the metadata does not describe exactly one entity")]
    NotOneEntity,
    #[error("the entity is not a SAML 2.0 identity provider")]
    NotAnIdentityProvider,
    #[error("the identity provider offers no sign-on over the Redirect binding")]
    NoRedirectSignOn,
    #[error("the identity provider names no certificate to verify its signatures with")]
    NoSigningCertificate,
    #[error("a certificate in the metadata cannot be read")]
    UnreadableCertificate,
    #[error("the metadata is not shaped as SAML 2.0 metadata")]
    Misshapen,
}

/// An endpoint a provider takes messages at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub location: String,
    /// Where responses go, when not to the location itself.
    pub response_location: Option<String>,
}

/// What a realm keeps of an identity provider, read from its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProvider {
    pub entity_id: String,
    /// Where authentication requests go, over the Redirect binding.
    pub single_sign_on: String,
    /// Where logout messages go over the Redirect binding, when the provider takes them.
    pub single_logout: Option<Endpoint>,
    /// DER certificates whose keys may verify the provider's signatures.
    pub signing_certificates: Vec<Vec<u8>>,
    pub name_id_formats: Vec<String>,
}

/// What a realm says of itself to one identity provider, as the service provider
/// of one broker.
#[derive(Debug, Clone, Copy)]
pub struct ServiceProvider<'a> {
    pub entity_id: &'a str,
    /// Where responses come back, over the POST binding.
    pub assertion_consumer: &'a str,
    /// Where logout messages come, over the Redirect and POST bindings.
    pub single_logout: &'a str,
    pub name_id_format: Option<&'a str>,
    /// DER certificates of the keys requests are signed with.
    pub signing_certificates: &'a [Vec<u8>],
    /// DER certificates of the keys assertions may be encrypted to.
    pub encryption_certificates: &'a [Vec<u8>],
}

/// Read an identity provider from its SAML 2.0 metadata as an administrator pastes
/// it: one entity, one identity provider role for SAML 2.0, a sign-on over the
/// Redirect binding and at least one certificate to verify signatures with.
///
/// A key for encryption only is never taken to verify a signature. A signature on
/// the metadata itself is not checked: the administrator chose what to paste.
pub fn read_identity_provider(text: &str, limits: Limits) -> Result<IdentityProvider, Misread> {
    let document = read_message(text, limits)?;
    let entity = document.root_element();
    if !is_named(entity, METADATA, "EntityDescriptor") {
        return Err(Misread::NotOneEntity);
    }
    let entity_id = entity.attribute("entityID").unwrap_or_default();
    if entity_id.is_empty()
        || entity_id.trim() != entity_id
        || entity_id.chars().count() > ENTITY_ID_MAX_CHARS
    {
        return Err(Misread::Misshapen);
    }

    let mut roles = children_named(entity, METADATA, "IDPSSODescriptor").filter(|role| {
        role.attribute("protocolSupportEnumeration")
            .is_some_and(|protocols| protocols.split_whitespace().any(|named| named == PROTOCOL))
    });
    let role = roles.next().ok_or(Misread::NotAnIdentityProvider)?;
    if roles.next().is_some() {
        return Err(Misread::Misshapen);
    }

    let single_sign_on = redirect_endpoint_of(role, "SingleSignOnService")?
        .ok_or(Misread::NoRedirectSignOn)?
        .location;
    let single_logout = redirect_endpoint_of(role, "SingleLogoutService")?;

    let mut signing_certificates: Vec<Vec<u8>> = Vec::new();
    for key in children_named(role, METADATA, "KeyDescriptor") {
        let signs = match key.attribute("use") {
            None | Some("signing") => true,
            Some("encryption") => false,
            Some(_) => return Err(Misread::Misshapen),
        };
        let certificate = certificate_of(key)?;
        if !signs {
            continue;
        }
        if let Some(certificate) = certificate.filter(|held| !signing_certificates.contains(held)) {
            signing_certificates.push(certificate);
        }
    }
    if signing_certificates.is_empty() {
        return Err(Misread::NoSigningCertificate);
    }

    let name_id_formats = children_named(role, METADATA, "NameIDFormat")
        .map(|format| {
            strict_text_of(format)
                .filter(|text| !text.is_empty())
                .ok_or(Misread::Misshapen)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(IdentityProvider {
        entity_id: entity_id.to_owned(),
        single_sign_on,
        single_logout,
        signing_certificates,
        name_id_formats,
    })
}

/// The realm's metadata as that service provider: it signs its requests, wants
/// assertions signed, takes responses over POST and logout over Redirect and POST,
/// and offers only authenticated content ciphers for what is encrypted to it.
pub fn describe_service_provider(provider: &ServiceProvider<'_>) -> String {
    let mut xml = String::from(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#""#,
    );
    push_attribute(&mut xml, "entityID", provider.entity_id);
    xml.push_str(r#"><md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true""#);
    push_attribute(&mut xml, "protocolSupportEnumeration", PROTOCOL);
    xml.push('>');
    for certificate in provider.signing_certificates {
        push_key_descriptor(&mut xml, "signing", certificate, &[]);
    }
    for certificate in provider.encryption_certificates {
        push_key_descriptor(
            &mut xml,
            "encryption",
            certificate,
            &ENCRYPTION_METHODS_OFFERED,
        );
    }
    for binding in [REDIRECT_BINDING, POST_BINDING] {
        xml.push_str("<md:SingleLogoutService");
        push_attribute(&mut xml, "Binding", binding);
        push_attribute(&mut xml, "Location", provider.single_logout);
        xml.push_str("/>");
    }
    if let Some(format) = provider.name_id_format {
        xml.push_str("<md:NameIDFormat>");
        push_text(&mut xml, format);
        xml.push_str("</md:NameIDFormat>");
    }
    xml.push_str("<md:AssertionConsumerService");
    push_attribute(&mut xml, "Binding", POST_BINDING);
    push_attribute(&mut xml, "Location", provider.assertion_consumer);
    xml.push_str(r#" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>"#);
    xml
}

/// The first endpoint over the Redirect binding a role lists under `name`.
fn redirect_endpoint_of(
    role: Node<'_, '_>,
    name: &'static str,
) -> Result<Option<Endpoint>, Misread> {
    let Some(endpoint) = children_named(role, METADATA, name)
        .find(|endpoint| endpoint.attribute("Binding") == Some(REDIRECT_BINDING))
    else {
        return Ok(None);
    };
    let location = endpoint
        .attribute("Location")
        .filter(|held| !held.is_empty())
        .ok_or(Misread::Misshapen)?;
    let response_location = match endpoint.attribute("ResponseLocation") {
        Some("") => return Err(Misread::Misshapen),
        held => held.map(str::to_owned),
    };
    Ok(Some(Endpoint {
        location: location.to_owned(),
        response_location,
    }))
}

/// The one certificate a key descriptor holds, when it holds one.
fn certificate_of(key: Node<'_, '_>) -> Result<Option<Vec<u8>>, Misread> {
    let mut infos = children_named(key, XMLDSIG, "KeyInfo");
    let (Some(info), None) = (infos.next(), infos.next()) else {
        return Err(Misread::Misshapen);
    };
    let mut certificates = children_named(info, XMLDSIG, "X509Data")
        .flat_map(|data| children_named(data, XMLDSIG, "X509Certificate"));
    let certificate = match (certificates.next(), certificates.next()) {
        (None, _) => return Ok(None),
        (Some(certificate), None) => certificate,
        (Some(_), Some(_)) => return Err(Misread::Misshapen),
    };
    let der = base64_content_of(certificate).ok_or(Misread::UnreadableCertificate)?;
    crypto::x509::public_key_of(&der).ok_or(Misread::UnreadableCertificate)?;
    Ok(Some(der))
}

fn push_key_descriptor(xml: &mut String, usage: &str, certificate: &[u8], methods: &[&str]) {
    xml.push_str("<md:KeyDescriptor");
    push_attribute(xml, "use", usage);
    xml.push_str("><ds:KeyInfo><ds:X509Data><ds:X509Certificate>");
    xml.push_str(&data_encoding::BASE64.encode(certificate));
    xml.push_str("</ds:X509Certificate></ds:X509Data></ds:KeyInfo>");
    for method in methods {
        xml.push_str("<md:EncryptionMethod");
        push_attribute(xml, "Algorithm", method);
        xml.push_str("/>");
    }
    xml.push_str("</md:KeyDescriptor>");
}

#[cfg(test)]
mod tests {
    use super::{
        Endpoint, IdentityProvider, Misread, ServiceProvider, describe_service_provider,
        read_identity_provider,
    };
    use crate::testing::DrawnKey;
    use crate::xml::{Limits, read_message};
    use std::sync::LazyLock;

    static RSA: LazyLock<String> =
        LazyLock::new(|| DrawnKey::draw_rsa().issue_certificate_in_base64());
    static EC: LazyLock<String> =
        LazyLock::new(|| DrawnKey::draw_ec().issue_certificate_in_base64());
    const ENTITY_ID: &str = r#"entityID="https://idp.test/metadata""#;
    const REDIRECT_SIGN_ON: &str = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>"#;
    const REDIRECT_LOGOUT: &str = r#"<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/slo" ResponseLocation="https://idp.test/slo/answers"/>"#;

    fn der(certificate: &str) -> Vec<u8> {
        data_encoding::BASE64
            .decode(certificate.trim().as_bytes())
            .expect("base64")
    }

    /// A key descriptor as exporters write it, its certificate broken into lines.
    fn key(usage: &str, certificate: &str) -> String {
        let lines: Vec<&str> = certificate
            .trim()
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
            .collect();
        format!(
            "<md:KeyDescriptor{usage}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>\n{}\n</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
            lines.join("\n")
        )
    }

    /// An identity provider as most export theirs: SAML 1.1 beside 2.0, POST
    /// endpoints before Redirect ones, a format with space around it, a contact.
    fn metadata(keys: &str) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" {ENTITY_ID}>
  <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol
      urn:oasis:names:tc:SAML:2.0:protocol">
    {keys}
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/slo/post"/>
    {REDIRECT_LOGOUT}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>
      urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    </md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/sso/post"/>
    {REDIRECT_SIGN_ON}
  </md:IDPSSODescriptor>
  <md:ContactPerson contactType="technical"><md:EmailAddress>mailto:ops@idp.test</md:EmailAddress></md:ContactPerson>
</md:EntityDescriptor>"#
        )
    }

    /// An identity provider is read from its metadata: its Redirect sign-on and
    /// logout, its key for both uses and its formats, with an identifier as long as
    /// an entity identifier may be; without a Redirect logout it has none.
    #[test]
    fn an_identity_provider_is_read_from_its_metadata() {
        let plain = metadata(&key("", &RSA));
        assert_eq!(
            read_identity_provider(&plain, Limits::MESSAGE),
            Ok(IdentityProvider {
                entity_id: "https://idp.test/metadata".to_owned(),
                single_sign_on: "https://idp.test/sso".to_owned(),
                single_logout: Some(Endpoint {
                    location: "https://idp.test/slo".to_owned(),
                    response_location: Some("https://idp.test/slo/answers".to_owned()),
                }),
                signing_certificates: vec![der(&RSA)],
                name_id_formats: vec![
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned(),
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_owned(),
                ],
            })
        );

        let longest = format!(r#"entityID="https://idp.test/{}""#, "a".repeat(1007));
        let read = read_identity_provider(&plain.replacen(ENTITY_ID, &longest, 1), Limits::MESSAGE)
            .expect("an identity provider");
        assert_eq!(read.entity_id.chars().count(), 1024);

        let read = read_identity_provider(&plain.replacen(REDIRECT_LOGOUT, "", 1), Limits::MESSAGE)
            .expect("an identity provider");
        assert_eq!(read.single_logout, None);
    }

    /// Only a key that may sign is kept to verify signatures: one for signing and
    /// one for both uses, once each, and never one for encryption only.
    #[test]
    fn only_a_key_that_may_sign_is_kept_to_verify_signatures() {
        let signing_of = |keys: &[String]| {
            read_identity_provider(&metadata(&keys.concat()), Limits::MESSAGE)
                .map(|provider| provider.signing_certificates)
        };
        assert_eq!(
            signing_of(&[
                key(r#" use="encryption""#, &EC),
                key(r#" use="signing""#, &RSA)
            ]),
            Ok(vec![der(&RSA)])
        );
        assert_eq!(
            signing_of(&[key(r#" use="signing""#, &RSA), key("", &EC), key("", &RSA)]),
            Ok(vec![der(&RSA), der(&EC)])
        );
        assert_eq!(
            signing_of(&[key(r#" use="encryption""#, &RSA)]),
            Err(Misread::NoSigningCertificate)
        );
    }

    /// What is not one SAML 2.0 identity provider, or not shaped as its metadata,
    /// is refused.
    #[test]
    fn what_is_not_one_identity_provider_is_refused() {
        let plain = metadata(&key("", &RSA));
        let role_start = plain.find("<md:IDPSSODescriptor").expect("a role");
        let role_end =
            plain.find("</md:IDPSSODescriptor>").expect("a role") + "</md:IDPSSODescriptor>".len();
        let two_roles = format!("{}{}", &plain[..role_end], &plain[role_start..]);
        let unreadable_key = r#"<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>not base64!</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#;
        for (text, refused) in [
            (
                format!(r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">{plain}</md:EntitiesDescriptor>"#),
                Misread::NotOneEntity,
            ),
            (
                plain.replacen("urn:oasis:names:tc:SAML:2.0:metadata", "urn:example:metadata", 1),
                Misread::NotOneEntity,
            ),
            (
                plain.replacen("\n      urn:oasis:names:tc:SAML:2.0:protocol\"", "\"", 1),
                Misread::NotAnIdentityProvider,
            ),
            (
                plain.replace("md:IDPSSODescriptor", "md:SPSSODescriptor"),
                Misread::NotAnIdentityProvider,
            ),
            (two_roles, Misread::Misshapen),
            (plain.replacen(REDIRECT_SIGN_ON, "", 1), Misread::NoRedirectSignOn),
            (
                plain.replacen(r#" Location="https://idp.test/sso"/>"#, "/>", 1),
                Misread::Misshapen,
            ),
            (
                plain.replacen(r#"Location="https://idp.test/sso"/>"#, r#"Location=""/>"#, 1),
                Misread::Misshapen,
            ),
            (
                plain.replacen(
                    r#"ResponseLocation="https://idp.test/slo/answers""#,
                    r#"ResponseLocation="""#,
                    1,
                ),
                Misread::Misshapen,
            ),
            (plain.replacen(&format!(" {ENTITY_ID}"), "", 1), Misread::Misshapen),
            (
                plain.replacen(ENTITY_ID, r#"entityID=" https://idp.test/metadata""#, 1),
                Misread::Misshapen,
            ),
            (
                plain.replacen(
                    ENTITY_ID,
                    &format!(r#"entityID="https://idp.test/{}""#, "a".repeat(1008)),
                    1,
                ),
                Misread::Misshapen,
            ),
            (metadata(&key(r#" use="both""#, &RSA)), Misread::Misshapen),
            (
                metadata(&key("", &RSA).replace("ds:KeyInfo", "ds:KeyName")),
                Misread::Misshapen,
            ),
            (
                metadata(&key("", &RSA).replace("<ds:KeyInfo>", "<ds:KeyInfo></ds:KeyInfo><ds:KeyInfo>")),
                Misread::Misshapen,
            ),
            (
                metadata(&key("", &RSA).replace(
                    "</ds:X509Certificate>",
                    &format!("</ds:X509Certificate><ds:X509Certificate>{}</ds:X509Certificate>", EC.trim()),
                )),
                Misread::Misshapen,
            ),
            (
                metadata(r#"<md:KeyDescriptor><ds:KeyInfo><ds:KeyName>idp</ds:KeyName></ds:KeyInfo></md:KeyDescriptor>"#),
                Misread::NoSigningCertificate,
            ),
            (metadata(unreadable_key), Misread::UnreadableCertificate),
            (
                metadata(&unreadable_key.replace(
                    "not base64!",
                    &data_encoding::BASE64.encode(b"not a certificate"),
                )),
                Misread::UnreadableCertificate,
            ),
            (
                metadata(&[key("", &RSA), unreadable_key.replace("<md:KeyDescriptor>", r#"<md:KeyDescriptor use="encryption">"#)].concat()),
                Misread::UnreadableCertificate,
            ),
            (
                plain.replacen(
                    "nameid-format:persistent</md:NameIDFormat>",
                    "nameid-format:persistent<!-- and more --></md:NameIDFormat>",
                    1,
                ),
                Misread::Misshapen,
            ),
            (
                plain.replacen(
                    "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>",
                    "<md:NameIDFormat> </md:NameIDFormat>",
                    1,
                ),
                Misread::Misshapen,
            ),
        ] {
            assert_ne!(text, plain);
            assert_eq!(
                read_identity_provider(&text, Limits::MESSAGE).err(),
                Some(refused),
                "{text}"
            );
        }
        assert!(matches!(
            read_identity_provider(
                &format!("<!DOCTYPE md:EntityDescriptor>{plain}"),
                Limits::MESSAGE
            ),
            Err(Misread::Unreadable(_))
        ));
    }

    /// A realm describes itself with a key for each use, logout over both bindings,
    /// its format and its consumer over POST, in the order the schema sets and every
    /// value escaped; with no key for encryption and no format it names neither.
    #[test]
    fn a_realm_describes_itself_as_a_service_provider() {
        let certificates = [der(&RSA)];
        let provider = ServiceProvider {
            entity_id: "https://sp.test/realms/main/broker/corp/saml/metadata?a=1&b=<2>",
            assertion_consumer: "https://sp.test/realms/main/broker/corp/saml/acs",
            single_logout: "https://sp.test/realms/main/broker/corp/saml/slo",
            name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
            signing_certificates: &certificates,
            encryption_certificates: &certificates,
        };
        let written = describe_service_provider(&provider);
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let entity = document.root_element();
        assert_eq!(entity.tag_name().name(), "EntityDescriptor");
        assert_eq!(entity.attribute("entityID"), Some(provider.entity_id));
        let role = entity.first_element_child().expect("a role");
        assert_eq!(role.tag_name().name(), "SPSSODescriptor");
        for (name, value) in [
            ("AuthnRequestsSigned", "true"),
            ("WantAssertionsSigned", "true"),
            (
                "protocolSupportEnumeration",
                "urn:oasis:names:tc:SAML:2.0:protocol",
            ),
        ] {
            assert_eq!(role.attribute(name), Some(value), "{name}");
        }
        let parts: Vec<_> = role.children().filter(|node| node.is_element()).collect();
        let names: Vec<_> = parts.iter().map(|part| part.tag_name().name()).collect();
        assert_eq!(
            names,
            [
                "KeyDescriptor",
                "KeyDescriptor",
                "SingleLogoutService",
                "SingleLogoutService",
                "NameIDFormat",
                "AssertionConsumerService",
            ]
        );

        let offered_for_encryption = [
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        ];
        for (part, usage, offered) in [
            (parts[0], "signing", &[] as &[&str]),
            (parts[1], "encryption", &offered_for_encryption[..]),
        ] {
            assert_eq!(part.attribute("use"), Some(usage));
            let certificate = part
                .descendants()
                .find(|node| node.tag_name().name() == "X509Certificate")
                .and_then(|node| node.text())
                .expect("a certificate");
            assert_eq!(der(certificate), der(&RSA));
            let methods: Vec<_> = part
                .children()
                .filter(|node| node.tag_name().name() == "EncryptionMethod")
                .filter_map(|node| node.attribute("Algorithm"))
                .collect();
            assert_eq!(methods, offered);
        }
        for (part, binding) in [
            (
                parts[2],
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            ),
            (parts[3], "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
        ] {
            assert_eq!(part.attribute("Binding"), Some(binding));
            assert_eq!(part.attribute("Location"), Some(provider.single_logout));
        }
        assert_eq!(parts[4].text(), provider.name_id_format);
        for (name, value) in [
            ("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
            ("Location", provider.assertion_consumer),
            ("index", "0"),
            ("isDefault", "true"),
        ] {
            assert_eq!(parts[5].attribute(name), Some(value), "{name}");
        }
        assert_eq!(
            read_identity_provider(&written, Limits::MESSAGE),
            Err(Misread::NotAnIdentityProvider)
        );

        let bare = ServiceProvider {
            name_id_format: None,
            encryption_certificates: &[],
            ..provider
        };
        let written = describe_service_provider(&bare);
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let role = document
            .root_element()
            .first_element_child()
            .expect("a role");
        let names: Vec<_> = role
            .children()
            .filter(|node| node.is_element())
            .map(|node| node.tag_name().name())
            .collect();
        assert_eq!(
            names,
            [
                "KeyDescriptor",
                "SingleLogoutService",
                "SingleLogoutService",
                "AssertionConsumerService",
            ]
        );
    }
}
