use crate::time::write_instant;
use crate::xml::{push_attribute, push_text};

const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// What an authentication request asks of an identity provider.
#[derive(Debug, Clone, Copy)]
pub struct AuthnRequest<'a> {
    /// A fresh identifier, the one the response must answer.
    pub id: &'a str,
    pub issue_instant: i64,
    /// The identity provider's single sign-on address the request goes to.
    pub destination: &'a str,
    /// This service provider's entity identifier.
    pub issuer: &'a str,
    /// Where the response comes back, over the POST binding.
    pub assertion_consumer: &'a str,
    pub name_id_format: Option<&'a str>,
    /// Asks the provider to authenticate the person again rather than reuse its session.
    pub force_authn: bool,
}

/// Why a message could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unwritable {
    #[error("a time could not be written")]
    Time,
}

/// The request as XML for the Redirect binding to carry. It holds no enveloped
/// signature: that binding signs the query instead.
pub fn write_authn_request(request: &AuthnRequest<'_>) -> Result<String, Unwritable> {
    let instant = write_instant(request.issue_instant).ok_or(Unwritable::Time)?;
    let mut xml = String::from(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#,
    );
    push_attribute(&mut xml, "ID", request.id);
    push_attribute(&mut xml, "Version", "2.0");
    push_attribute(&mut xml, "IssueInstant", &instant);
    push_attribute(&mut xml, "Destination", request.destination);
    push_attribute(
        &mut xml,
        "AssertionConsumerServiceURL",
        request.assertion_consumer,
    );
    push_attribute(&mut xml, "ProtocolBinding", POST_BINDING);
    if request.force_authn {
        push_attribute(&mut xml, "ForceAuthn", "true");
    }
    xml.push_str("><saml:Issuer>");
    push_text(&mut xml, request.issuer);
    xml.push_str("</saml:Issuer><samlp:NameIDPolicy");
    if let Some(format) = request.name_id_format {
        push_attribute(&mut xml, "Format", format);
    }
    push_attribute(&mut xml, "AllowCreate", "true");
    xml.push_str("/></samlp:AuthnRequest>");
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::{AuthnRequest, Unwritable, write_authn_request};
    use crate::xml::{Limits, read_message};

    fn request<'a>() -> AuthnRequest<'a> {
        AuthnRequest {
            id: "_request-7",
            issue_instant: 1_789_372_800,
            destination: "https://idp.test/sso",
            issuer: "https://sp.test/realms/main/broker/corp/saml/metadata",
            assertion_consumer: "https://sp.test/realms/main/broker/corp/saml/acs",
            name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
            force_authn: false,
        }
    }

    /// The request names itself, its destination, where and over which binding to
    /// answer, its issuer with no format, and the identifier it asks for, every
    /// value escaped; a time no calendar holds is not written.
    #[test]
    fn a_request_says_what_the_profile_asks_and_escapes_it() {
        let written = write_authn_request(&request()).expect("a request");
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "AuthnRequest");
        for (name, value) in [
            ("ID", "_request-7"),
            ("Version", "2.0"),
            ("IssueInstant", "2026-09-14T08:00:00Z"),
            ("Destination", "https://idp.test/sso"),
            (
                "AssertionConsumerServiceURL",
                "https://sp.test/realms/main/broker/corp/saml/acs",
            ),
            (
                "ProtocolBinding",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            ),
        ] {
            assert_eq!(root.attribute(name), Some(value), "{name}");
        }
        assert_eq!(root.attribute("ForceAuthn"), None);
        let issuer = root
            .children()
            .find(|node| node.tag_name().name() == "Issuer")
            .expect("an issuer");
        assert_eq!(
            issuer.text(),
            Some("https://sp.test/realms/main/broker/corp/saml/metadata")
        );
        assert_eq!(issuer.attribute("Format"), None);
        let policy = root
            .children()
            .find(|node| node.tag_name().name() == "NameIDPolicy")
            .expect("a policy");
        assert_eq!(
            policy.attribute("Format"),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        );
        assert_eq!(policy.attribute("AllowCreate"), Some("true"));

        let odd = AuthnRequest {
            issuer: "https://sp.test/?a=1&b=\"<2>\"&c=]]>",
            id: "_\"quoted\"&<angled>",
            force_authn: true,
            ..request()
        };
        let written = write_authn_request(&odd).expect("a request");
        let document = read_message(&written, Limits::MESSAGE).expect("still well-formed");
        let root = document.root_element();
        assert_eq!(root.attribute("ForceAuthn"), Some("true"));
        assert_eq!(root.attribute("ID"), Some("_\"quoted\"&<angled>"));
        let issuer = root
            .children()
            .find(|node| node.tag_name().name() == "Issuer")
            .expect("an issuer");
        assert_eq!(issuer.text(), Some("https://sp.test/?a=1&b=\"<2>\"&c=]]>"));

        let timeless = AuthnRequest {
            issue_instant: i64::MAX,
            ..request()
        };
        assert_eq!(write_authn_request(&timeless), Err(Unwritable::Time));
    }
}
