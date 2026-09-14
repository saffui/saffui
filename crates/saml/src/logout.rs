use crate::name_id::{NameId, push_name_id};
use crate::protocol::{Unwritable, open_protocol_message};
use crate::xml::{push_attribute, push_text};

const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// What a logout request tells an identity provider.
#[derive(Debug, Clone, Copy)]
pub struct LogoutRequest<'a> {
    /// A fresh identifier, the one the response must answer.
    pub id: &'a str,
    pub issue_instant: i64,
    /// The identity provider's logout address the request goes to.
    pub destination: &'a str,
    /// This service provider's entity identifier.
    pub issuer: &'a str,
    /// The name the identity provider gave the person at sign-in, repeated whole.
    pub name_id: &'a NameId,
    /// The session the identity provider named at sign-in, when it named one.
    pub session_index: Option<&'a str>,
}

/// What a logout response tells the identity provider that asked.
#[derive(Debug, Clone, Copy)]
pub struct LogoutResponse<'a> {
    pub id: &'a str,
    pub issue_instant: i64,
    /// Where the identity provider takes answers to its logout requests.
    pub destination: &'a str,
    /// This service provider's entity identifier.
    pub issuer: &'a str,
    /// The identifier of the logout request this answers.
    pub in_response_to: &'a str,
}

/// The request as XML for the Redirect binding to carry, unsigned: that binding
/// signs the query.
pub fn write_logout_request(request: &LogoutRequest<'_>) -> Result<String, Unwritable> {
    let mut xml = open_protocol_message(
        "LogoutRequest",
        request.id,
        request.issue_instant,
        request.destination,
    )?;
    xml.push_str("><saml:Issuer>");
    push_text(&mut xml, request.issuer);
    xml.push_str("</saml:Issuer>");
    push_name_id(&mut xml, request.name_id);
    if let Some(session_index) = request.session_index {
        xml.push_str("<samlp:SessionIndex>");
        push_text(&mut xml, session_index);
        xml.push_str("</samlp:SessionIndex>");
    }
    xml.push_str("</samlp:LogoutRequest>");
    Ok(xml)
}

/// The response as XML for the Redirect binding to carry, unsigned. It says the
/// logout succeeded: a person with no session here is logged out already.
pub fn write_logout_response(response: &LogoutResponse<'_>) -> Result<String, Unwritable> {
    let mut xml = open_protocol_message(
        "LogoutResponse",
        response.id,
        response.issue_instant,
        response.destination,
    )?;
    push_attribute(&mut xml, "InResponseTo", response.in_response_to);
    xml.push_str("><saml:Issuer>");
    push_text(&mut xml, response.issuer);
    xml.push_str("</saml:Issuer><samlp:Status><samlp:StatusCode");
    push_attribute(&mut xml, "Value", SUCCESS);
    xml.push_str("/></samlp:Status></samlp:LogoutResponse>");
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use super::{LogoutRequest, LogoutResponse, write_logout_request, write_logout_response};
    use crate::name_id::{NameId, read_name_id};
    use crate::protocol::Unwritable;
    use crate::xml::{Limits, read_message};

    const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

    /// A logout request names itself, its destination and issuer, repeats the name
    /// identifier whole and the session when there is one; a time no calendar holds
    /// is not written.
    #[test]
    fn a_logout_request_repeats_the_name_and_session_it_ends() {
        let name_id = NameId {
            value: "AAdzZWNyZXQx".to_owned(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
            name_qualifier: Some("https://idp.test/metadata".to_owned()),
            sp_name_qualifier: Some(
                "https://sp.test/realms/main/broker/corp/saml/metadata".to_owned(),
            ),
        };
        let request = LogoutRequest {
            id: "_logout-3",
            issue_instant: 1_789_372_800,
            destination: "https://idp.test/slo",
            issuer: "https://sp.test/realms/main/broker/corp/saml/metadata",
            name_id: &name_id,
            session_index: Some("_session-1"),
        };
        let written = write_logout_request(&request).expect("a request");
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let root = document.root_element();
        assert_eq!(root.tag_name().namespace(), Some(PROTOCOL));
        assert_eq!(root.tag_name().name(), "LogoutRequest");
        for (name, value) in [
            ("ID", "_logout-3"),
            ("Version", "2.0"),
            ("IssueInstant", "2026-09-14T08:00:00Z"),
            ("Destination", "https://idp.test/slo"),
        ] {
            assert_eq!(root.attribute(name), Some(value), "{name}");
        }
        let parts: Vec<_> = root.children().filter(|node| node.is_element()).collect();
        let names: Vec<_> = parts.iter().map(|part| part.tag_name().name()).collect();
        assert_eq!(names, ["Issuer", "NameID", "SessionIndex"]);
        assert_eq!(parts[0].text(), Some(request.issuer));
        assert_eq!(read_name_id(parts[1]), Some(name_id.clone()));
        assert_eq!(parts[2].tag_name().namespace(), Some(PROTOCOL));
        assert_eq!(parts[2].text(), Some("_session-1"));

        let sessionless = LogoutRequest {
            session_index: None,
            ..request
        };
        let written = write_logout_request(&sessionless).expect("a request");
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let names: Vec<_> = document
            .root_element()
            .children()
            .filter(|node| node.is_element())
            .map(|node| node.tag_name().name())
            .collect();
        assert_eq!(names, ["Issuer", "NameID"]);

        let timeless = LogoutRequest {
            issue_instant: i64::MAX,
            ..request
        };
        assert_eq!(write_logout_request(&timeless), Err(Unwritable::Time));
    }

    /// A logout response answers the request it names with success, from this
    /// issuer to the address the provider takes answers at.
    #[test]
    fn a_logout_response_answers_the_request_with_success() {
        let response = LogoutResponse {
            id: "_answer-4",
            issue_instant: 1_789_372_800,
            destination: "https://idp.test/slo/answers",
            issuer: "https://sp.test/realms/main/broker/corp/saml/metadata",
            in_response_to: "_logout-from-idp",
        };
        let written = write_logout_response(&response).expect("a response");
        let document = read_message(&written, Limits::MESSAGE).expect("well-formed");
        let root = document.root_element();
        assert_eq!(root.tag_name().namespace(), Some(PROTOCOL));
        assert_eq!(root.tag_name().name(), "LogoutResponse");
        for (name, value) in [
            ("ID", "_answer-4"),
            ("Version", "2.0"),
            ("IssueInstant", "2026-09-14T08:00:00Z"),
            ("Destination", "https://idp.test/slo/answers"),
            ("InResponseTo", "_logout-from-idp"),
        ] {
            assert_eq!(root.attribute(name), Some(value), "{name}");
        }
        let parts: Vec<_> = root.children().filter(|node| node.is_element()).collect();
        let names: Vec<_> = parts.iter().map(|part| part.tag_name().name()).collect();
        assert_eq!(names, ["Issuer", "Status"]);
        assert_eq!(parts[0].text(), Some(response.issuer));
        let codes: Vec<_> = parts[1]
            .children()
            .filter(|node| node.is_element())
            .map(|node| (node.tag_name().name(), node.attribute("Value")))
            .collect();
        assert_eq!(
            codes,
            [(
                "StatusCode",
                Some("urn:oasis:names:tc:SAML:2.0:status:Success")
            )]
        );

        let timeless = LogoutResponse {
            issue_instant: i64::MAX,
            ..response
        };
        assert_eq!(write_logout_response(&timeless), Err(Unwritable::Time));
    }
}
