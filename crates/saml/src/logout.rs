use crypto::provider::{CryptoProvider, PublicKey};
use roxmltree::{Document, Node};

use crate::dsig::{Unverified, verify_enveloped_signature};
use crate::name_id::{NameId, push_name_id, read_name_id};
use crate::protocol::{Unwritable, open_protocol_message};
use crate::redirect::{Carried, Received, verify_query_signature};
use crate::time::read_instant;
use crate::xml::{
    Limits, children_named, is_named, push_attribute, push_text, read_message, strict_text_of,
};

const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const ENTITY_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
/// How long after its instant a logout message is taken, clock skew aside.
const MESSAGE_LIFETIME: i64 = 180;

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

/// What a logout message from the identity provider is checked against.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedLogout<'e> {
    /// The identity provider's entity identifier.
    pub issuer: &'e str,
    /// The logout address of this service provider the message reached.
    pub destination: &'e str,
    /// The keys the identity provider signs with.
    pub trusted: &'e [PublicKey],
    /// Seconds since the epoch.
    pub now: i64,
    /// Seconds of clock difference tolerated either way.
    pub skew: i64,
}

/// How a logout message arrived: on a Redirect query, signed over the query, or
/// posted in a form, signed inside.
#[derive(Debug, Clone, Copy)]
pub enum Delivered<'a> {
    Redirected(&'a Received),
    Posted(&'a str),
}

/// Why a logout message from the identity provider was refused.
///
/// Precise for the log; the person is told one thing whatever the variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefusedLogout {
    #[error("the logout message is not shaped as SAML 2.0 logout")]
    Misshapen,
    #[error("the logout message is not signed by the identity provider")]
    Unverified(Unverified),
    #[error("the logout message comes from another issuer")]
    WrongIssuer,
    #[error("the logout message was sent to another address")]
    WrongDestination,
    #[error("the logout message is out of its time")]
    OutOfTime,
    #[error("the logout request names the person in a form this service does not read")]
    UnreadIdentifier,
    #[error("the logout response answers no request this service sent")]
    Unsolicited,
}

/// A logout request from the identity provider, accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequested {
    /// The identifier the response answers, kept against replay until
    /// `replayable_until`.
    pub id: String,
    pub replayable_until: i64,
    pub name_id: NameId,
    /// The sessions to end; none means every session under that name.
    pub session_indexes: Vec<String>,
}

/// What the identity provider says of a logout this service asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggedOut {
    Everywhere,
    /// The provider could not end every session it holds for the person.
    NotEverywhere,
}

/// Accept a logout request the identity provider sent: signed over its query or
/// inside, from that provider to this address within its time, naming one person
/// by a name identifier and the sessions to end.
pub fn accept_logout_request(
    provider: &dyn CryptoProvider,
    delivered: Delivered<'_>,
    expected: &ExpectedLogout<'_>,
) -> Result<LogoutRequested, RefusedLogout> {
    let document = read_delivered(delivered, Carried::Request)?;
    let request = document.root_element();
    if !is_named(request, PROTOCOL, "LogoutRequest") {
        return Err(RefusedLogout::Misshapen);
    }
    let (id, replayable_until) = check_logout_message(provider, delivered, request, expected)?;

    if children_named(request, ASSERTION, "EncryptedID")
        .next()
        .is_some()
        || children_named(request, ASSERTION, "BaseID")
            .next()
            .is_some()
    {
        return Err(RefusedLogout::UnreadIdentifier);
    }
    let mut names = children_named(request, ASSERTION, "NameID");
    let (Some(name), None) = (names.next(), names.next()) else {
        return Err(RefusedLogout::Misshapen);
    };
    let name_id = read_name_id(name).ok_or(RefusedLogout::Misshapen)?;
    let session_indexes = children_named(request, PROTOCOL, "SessionIndex")
        .map(|index| {
            strict_text_of(index)
                .filter(|text| !text.is_empty())
                .ok_or(RefusedLogout::Misshapen)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LogoutRequested {
        id,
        replayable_until,
        name_id,
        session_indexes,
    })
}

/// Accept the identity provider's answer to the logout request `request_id` this
/// service sent: held to what a request is held to, then read for its status.
pub fn accept_logout_response(
    provider: &dyn CryptoProvider,
    delivered: Delivered<'_>,
    expected: &ExpectedLogout<'_>,
    request_id: &str,
) -> Result<LoggedOut, RefusedLogout> {
    let document = read_delivered(delivered, Carried::Response)?;
    let response = document.root_element();
    if !is_named(response, PROTOCOL, "LogoutResponse") {
        return Err(RefusedLogout::Misshapen);
    }
    check_logout_message(provider, delivered, response, expected)?;
    if request_id.is_empty() || response.attribute("InResponseTo") != Some(request_id) {
        return Err(RefusedLogout::Unsolicited);
    }
    let mut statuses = children_named(response, PROTOCOL, "Status");
    let (Some(status), None) = (statuses.next(), statuses.next()) else {
        return Err(RefusedLogout::Misshapen);
    };
    let code = children_named(status, PROTOCOL, "StatusCode")
        .next()
        .and_then(|code| code.attribute("Value"))
        .ok_or(RefusedLogout::Misshapen)?;
    if code == SUCCESS {
        Ok(LoggedOut::Everywhere)
    } else {
        Ok(LoggedOut::NotEverywhere)
    }
}

/// The message a delivery carries, read under the message limits; a query must
/// carry it under the parameter of its kind.
fn read_delivered(
    delivered: Delivered<'_>,
    carried: Carried,
) -> Result<Document<'_>, RefusedLogout> {
    let text = match delivered {
        Delivered::Redirected(received) if received.carried == carried => received.message.as_str(),
        Delivered::Redirected(_) => return Err(RefusedLogout::Misshapen),
        Delivered::Posted(text) => text,
    };
    read_message(text, Limits::MESSAGE).map_err(|_| RefusedLogout::Misshapen)
}

/// What both logout messages are held to: the provider's signature, over the query
/// or inside; version 2.0 and an identifier; the provider as issuer; this address
/// as destination, which a signed message must name; an instant within the message
/// lifetime and no expiry passed. Answers the identifier and the instant until
/// which it is kept against replay.
fn check_logout_message(
    provider: &dyn CryptoProvider,
    delivered: Delivered<'_>,
    message: Node<'_, '_>,
    expected: &ExpectedLogout<'_>,
) -> Result<(String, i64), RefusedLogout> {
    match delivered {
        Delivered::Redirected(received) => {
            let signature = received
                .signature
                .as_ref()
                .ok_or(RefusedLogout::Unverified(Unverified::Unsigned))?;
            verify_query_signature(provider, signature, expected.trusted)
                .map_err(RefusedLogout::Unverified)?;
        }
        Delivered::Posted(_) => {
            verify_enveloped_signature(provider, message, expected.trusted)
                .map_err(RefusedLogout::Unverified)?;
        }
    }
    if message.attribute("Version") != Some("2.0") {
        return Err(RefusedLogout::Misshapen);
    }
    let id = message
        .attribute("ID")
        .filter(|id| !id.is_empty())
        .ok_or(RefusedLogout::Misshapen)?;

    let mut issuers = children_named(message, ASSERTION, "Issuer");
    let (Some(issuer), None) = (issuers.next(), issuers.next()) else {
        return Err(RefusedLogout::Misshapen);
    };
    if !issuer
        .attribute("Format")
        .is_none_or(|format| format == ENTITY_FORMAT)
        || strict_text_of(issuer).as_deref() != Some(expected.issuer)
    {
        return Err(RefusedLogout::WrongIssuer);
    }
    if message.attribute("Destination") != Some(expected.destination) {
        return Err(RefusedLogout::WrongDestination);
    }

    let issued = message
        .attribute("IssueInstant")
        .and_then(read_instant)
        .ok_or(RefusedLogout::Misshapen)?;
    let replayable_until = issued + MESSAGE_LIFETIME + expected.skew;
    if issued > expected.now + expected.skew || expected.now >= replayable_until {
        return Err(RefusedLogout::OutOfTime);
    }
    if let Some(until) = message.attribute("NotOnOrAfter") {
        let until = read_instant(until).ok_or(RefusedLogout::Misshapen)?;
        if expected.now >= until + expected.skew {
            return Err(RefusedLogout::OutOfTime);
        }
    }
    Ok((id.to_owned(), replayable_until))
}

#[cfg(test)]
mod tests {
    use super::{
        Delivered, ExpectedLogout, LoggedOut, LogoutRequest, LogoutRequested, LogoutResponse,
        RefusedLogout, accept_logout_request, accept_logout_response, write_logout_request,
        write_logout_response,
    };
    use crate::dsig::Unverified;
    use crate::name_id::{NameId, read_name_id};
    use crate::post::decode_posted_message;
    use crate::protocol::Unwritable;
    use crate::redirect::{Carried, Received, decode_query, encode_query};
    use crate::testing::{DrawnKey, key_certified_by, provider};
    use crate::xml::{Limits, read_message};
    use crypto::provider::{CryptoProvider, SignAlg};
    use std::sync::LazyLock;

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

    const IDP: &str = "https://idp.test/metadata";
    const SLO: &str = "https://sp.test/realms/main/broker/corp/saml/slo";
    static IDP_KEY: LazyLock<DrawnKey> = LazyLock::new(DrawnKey::draw_rsa);
    static OTHER_KEY: LazyLock<DrawnKey> = LazyLock::new(DrawnKey::draw_rsa);
    const NAME: &str = r#"<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://idp.test/metadata" SPNameQualifier="https://sp.test/realms/main">AAdzZWNyZXQx</saml:NameID>"#;
    const IDP_REQUEST: &str = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_idp-logout" Version="2.0" IssueInstant="2026-09-14T08:00:00Z" Destination="https://sp.test/realms/main/broker/corp/saml/slo"><saml:Issuer>https://idp.test/metadata</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://idp.test/metadata" SPNameQualifier="https://sp.test/realms/main">AAdzZWNyZXQx</saml:NameID><samlp:SessionIndex>_session-1</samlp:SessionIndex><samlp:SessionIndex>_session-2</samlp:SessionIndex></samlp:LogoutRequest>"#;
    const IDP_ANSWER: &str = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_idp-answer" Version="2.0" IssueInstant="2026-09-14T08:00:00Z" Destination="https://sp.test/realms/main/broker/corp/saml/slo" InResponseTo="_logout-3"><saml:Issuer>https://idp.test/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#;
    const SUCCESS_CODE: &str =
        r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#;
    const POSTED_REQUEST: &str = include_str!("../tests/fixtures/logout-request-posted.xml");
    const POSTED_REQUEST_OTHER_KEY: &str =
        include_str!("../tests/fixtures/logout-request-posted-other-key.xml");
    const POSTED_ANSWER: &str = include_str!("../tests/fixtures/logout-response-posted.xml");

    fn at(text: &str) -> i64 {
        crate::time::read_instant(text).expect("a time")
    }

    /// A message on a Redirect query signed with `signer`.
    fn redirected(carried: Carried, message: &str, signer: &DrawnKey) -> Received {
        let provider = provider();
        let key = signer.to_private_key();
        let query = encode_query(carried, message, Some("back"), SignAlg::Rs256, &|octets| {
            provider.signer().sign(SignAlg::Rs256, &key, octets).ok()
        })
        .expect("a query");
        decode_query(&query, Limits::MESSAGE).expect("a query")
    }

    /// This service provider's expectations at 08:01, with three minutes of skew,
    /// trusting the key the Redirect cases sign with and the certificate of the
    /// provider that signed the posted fixtures.
    fn expected_with<T>(check: impl FnOnce(&ExpectedLogout<'_>) -> T) -> T {
        let trusted = [
            IDP_KEY.to_public_key(),
            key_certified_by(include_str!("../tests/fixtures/idp-rsa.cer.b64")),
        ];
        check(&ExpectedLogout {
            issuer: IDP,
            destination: SLO,
            trusted: &trusted,
            now: at("2026-09-14T08:01:00Z"),
            skew: 180,
        })
    }

    fn request_outcome(delivered: Delivered<'_>) -> Result<LogoutRequested, RefusedLogout> {
        expected_with(|expected| accept_logout_request(&provider(), delivered, expected))
    }

    fn response_outcome(
        delivered: Delivered<'_>,
        request_id: &str,
    ) -> Result<LoggedOut, RefusedLogout> {
        expected_with(|expected| {
            accept_logout_response(&provider(), delivered, expected, request_id)
        })
    }

    /// A logout request from the identity provider is accepted over either binding,
    /// with the name, the sessions to end and how long it is kept against replay.
    #[test]
    fn a_logout_request_is_accepted_redirected_or_posted() {
        let accepted = LogoutRequested {
            id: "_idp-logout".to_owned(),
            replayable_until: at("2026-09-14T08:06:00Z"),
            name_id: NameId {
                value: "AAdzZWNyZXQx".to_owned(),
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
                name_qualifier: Some(IDP.to_owned()),
                sp_name_qualifier: Some("https://sp.test/realms/main".to_owned()),
            },
            session_indexes: vec!["_session-1".to_owned(), "_session-2".to_owned()],
        };
        let received = redirected(Carried::Request, IDP_REQUEST, &IDP_KEY);
        assert_eq!(
            request_outcome(Delivered::Redirected(&received)),
            Ok(accepted.clone())
        );

        let form = data_encoding::BASE64.encode(POSTED_REQUEST.as_bytes());
        let lines: Vec<&str> = form
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
            .collect();
        let posted = decode_posted_message(&lines.join("\r\n")).expect("a posted message");
        assert_eq!(request_outcome(Delivered::Posted(&posted)), Ok(accepted));
    }

    /// A logout request is refused for what it says: another issuer, another issuer
    /// format or two issuers, another destination or none, an instant ahead or at
    /// the end of its lifetime, an instant with an offset, an expiry passed, another
    /// version, an empty identifier, no name, two names, an empty name, a name in a
    /// form not read, an empty session, and another request or a response in its
    /// place.
    #[test]
    fn a_logout_request_is_refused_for_what_it_says() {
        let instant = r#"IssueInstant="2026-09-14T08:00:00Z""#;
        for (message, refused) in [
            (
                IDP_REQUEST.replacen(
                    ">https://idp.test/metadata</saml:Issuer>",
                    ">https://other-idp.test</saml:Issuer>",
                    1,
                ),
                RefusedLogout::WrongIssuer,
            ),
            (
                IDP_REQUEST.replacen(
                    "<saml:Issuer>",
                    r#"<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">"#,
                    1,
                ),
                RefusedLogout::WrongIssuer,
            ),
            (
                IDP_REQUEST.replacen(
                    "</saml:Issuer>",
                    "</saml:Issuer><saml:Issuer>https://idp.test/metadata</saml:Issuer>",
                    1,
                ),
                RefusedLogout::Misshapen,
            ),
            (
                IDP_REQUEST.replacen("/broker/corp/saml/slo", "/broker/other/saml/slo", 1),
                RefusedLogout::WrongDestination,
            ),
            (
                IDP_REQUEST.replacen(&format!(r#" Destination="{SLO}""#), "", 1),
                RefusedLogout::WrongDestination,
            ),
            (
                IDP_REQUEST.replacen(instant, r#"IssueInstant="2026-09-14T08:04:01Z""#, 1),
                RefusedLogout::OutOfTime,
            ),
            (
                IDP_REQUEST.replacen(instant, r#"IssueInstant="2026-09-14T07:55:00Z""#, 1),
                RefusedLogout::OutOfTime,
            ),
            (
                IDP_REQUEST.replacen(instant, r#"IssueInstant="2026-09-14T08:00:00+00:00""#, 1),
                RefusedLogout::Misshapen,
            ),
            (
                IDP_REQUEST.replacen(
                    instant,
                    &format!(r#"{instant} NotOnOrAfter="2026-09-14T07:58:00Z""#),
                    1,
                ),
                RefusedLogout::OutOfTime,
            ),
            (
                IDP_REQUEST.replacen(r#"Version="2.0""#, r#"Version="1.1""#, 1),
                RefusedLogout::Misshapen,
            ),
            (
                IDP_REQUEST.replacen(r#"ID="_idp-logout""#, r#"ID="""#, 1),
                RefusedLogout::Misshapen,
            ),
            (IDP_REQUEST.replacen(NAME, "", 1), RefusedLogout::Misshapen),
            (
                IDP_REQUEST.replacen(NAME, &NAME.repeat(2), 1),
                RefusedLogout::Misshapen,
            ),
            (
                IDP_REQUEST.replacen(">AAdzZWNyZXQx<", "><", 1),
                RefusedLogout::Misshapen,
            ),
            (
                IDP_REQUEST.replacen(NAME, "<saml:EncryptedID/>", 1),
                RefusedLogout::UnreadIdentifier,
            ),
            (
                IDP_REQUEST.replacen(NAME, "<saml:BaseID/>", 1),
                RefusedLogout::UnreadIdentifier,
            ),
            (
                IDP_REQUEST.replacen(">_session-2<", "><", 1),
                RefusedLogout::Misshapen,
            ),
            (
                IDP_REQUEST.replace("samlp:LogoutRequest", "samlp:ManageNameIDRequest"),
                RefusedLogout::Misshapen,
            ),
            (IDP_ANSWER.to_owned(), RefusedLogout::Misshapen),
        ] {
            assert_ne!(message, IDP_REQUEST);
            let received = redirected(Carried::Request, &message, &IDP_KEY);
            assert_eq!(
                request_outcome(Delivered::Redirected(&received)),
                Err(refused),
                "{message}"
            );
        }
    }

    /// A logout request is taken only under the identity provider's signature: not
    /// on a query unsigned or signed by another key, nor on a query for a response,
    /// nor posted unsigned, signed by another key or changed after signing.
    #[test]
    fn a_logout_request_is_taken_only_under_the_provider_signature() {
        let signed = redirected(Carried::Request, IDP_REQUEST, &IDP_KEY);
        let unsigned = Received {
            signature: None,
            ..signed
        };
        let foreign = redirected(Carried::Request, IDP_REQUEST, &OTHER_KEY);
        let crossed = redirected(Carried::Response, IDP_REQUEST, &IDP_KEY);
        let tampered = POSTED_REQUEST.replacen(">AAdzZWNyZXQx<", ">AAdzZWNyZXQy<", 1);
        assert_ne!(tampered, POSTED_REQUEST);
        for (delivered, refused) in [
            (
                Delivered::Redirected(&unsigned),
                RefusedLogout::Unverified(Unverified::Unsigned),
            ),
            (
                Delivered::Redirected(&foreign),
                RefusedLogout::Unverified(Unverified::Untrusted),
            ),
            (Delivered::Redirected(&crossed), RefusedLogout::Misshapen),
            (
                Delivered::Posted(IDP_REQUEST),
                RefusedLogout::Unverified(Unverified::Unsigned),
            ),
            (
                Delivered::Posted(POSTED_REQUEST_OTHER_KEY),
                RefusedLogout::Unverified(Unverified::Untrusted),
            ),
            (
                Delivered::Posted(&tampered),
                RefusedLogout::Unverified(Unverified::DigestMismatch),
            ),
        ] {
            assert_eq!(request_outcome(delivered), Err(refused));
        }
    }

    /// A logout response tells whether the provider logged out everywhere, over
    /// either binding, and is refused when it answers another request, none or an
    /// empty one, holds no status or two, a status with no value, no destination,
    /// or is a request.
    #[test]
    fn a_logout_response_tells_whether_the_provider_logged_out_everywhere() {
        let received = redirected(Carried::Response, IDP_ANSWER, &IDP_KEY);
        assert_eq!(
            response_outcome(Delivered::Redirected(&received), "_logout-3"),
            Ok(LoggedOut::Everywhere)
        );
        assert_eq!(
            response_outcome(Delivered::Posted(POSTED_ANSWER), "_logout-3"),
            Ok(LoggedOut::Everywhere)
        );
        let answered = r#"InResponseTo="_logout-3""#;
        for (message, request_id, outcome) in [
            (
                IDP_ANSWER.replacen(
                    SUCCESS_CODE,
                    r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:PartialLogout"/></samlp:StatusCode>"#,
                    1,
                ),
                "_logout-3",
                Ok(LoggedOut::NotEverywhere),
            ),
            (
                IDP_ANSWER.replacen(
                    SUCCESS_CODE,
                    r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>"#,
                    1,
                ),
                "_logout-3",
                Ok(LoggedOut::NotEverywhere),
            ),
            (
                IDP_ANSWER.replacen(answered, r#"InResponseTo="_logout-4""#, 1),
                "_logout-3",
                Err(RefusedLogout::Unsolicited),
            ),
            (
                IDP_ANSWER.replacen(&format!(" {answered}"), "", 1),
                "_logout-3",
                Err(RefusedLogout::Unsolicited),
            ),
            (
                IDP_ANSWER.replacen(answered, r#"InResponseTo="""#, 1),
                "",
                Err(RefusedLogout::Unsolicited),
            ),
            (
                IDP_ANSWER.replacen(&format!("<samlp:Status>{SUCCESS_CODE}</samlp:Status>"), "", 1),
                "_logout-3",
                Err(RefusedLogout::Misshapen),
            ),
            (
                IDP_ANSWER.replacen(
                    "</samlp:Status>",
                    &format!("</samlp:Status><samlp:Status>{SUCCESS_CODE}</samlp:Status>"),
                    1,
                ),
                "_logout-3",
                Err(RefusedLogout::Misshapen),
            ),
            (
                IDP_ANSWER.replacen(SUCCESS_CODE, "<samlp:StatusCode/>", 1),
                "_logout-3",
                Err(RefusedLogout::Misshapen),
            ),
            (
                IDP_ANSWER.replacen(&format!(r#" Destination="{SLO}""#), "", 1),
                "_logout-3",
                Err(RefusedLogout::WrongDestination),
            ),
            (IDP_REQUEST.to_owned(), "_logout-3", Err(RefusedLogout::Misshapen)),
        ] {
            assert_ne!(message, IDP_ANSWER);
            let received = redirected(Carried::Response, &message, &IDP_KEY);
            assert_eq!(
                response_outcome(Delivered::Redirected(&received), request_id),
                outcome,
                "{message}"
            );
        }
    }
}
