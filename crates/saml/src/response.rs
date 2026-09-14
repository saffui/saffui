use chrono::NaiveDateTime;
use crypto::provider::{CryptoProvider, PublicKey};
use roxmltree::{Document, Node, NodeType};

use crate::dsig::{Unverified, carries_signature, verify_enveloped_signature};

const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const ENTITY_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

/// What a response is checked against: the identity provider it comes from,
/// this realm as a service provider, and the request it answers.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'e> {
    /// The identity provider's entity identifier.
    pub issuer: &'e str,
    /// This service provider's entity identifier.
    pub audience: &'e str,
    /// The assertion consumer service address the response reached.
    pub recipient: &'e str,
    /// The identifier of the authentication request the response answers.
    pub request_id: &'e str,
    /// The keys the identity provider signs with.
    pub trusted: &'e [PublicKey],
    /// Seconds since the epoch.
    pub now: i64,
    /// Seconds of clock difference tolerated either way.
    pub skew: i64,
}

/// Why a response was refused.
///
/// Precise for the log; the person signing in is told one thing whatever the
/// variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the message is not a SAML 2.0 response")]
    NotAResponse,
    #[error("a signature was not accepted: {0}")]
    Unverified(Unverified),
    #[error("the response was sent to another address")]
    WrongDestination,
    #[error("the response or its assertion comes from another issuer")]
    WrongIssuer,
    #[error("the identity provider answered {status}")]
    Unsuccessful { status: String },
    #[error("the response answers no request of this service provider")]
    Unsolicited,
    #[error("the response answers another request")]
    WrongRequest,
    #[error("the response carries an encrypted assertion")]
    Encrypted,
    #[error("the response does not carry exactly one assertion")]
    NotOneAssertion,
    #[error("the assertion is not shaped as the profile requires")]
    Misshapen,
    #[error("no bearer confirmation of the subject holds")]
    Unconfirmed,
    #[error("the assertion is not valid at this time")]
    OutOfTime,
    #[error("the assertion is not addressed to this service provider")]
    WrongAudience,
    #[error("the assertion holds a condition this service provider does not understand")]
    UnknownCondition,
}

/// What an accepted response says about the person, read only from what a
/// verified signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// Kept against replay until `replayable_until`, when the confirmation closes.
    pub assertion_id: String,
    pub replayable_until: i64,
    pub name_id: String,
    pub name_id_format: Option<String>,
    /// Names the session a later logout request refers to.
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<i64>,
    pub authn_instant: i64,
    pub authn_context_class: Option<String>,
    /// Each attribute's name and its plain text values, in document order.
    pub attributes: Vec<(String, Vec<String>)>,
}

/// Accept a response to one of this service provider's authentication requests,
/// or say why not.
///
/// A signature on the response covers its one assertion; otherwise the assertion
/// carries its own, and any signature present has to verify. The response has to
/// answer this request, at this address, from this issuer, with success; the
/// assertion has to come from the same issuer, confirm its subject as a bearer
/// for this address and this request, be addressed to this service provider,
/// hold no condition this code does not understand, and be valid now within the
/// skew. A response nobody asked for is refused.
pub fn accept_response(
    provider: &dyn CryptoProvider,
    document: &Document<'_>,
    expected: &Expected<'_>,
) -> Result<Accepted, Refused> {
    let response = document.root_element();
    if !is_named(response, PROTOCOL, "Response") || response.attribute("Version") != Some("2.0") {
        return Err(Refused::NotAResponse);
    }
    let response_signed = carries_signature(response);
    if response_signed {
        verify_enveloped_signature(provider, response, expected.trusted)
            .map_err(Refused::Unverified)?;
    }

    // The bindings require a destination on a signed response.
    match response.attribute("Destination") {
        Some(destination) if destination == expected.recipient => {}
        None if !response_signed => {}
        _ => return Err(Refused::WrongDestination),
    }
    if let Some(issuer) = single_child(response, ASSERTION, "Issuer")? {
        check_issuer(issuer, expected.issuer)?;
    }
    check_status(response)?;
    match response.attribute("InResponseTo") {
        None => return Err(Refused::Unsolicited),
        Some(answered) if answered != expected.request_id => return Err(Refused::WrongRequest),
        Some(_) => {}
    }

    if children_named(response, ASSERTION, "EncryptedAssertion")
        .next()
        .is_some()
    {
        return Err(Refused::Encrypted);
    }
    let mut assertions = children_named(response, ASSERTION, "Assertion");
    let assertion = assertions.next().ok_or(Refused::NotOneAssertion)?;
    if assertions.next().is_some() {
        return Err(Refused::NotOneAssertion);
    }
    if !response_signed || carries_signature(assertion) {
        verify_enveloped_signature(provider, assertion, expected.trusted)
            .map_err(Refused::Unverified)?;
    }
    read_assertion(assertion, expected)
}

fn read_assertion(assertion: Node<'_, '_>, expected: &Expected<'_>) -> Result<Accepted, Refused> {
    if assertion.attribute("Version") != Some("2.0") {
        return Err(Refused::Misshapen);
    }
    let assertion_id = assertion.attribute("ID").ok_or(Refused::Misshapen)?;
    let issuer = single_child(assertion, ASSERTION, "Issuer")?.ok_or(Refused::Misshapen)?;
    check_issuer(issuer, expected.issuer)?;

    let subject = single_child(assertion, ASSERTION, "Subject")?.ok_or(Refused::Misshapen)?;
    let name = single_child(subject, ASSERTION, "NameID")?.ok_or(Refused::Misshapen)?;
    let replayable_until = confirmed_until(subject, expected)?;
    let conditions =
        single_child(assertion, ASSERTION, "Conditions")?.ok_or(Refused::WrongAudience)?;
    check_conditions(conditions, expected)?;

    let statement = children_named(assertion, ASSERTION, "AuthnStatement")
        .next()
        .ok_or(Refused::Misshapen)?;
    let authn_instant = instant_of(
        statement
            .attribute("AuthnInstant")
            .ok_or(Refused::Misshapen)?,
    )?;
    let session_not_on_or_after = statement
        .attribute("SessionNotOnOrAfter")
        .map(instant_of)
        .transpose()?;
    if session_not_on_or_after.is_some_and(|until| expected.now >= until + expected.skew) {
        return Err(Refused::OutOfTime);
    }
    let authn_context_class = single_child(statement, ASSERTION, "AuthnContext")?
        .map(|context| single_child(context, ASSERTION, "AuthnContextClassRef"))
        .transpose()?
        .flatten()
        .map(strict_text)
        .transpose()?;

    Ok(Accepted {
        assertion_id: assertion_id.to_owned(),
        replayable_until,
        name_id: strict_text(name)?,
        name_id_format: name.attribute("Format").map(str::to_owned),
        session_index: statement.attribute("SessionIndex").map(str::to_owned),
        session_not_on_or_after,
        authn_instant,
        authn_context_class,
        attributes: read_attributes(assertion),
    })
}

fn check_issuer(issuer: Node<'_, '_>, expected: &str) -> Result<(), Refused> {
    let entity = issuer
        .attribute("Format")
        .is_none_or(|format| format == ENTITY_FORMAT);
    if entity && strict_text(issuer)? == expected {
        Ok(())
    } else {
        Err(Refused::WrongIssuer)
    }
}

fn check_status(response: Node<'_, '_>) -> Result<(), Refused> {
    let code = single_child(response, PROTOCOL, "Status")?
        .map(|status| single_child(status, PROTOCOL, "StatusCode"))
        .transpose()?
        .flatten()
        .ok_or(Refused::NotAResponse)?;
    let top = code.attribute("Value").unwrap_or_default();
    if top == SUCCESS {
        return Ok(());
    }
    let status = match single_child(code, PROTOCOL, "StatusCode")?
        .and_then(|nested| nested.attribute("Value"))
    {
        Some(second) => format!("{top} / {second}"),
        None => top.to_owned(),
    };
    Err(Refused::Unsuccessful { status })
}

/// When the latest bearer confirmation of the subject that holds here closes:
/// for this address and this request, with no start of its own, and still open.
/// That instant is how long the assertion is kept against replay.
fn confirmed_until(subject: Node<'_, '_>, expected: &Expected<'_>) -> Result<i64, Refused> {
    let mut until = None;
    for confirmation in children_named(subject, ASSERTION, "SubjectConfirmation") {
        if confirmation.attribute("Method") != Some(BEARER) {
            continue;
        }
        let Some(data) = single_child(confirmation, ASSERTION, "SubjectConfirmationData")? else {
            continue;
        };
        let Some(closing) = data.attribute("NotOnOrAfter") else {
            continue;
        };
        let closing = instant_of(closing)?;
        let holds = data.attribute("NotBefore").is_none()
            && data.attribute("Recipient") == Some(expected.recipient)
            && data.attribute("InResponseTo") == Some(expected.request_id)
            && expected.now < closing + expected.skew;
        if holds {
            until = until.max(Some(closing));
        }
    }
    until.ok_or(Refused::Unconfirmed)
}

/// Every condition understood and holding, or the assertion is refused: what
/// cannot be evaluated counts against it, as the core specification says. Each
/// audience restriction has to name this service provider among its audiences.
fn check_conditions(conditions: Node<'_, '_>, expected: &Expected<'_>) -> Result<(), Refused> {
    let start = conditions
        .attribute("NotBefore")
        .map(instant_of)
        .transpose()?;
    let end = conditions
        .attribute("NotOnOrAfter")
        .map(instant_of)
        .transpose()?;
    if let (Some(start), Some(end)) = (start, end)
        && start >= end
    {
        return Err(Refused::Misshapen);
    }
    if start.is_some_and(|start| expected.now + expected.skew < start)
        || end.is_some_and(|end| expected.now >= end + expected.skew)
    {
        return Err(Refused::OutOfTime);
    }

    let (mut restricted, mut used_once) = (false, 0);
    for condition in conditions.children().filter(Node::is_element) {
        match (
            condition.tag_name().namespace(),
            condition.tag_name().name(),
        ) {
            (Some(ASSERTION), "AudienceRestriction") => {
                restricted = true;
                let addressed = children_named(condition, ASSERTION, "Audience").any(|audience| {
                    strict_text(audience).is_ok_and(|named| named == expected.audience)
                });
                if !addressed {
                    return Err(Refused::WrongAudience);
                }
            }
            (Some(ASSERTION), "OneTimeUse") => used_once += 1,
            _ => return Err(Refused::UnknownCondition),
        }
    }
    if used_once > 1 {
        return Err(Refused::Misshapen);
    }
    if !restricted {
        return Err(Refused::WrongAudience);
    }
    Ok(())
}

/// Each attribute's name and the values it states as plain text. A value holding
/// anything but text, a nested identifier or a comment, is left out rather than
/// read around.
fn read_attributes(assertion: Node<'_, '_>) -> Vec<(String, Vec<String>)> {
    children_named(assertion, ASSERTION, "AttributeStatement")
        .flat_map(|statement| children_named(statement, ASSERTION, "Attribute"))
        .filter_map(|attribute| {
            let name = attribute.attribute("Name")?.to_owned();
            let values = children_named(attribute, ASSERTION, "AttributeValue")
                .filter_map(|value| strict_text(value).ok())
                .collect();
            Some((name, values))
        })
        .collect()
}

/// A SAML time: `xs:dateTime` in UTC, fractional seconds allowed, with a `Z` or
/// no zone at all. An offset is refused rather than converted.
fn instant_of(text: &str) -> Result<i64, Refused> {
    let local = text.strip_suffix('Z').unwrap_or(text);
    NaiveDateTime::parse_from_str(local, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|instant| instant.and_utc().timestamp())
        .map_err(|_| Refused::Misshapen)
}

/// The text of an element that holds text alone. A comment or an element inside
/// is refused rather than skipped: reading around a comment is how one
/// identifier turns into another.
fn strict_text(element: Node<'_, '_>) -> Result<String, Refused> {
    let mut text = String::new();
    for child in element.children() {
        match child.node_type() {
            NodeType::Text => text.push_str(child.text().unwrap_or_default()),
            _ => return Err(Refused::Misshapen),
        }
    }
    Ok(text.trim().to_owned())
}

fn is_named(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

fn children_named<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    parent
        .children()
        .filter(move |child| is_named(*child, namespace, name))
}

/// The one child of that name, if any; two of them are refused, since which one
/// a reader takes is exactly what an attacker would choose.
fn single_child<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> Result<Option<Node<'a, 'input>>, Refused> {
    let mut found = children_named(parent, namespace, name);
    let first = found.next();
    if found.next().is_some() {
        return Err(Refused::Misshapen);
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::{Accepted, Expected, Refused, accept_response, instant_of};
    use crate::dsig::Unverified;
    use crate::testing::{key_certified_by, provider};
    use crate::xml::{Limits, read_message};
    use chrono::NaiveDateTime;

    const ACS: &str = "https://sp.test/realms/main/broker/corp/endpoint";
    const SP: &str = "https://sp.test/realms/main";
    const IDP: &str = "https://idp.test/metadata";
    const REQUEST: &str = "_request-7";
    const ASSERTION_SIGNED: &str = include_str!("../tests/fixtures/response-assertion-signed.xml");
    const RESPONSE_SIGNED: &str = include_str!("../tests/fixtures/response-signed.xml");
    const BOTH_SIGNED: &str = include_str!("../tests/fixtures/response-both-signed.xml");

    fn at(text: &str) -> i64 {
        NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
            .expect("a time")
            .and_utc()
            .timestamp()
    }

    /// The outcome of a response against this service provider's expectations
    /// at 08:01, changed as a case needs.
    fn outcome(text: &str, change: impl FnOnce(&mut Expected<'_>)) -> Result<Accepted, Refused> {
        let trusted = [key_certified_by(include_str!(
            "../tests/fixtures/idp-rsa.cer.b64"
        ))];
        let mut expected = Expected {
            issuer: IDP,
            audience: SP,
            recipient: ACS,
            request_id: REQUEST,
            trusted: &trusted,
            now: at("2026-09-14T08:01:00"),
            skew: 180,
        };
        change(&mut expected);
        let document = read_message(text, Limits::MESSAGE).expect("a message");
        accept_response(&provider(), &document, &expected)
    }

    fn unchanged(_: &mut Expected<'_>) {}

    fn at_four(expected: &mut Expected<'_>) {
        expected.now = at("2026-09-14T08:04:00");
    }

    /// A response signed on its assertion, on itself or on both is accepted, and
    /// hands back what the assertion says.
    #[test]
    fn a_response_signed_either_way_is_accepted_with_what_it_says() {
        for text in [ASSERTION_SIGNED, RESPONSE_SIGNED, BOTH_SIGNED] {
            assert_eq!(
                outcome(text, unchanged),
                Ok(Accepted {
                    assertion_id: "_assertion".to_owned(),
                    replayable_until: at("2026-09-14T08:05:00"),
                    name_id: "AAdzZWNyZXQx".to_owned(),
                    name_id_format: Some(
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()
                    ),
                    session_index: Some("_session-1".to_owned()),
                    session_not_on_or_after: Some(at("2026-09-14T16:00:00")),
                    authn_instant: at("2026-09-14T07:59:30"),
                    authn_context_class: Some(
                        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                            .to_owned()
                    ),
                    attributes: vec![
                        ("mail".to_owned(), vec!["alice@idp.test".to_owned()]),
                        (
                            "groups".to_owned(),
                            vec!["staff".to_owned(), "admins".to_owned()]
                        ),
                    ],
                })
            );
        }
    }

    /// The response has to be SAML 2.0 and answer this request, at this address,
    /// from this issuer named as an entity, for this service provider; the
    /// assertion names the same issuer; a response nobody asked for is refused.
    #[test]
    fn a_response_answers_this_request_here_from_this_issuer() {
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.request_id =
                "_request-8"),
            Err(Refused::WrongRequest)
        );
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.recipient =
                "https://sp.test/elsewhere"),
            Err(Refused::WrongDestination)
        );
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.issuer =
                "https://other-idp.test"),
            Err(Refused::WrongIssuer)
        );
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.audience =
                "https://other-sp.test"),
            Err(Refused::WrongAudience)
        );
        let unsolicited = ASSERTION_SIGNED.replacen(r#" InResponseTo="_request-7""#, "", 1);
        let old_version = ASSERTION_SIGNED.replacen(
            r#"ID="_response" Version="2.0""#,
            r#"ID="_response" Version="1.1""#,
            1,
        );
        let other_sender = ASSERTION_SIGNED.replacen(
            "<saml:Issuer>https://idp.test/metadata</saml:Issuer>",
            "<saml:Issuer>https://other-idp.test</saml:Issuer>",
            1,
        );
        let person_named = ASSERTION_SIGNED.replacen(
            "<saml:Issuer>https://idp.test/metadata</saml:Issuer>",
            r#"<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">https://idp.test/metadata</saml:Issuer>"#,
            1,
        );
        for (text, refused) in [
            (unsolicited, Refused::Unsolicited),
            (old_version, Refused::NotAResponse),
            (other_sender, Refused::WrongIssuer),
            (person_named, Refused::WrongIssuer),
            (
                include_str!("../tests/fixtures/response-assertion-other-issuer.xml").to_owned(),
                Refused::WrongIssuer,
            ),
        ] {
            assert_ne!(text, ASSERTION_SIGNED);
            assert_eq!(outcome(&text, unchanged), Err(refused.clone()), "{refused}");
        }
    }

    /// Only a bearer confirmation for this address and this request, still open
    /// and with no start of its own, confirms the subject, and the latest one
    /// that holds sets how long the assertion is kept against replay.
    #[test]
    fn only_an_open_bearer_confirmation_confirms_the_subject() {
        for fixture in [
            include_str!("../tests/fixtures/response-holder-of-key.xml"),
            include_str!("../tests/fixtures/response-confirmation-not-before.xml"),
            include_str!("../tests/fixtures/response-other-recipient.xml"),
            include_str!("../tests/fixtures/response-confirmation-other-request.xml"),
        ] {
            assert_eq!(outcome(fixture, unchanged), Err(Refused::Unconfirmed));
        }
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.now =
                at("2026-09-14T08:08:00")),
            Err(Refused::Unconfirmed)
        );
        assert!(
            outcome(ASSERTION_SIGNED, |expected| expected.now =
                at("2026-09-14T08:07:59"))
            .is_ok()
        );
        assert_eq!(
            outcome(
                include_str!("../tests/fixtures/response-two-confirmations.xml"),
                unchanged
            )
            .map(|accepted| accepted.replayable_until),
            Ok(at("2026-09-14T08:07:00"))
        );
    }

    /// Conditions hold the assertion to its time and to this service provider:
    /// one audience restriction at least and every one counting, one-time use at
    /// most once, nothing not understood; a session already closed is refused.
    #[test]
    fn conditions_hold_time_and_audience_and_admit_nothing_unknown() {
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.now =
                at("2026-09-14T07:55:59")),
            Err(Refused::OutOfTime)
        );
        assert!(
            outcome(ASSERTION_SIGNED, |expected| expected.now =
                at("2026-09-14T07:56:00"))
            .is_ok()
        );
        assert!(
            outcome(
                include_str!("../tests/fixtures/response-audience-among-several.xml"),
                unchanged
            )
            .is_ok()
        );
        assert_eq!(
            outcome(
                include_str!("../tests/fixtures/response-conditions-ended.xml"),
                at_four
            ),
            Err(Refused::OutOfTime)
        );
        assert_eq!(
            outcome(
                include_str!("../tests/fixtures/response-session-ended.xml"),
                at_four
            ),
            Err(Refused::OutOfTime)
        );
        for (fixture, refused) in [
            (
                include_str!("../tests/fixtures/response-audiences-anded.xml"),
                Refused::WrongAudience,
            ),
            (
                include_str!("../tests/fixtures/response-no-audience-restriction.xml"),
                Refused::WrongAudience,
            ),
            (
                include_str!("../tests/fixtures/response-no-conditions.xml"),
                Refused::WrongAudience,
            ),
            (
                include_str!("../tests/fixtures/response-proxy-restriction.xml"),
                Refused::UnknownCondition,
            ),
            (
                include_str!("../tests/fixtures/response-conditions-reversed.xml"),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-one-time-use-twice.xml"),
                Refused::Misshapen,
            ),
        ] {
            assert_eq!(
                outcome(fixture, unchanged),
                Err(refused.clone()),
                "{refused}"
            );
        }
    }

    /// A failed status is refused with its codes, and so are the shapes this code
    /// does not read: an encrypted assertion, two assertions, an assertion of
    /// another version, two names, no authentication statement, a comment inside
    /// the name, a time with an offset, and a signed response with no destination.
    #[test]
    fn failures_and_shapes_not_read_are_refused() {
        assert_eq!(
            outcome(include_str!("../tests/fixtures/response-failed.xml"), unchanged),
            Err(Refused::Unsuccessful {
                status: "urn:oasis:names:tc:SAML:2.0:status:Responder / urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".to_owned()
            })
        );
        for (fixture, refused) in [
            (
                include_str!("../tests/fixtures/response-encrypted-assertion.xml"),
                Refused::Encrypted,
            ),
            (
                include_str!("../tests/fixtures/response-two-assertions.xml"),
                Refused::NotOneAssertion,
            ),
            (
                include_str!("../tests/fixtures/response-assertion-version.xml"),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-two-names.xml"),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-no-authn-statement.xml"),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-comment-in-name.xml"),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-offset-time.xml"),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-signed-without-destination.xml"),
                Refused::WrongDestination,
            ),
        ] {
            assert_eq!(
                outcome(fixture, unchanged),
                Err(refused.clone()),
                "{refused}"
            );
        }
    }

    /// A signature that does not verify refuses the response, on the assertion or
    /// on the response; so does a response signed nowhere, and a broken signature
    /// on the assertion inside a response whose own signature holds.
    #[test]
    fn a_signature_that_does_not_verify_refuses_the_response() {
        let renamed = ASSERTION_SIGNED.replacen(">AAdzZWNyZXQx<", ">AAdzZWNyZXQy<", 1);
        assert_eq!(
            outcome(&renamed, unchanged),
            Err(Refused::Unverified(Unverified::DigestMismatch))
        );
        let redirected = RESPONSE_SIGNED.replacen(
            r#"Destination="https://sp.test/realms/main/broker/corp/endpoint""#,
            r#"Destination="https://sp.test/realms/main/broker/corp/endpoint/""#,
            1,
        );
        assert_ne!(redirected, RESPONSE_SIGNED);
        assert_eq!(
            outcome(&redirected, unchanged),
            Err(Refused::Unverified(Unverified::DigestMismatch))
        );
        assert_eq!(
            outcome(ASSERTION_SIGNED, |expected| expected.trusted = &[]),
            Err(Refused::Unverified(Unverified::Untrusted))
        );
        let start = ASSERTION_SIGNED.find("<ds:Signature").expect("a signature");
        let end =
            ASSERTION_SIGNED.find("</ds:Signature>").expect("its end") + "</ds:Signature>".len();
        let unsigned = format!("{}{}", &ASSERTION_SIGNED[..start], &ASSERTION_SIGNED[end..]);
        assert_eq!(
            outcome(&unsigned, unchanged),
            Err(Refused::Unverified(Unverified::Unsigned))
        );
        assert_eq!(
            outcome(
                include_str!("../tests/fixtures/response-both-signed-inner-broken.xml"),
                unchanged
            ),
            Err(Refused::Unverified(Unverified::Untrusted))
        );
    }

    /// A SAML time is UTC: a `Z` or no zone reads the same, fractional seconds are
    /// allowed, and an offset is refused rather than converted.
    #[test]
    fn times_are_read_in_utc_only() {
        let expected = Ok(at("2026-09-14T08:05:00"));
        assert_eq!(instant_of("2026-09-14T08:05:00Z"), expected);
        assert_eq!(instant_of("2026-09-14T08:05:00"), expected);
        assert_eq!(instant_of("2026-09-14T08:05:00.250Z"), expected);
        for refused in [
            "2026-09-14T08:05:00+00:00",
            "2026-09-14T10:05:00+02:00",
            "yesterday",
            "",
        ] {
            assert_eq!(instant_of(refused), Err(Refused::Misshapen), "{refused}");
        }
    }
}
