use crypto::provider::{CryptoProvider, PrivateKey, PublicKey};
use roxmltree::{Document, Node};

use crate::dsig::{Unverified, carries_signature, verify_enveloped_signature};
use crate::name_id::{NameId, read_name_id};
use crate::xml::{Limits, children_named, is_named, read_message};
use crate::xmlenc::{Undecrypted, content_cipher_of, decrypt_element};

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
    /// The keys this service provider decrypts assertions with.
    pub decryption_keys: &'e [PrivateKey],
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
    #[error("an assertion under an unauthenticated cipher sits in a response nobody signed")]
    EncryptedUnauthenticated,
    #[error("the encrypted assertion was not read: {0}")]
    Undecrypted(Undecrypted),
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
    pub name_id: NameId,
    /// Names the session a later logout request refers to.
    pub session_index: Option<String>,
    pub session_not_on_or_after: Option<i64>,
    pub authn_instant: i64,
    pub authn_context_class: Option<String>,
    /// Each attribute's name and its plain text values, in document order.
    pub attributes: Vec<(String, Vec<String>)>,
}

/// The request a response says it answers, read before anything in it is verified
/// and only to find that request: `accept_response` then holds the verified
/// response to it.
pub fn read_answered_request_id<'d>(document: &'d Document<'_>) -> Option<&'d str> {
    let response = document.root_element();
    if !is_named(response, PROTOCOL, "Response") {
        return None;
    }
    response.attribute("InResponseTo")
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

    let mut plain = children_named(response, ASSERTION, "Assertion");
    let mut sealed = children_named(response, ASSERTION, "EncryptedAssertion");
    match (plain.next(), plain.next(), sealed.next(), sealed.next()) {
        (Some(assertion), None, None, None) => {
            accept_assertion(provider, assertion, response_signed, expected)
        }
        (None, None, Some(encrypted), None) => {
            // Settled before any key is tried: an unauthenticated cipher
            // decrypted for anyone who asks is an oracle.
            let cipher = content_cipher_of(encrypted).map_err(Refused::Undecrypted)?;
            if !cipher.is_authenticated() && !response_signed {
                return Err(Refused::EncryptedUnauthenticated);
            }
            let plaintext = decrypt_element(provider, encrypted, expected.decryption_keys)
                .map_err(Refused::Undecrypted)?;
            let wrapped = wrapped_in_scope(encrypted, &plaintext)?;
            let decrypted =
                read_message(&wrapped, Limits::MESSAGE).map_err(|_| Refused::Misshapen)?;
            let mut inside = decrypted.root_element().children().filter(Node::is_element);
            match (inside.next(), inside.next()) {
                (Some(assertion), None) if is_named(assertion, ASSERTION, "Assertion") => {
                    accept_assertion(provider, assertion, response_signed, expected)
                }
                _ => Err(Refused::Misshapen),
            }
        }
        _ => Err(Refused::NotOneAssertion),
    }
}

/// Verify the assertion's own signature where the response's does not cover it,
/// or where it carries one anyway, then read it.
fn accept_assertion(
    provider: &dyn CryptoProvider,
    assertion: Node<'_, '_>,
    response_signed: bool,
    expected: &Expected<'_>,
) -> Result<Accepted, Refused> {
    if !response_signed || carries_signature(assertion) {
        verify_enveloped_signature(provider, assertion, expected.trusted)
            .map_err(Refused::Unverified)?;
    }
    read_assertion(assertion, expected)
}

/// The decrypted element inside a wrapper declaring every namespace in scope
/// where the encrypted one stood: XML Encryption lets the plaintext lean on that
/// context for prefixes it does not declare itself.
fn wrapped_in_scope(encrypted: Node<'_, '_>, plaintext: &[u8]) -> Result<String, Refused> {
    let plaintext = std::str::from_utf8(plaintext).map_err(|_| Refused::Misshapen)?;
    let mut wrapped = String::from("<decrypted");
    for namespace in encrypted.namespaces() {
        match namespace.name() {
            Some(prefix) => wrapped.push_str(&format!(" xmlns:{prefix}=\"")),
            None => wrapped.push_str(" xmlns=\""),
        }
        for held in namespace.uri().chars() {
            match held {
                '&' => wrapped.push_str("&amp;"),
                '<' => wrapped.push_str("&lt;"),
                '"' => wrapped.push_str("&quot;"),
                other => wrapped.push(other),
            }
        }
        wrapped.push('"');
    }
    wrapped.push('>');
    wrapped.push_str(plaintext);
    wrapped.push_str("</decrypted>");
    Ok(wrapped)
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
        name_id: read_name_id(name).ok_or(Refused::Misshapen)?,
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

fn instant_of(text: &str) -> Result<i64, Refused> {
    crate::time::read_instant(text).ok_or(Refused::Misshapen)
}

/// The text of an element that holds text alone. A comment or an element inside
/// is refused rather than skipped: reading around a comment is how one
/// identifier turns into another.
fn strict_text(element: Node<'_, '_>) -> Result<String, Refused> {
    crate::xml::strict_text_of(element).ok_or(Refused::Misshapen)
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
    use crate::name_id::NameId;
    use crate::testing::{DrawnKey, key_certified_by, private_key_of, provider};
    use crate::xml::{Limits, read_message};
    use crate::xmlenc::Undecrypted;
    use chrono::NaiveDateTime;
    use crypto::provider::PrivateKey;

    const ACS: &str = "https://sp.test/realms/main/broker/corp/endpoint";
    const SP: &str = "https://sp.test/realms/main";
    const IDP: &str = "https://idp.test/metadata";
    const REQUEST: &str = "_request-7";
    const ASSERTION_SIGNED: &str = include_str!("../tests/fixtures/response-assertion-signed.xml");
    const RESPONSE_SIGNED: &str = include_str!("../tests/fixtures/response-signed.xml");
    const BOTH_SIGNED: &str = include_str!("../tests/fixtures/response-both-signed.xml");
    const QUALIFIED_NAME: &str = include_str!("../tests/fixtures/response-qualified-name.xml");

    fn at(text: &str) -> i64 {
        NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
            .expect("a time")
            .and_utc()
            .timestamp()
    }

    /// The outcome of a response against this service provider's expectations
    /// at 08:01, changed as a case needs.
    fn outcome(text: &str, change: impl FnOnce(&mut Expected<'_>)) -> Result<Accepted, Refused> {
        let keys = [private_key_of(include_str!(
            "../tests/fixtures/sp-encryption.pk8.b64"
        ))];
        outcome_decrypting(text, &keys, change)
    }

    /// The same outcome with the decryption keys a case chooses.
    fn outcome_decrypting(
        text: &str,
        keys: &[PrivateKey],
        change: impl FnOnce(&mut Expected<'_>),
    ) -> Result<Accepted, Refused> {
        let trusted = [key_certified_by(include_str!(
            "../tests/fixtures/idp-rsa.cer.b64"
        ))];
        let mut expected = Expected {
            issuer: IDP,
            audience: SP,
            recipient: ACS,
            request_id: REQUEST,
            trusted: &trusted,
            decryption_keys: keys,
            now: at("2026-09-14T08:01:00"),
            skew: 180,
        };
        change(&mut expected);
        let document = read_message(text, Limits::MESSAGE).expect("a message");
        accept_response(&provider(), &document, &expected)
    }

    fn unchanged(_: &mut Expected<'_>) {}

    /// What the plain assertion of every fixture says.
    fn plain_acceptance() -> Accepted {
        Accepted {
            assertion_id: "_assertion".to_owned(),
            replayable_until: at("2026-09-14T08:05:00"),
            name_id: NameId {
                value: "AAdzZWNyZXQx".to_owned(),
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
                name_qualifier: None,
                sp_name_qualifier: None,
            },
            session_index: Some("_session-1".to_owned()),
            session_not_on_or_after: Some(at("2026-09-14T16:00:00")),
            authn_instant: at("2026-09-14T07:59:30"),
            authn_context_class: Some(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".to_owned(),
            ),
            attributes: vec![
                ("mail".to_owned(), vec!["alice@idp.test".to_owned()]),
                (
                    "groups".to_owned(),
                    vec!["staff".to_owned(), "admins".to_owned()],
                ),
            ],
        }
    }

    fn at_four(expected: &mut Expected<'_>) {
        expected.now = at("2026-09-14T08:04:00");
    }

    /// A response signed on its assertion, on itself or on both is accepted, and
    /// hands back what the assertion says.
    #[test]
    fn a_response_signed_either_way_is_accepted_with_what_it_says() {
        for text in [ASSERTION_SIGNED, RESPONSE_SIGNED, BOTH_SIGNED] {
            assert_eq!(outcome(text, unchanged), Ok(plain_acceptance()));
        }
    }

    /// A name identifier's qualifiers are kept as the identity provider wrote
    /// them, for the logout request that repeats them.
    #[test]
    fn a_qualified_name_is_kept_whole() {
        let accepted = outcome(QUALIFIED_NAME, unchanged).expect("an accepted response");
        assert_eq!(
            accepted.name_id,
            NameId {
                value: "AAdzZWNyZXQx".to_owned(),
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
                name_qualifier: Some(IDP.to_owned()),
                sp_name_qualifier: Some(SP.to_owned()),
            }
        );
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
    /// does not read: an encrypted assertion naming no cipher, two assertions, an assertion of
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
                Refused::Undecrypted(Undecrypted::Misshapen),
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

    /// An encrypted assertion reads like a plain one once decrypted: under CBC in
    /// a signed response, under GCM in an unsigned one, with RSA-OAEP naming its
    /// digests either way or leaving them to their defaults, its key beside the
    /// data, prefixes left to the response to declare, and a namespace whose name
    /// needs escaping.
    #[test]
    fn an_encrypted_assertion_reads_like_a_plain_one() {
        let gcm = include_str!("../tests/fixtures/response-encrypted-gcm.xml");
        let without_digest = gcm.replacen(
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>"#,
            "",
            1,
        );
        let odd_namespace = gcm.replacen(
            "<samlp:Response ",
            r#"<samlp:Response xmlns:odd="urn:a&amp;b&quot;&lt;" "#,
            1,
        );
        for text in [
            include_str!("../tests/fixtures/response-encrypted-cbc-signed.xml").to_owned(),
            gcm.to_owned(),
            include_str!("../tests/fixtures/response-encrypted-oaep-sha256.xml").to_owned(),
            include_str!("../tests/fixtures/response-encrypted-oaep-sha256-mgf256.xml").to_owned(),
            include_str!("../tests/fixtures/response-encrypted-sibling-key.xml").to_owned(),
            include_str!("../tests/fixtures/response-encrypted-context-namespaces.xml").to_owned(),
            without_digest,
            odd_namespace,
        ] {
            assert_eq!(outcome(&text, unchanged), Ok(plain_acceptance()));
        }
    }

    /// An encrypted assertion is read only when it can be trusted: CBC in an
    /// unsigned response is refused before any key is tried; a decrypted
    /// assertion signed nowhere needs a signed response; a tampered or short
    /// body, a bad padding, a key of the wrong length or not ours, RSA 1.5, a
    /// named MGF on the 2001 form, parameters, content held elsewhere, two keys,
    /// another type, extra parts, and something other than an assertion or
    /// beside a plain one are refused.
    #[test]
    fn an_encrypted_assertion_is_read_only_when_it_can_be_trusted() {
        let cbc_unsigned = include_str!("../tests/fixtures/response-encrypted-cbc-unsigned.xml");
        assert_eq!(
            outcome(cbc_unsigned, unchanged),
            Err(Refused::EncryptedUnauthenticated)
        );
        assert_eq!(
            outcome_decrypting(cbc_unsigned, &[], unchanged),
            Err(Refused::EncryptedUnauthenticated)
        );
        let gcm = include_str!("../tests/fixtures/response-encrypted-gcm.xml");
        let other_key = [DrawnKey::draw_rsa().to_private_key()];
        for keys in [&other_key[..], &[]] {
            assert_eq!(
                outcome_decrypting(gcm, keys, unchanged),
                Err(Refused::Undecrypted(Undecrypted::Undecryptable))
            );
        }

        let our_key = private_key_of(include_str!("../tests/fixtures/sp-encryption.pk8.b64"));
        let both = [other_key[0].clone(), our_key];
        assert_eq!(
            outcome_decrypting(gcm, &both, unchanged),
            Ok(plain_acceptance())
        );

        let digest = r#"<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>"#;
        let with_parameters = gcm.replacen(
            digest,
            &format!("{digest}<xenc:OAEPparams>AAAA</xenc:OAEPparams>"),
            1,
        );
        let digest_twice = gcm.replacen(digest, &format!("{digest}{digest}"), 1);
        let named_mgf = gcm.replacen(
            digest,
            &format!(r#"{digest}<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>"#),
            1,
        );
        let start = gcm.rfind("<xenc:CipherData>").expect("the content");
        let end = gcm.rfind("</xenc:CipherData>").expect("its end") + "</xenc:CipherData>".len();
        let held_elsewhere = format!(
            r##"{}<xenc:CipherData><xenc:CipherReference URI="#elsewhere"/></xenc:CipherData>{}"##,
            &gcm[..start],
            &gcm[end..]
        );
        let short_body = format!(
            "{}<xenc:CipherData><xenc:CipherValue>AAAAAAAAAAA=</xenc:CipherValue></xenc:CipherData>{}",
            &gcm[..start],
            &gcm[end..]
        );
        let with_properties = format!("{}<xenc:EncryptionProperties/>{}", &gcm[..end], &gcm[end..]);
        let other_type = gcm.replacen(
            r#"Type="http://www.w3.org/2001/04/xmlenc#Element""#,
            r#"Type="http://www.w3.org/2001/04/xmlenc#Content""#,
            1,
        );
        let sized_method = gcm.replacen(
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>"#,
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"><xenc:KeySize>256</xenc:KeySize></xenc:EncryptionMethod>"#,
            1,
        );
        let beside_data = gcm.replacen(
            "</saml:EncryptedAssertion>",
            "<saml:Other/></saml:EncryptedAssertion>",
            1,
        );
        let unknown_key_part = gcm.replacen(
            "</xenc:EncryptedKey>",
            "<xenc:Unknown/></xenc:EncryptedKey>",
            1,
        );
        let sibling = include_str!("../tests/fixtures/response-encrypted-sibling-key.xml");
        let key_start = sibling.rfind("<xenc:EncryptedKey").expect("the key");
        let key_end =
            sibling.rfind("</xenc:EncryptedKey>").expect("its end") + "</xenc:EncryptedKey>".len();
        let two_keys = format!(
            "{}{}{}",
            &sibling[..key_end],
            &sibling[key_start..key_end],
            &sibling[key_end..]
        );

        let undecryptable = Refused::Undecrypted(Undecrypted::Undecryptable);
        let misshapen = Refused::Undecrypted(Undecrypted::Misshapen);
        for (text, refused) in [
            (
                include_str!("../tests/fixtures/response-encrypted-gcm-unsigned-assertion.xml")
                    .to_owned(),
                Refused::Unverified(Unverified::Unsigned),
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-gcm-tampered.xml").to_owned(),
                undecryptable.clone(),
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-cbc-padding-zero.xml")
                    .to_owned(),
                undecryptable.clone(),
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-cbc-padding-long.xml")
                    .to_owned(),
                undecryptable.clone(),
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-cbc-short-body.xml").to_owned(),
                undecryptable.clone(),
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-short-key.xml").to_owned(),
                undecryptable.clone(),
            ),
            (short_body, undecryptable.clone()),
            (
                include_str!("../tests/fixtures/response-encrypted-rsa15.xml").to_owned(),
                Refused::Undecrypted(Undecrypted::UnacceptedAlgorithm),
            ),
            (
                named_mgf,
                Refused::Undecrypted(Undecrypted::UnacceptedAlgorithm),
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-not-assertion.xml").to_owned(),
                Refused::Misshapen,
            ),
            (
                include_str!("../tests/fixtures/response-encrypted-and-plain.xml").to_owned(),
                Refused::NotOneAssertion,
            ),
            (with_parameters, misshapen.clone()),
            (digest_twice, misshapen.clone()),
            (held_elsewhere, misshapen.clone()),
            (two_keys, misshapen.clone()),
            (other_type, misshapen.clone()),
            (with_properties, misshapen.clone()),
            (sized_method, misshapen.clone()),
            (beside_data, misshapen.clone()),
            (unknown_key_part, misshapen.clone()),
        ] {
            assert_ne!(text, gcm);
            assert_eq!(outcome(&text, unchanged), Err(refused.clone()), "{refused}");
        }
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

#[cfg(test)]
mod answered_request_tests {
    use super::read_answered_request_id;
    use crate::xml::{Limits, read_message};

    /// The request a response names is read from a SAML response alone: another
    /// message, or an element outside the protocol's namespace, names none.
    #[test]
    fn the_request_a_response_answers_is_read_from_a_response_alone() {
        for (xml, answered) in [
            (
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="_request"/>"#,
                Some("_request"),
            ),
            (
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
                None,
            ),
            (
                r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="_request"/>"#,
                None,
            ),
            (r#"<Response InResponseTo="_request"/>"#, None),
        ] {
            let document = read_message(xml, Limits::MESSAGE).expect("well-formed");
            assert_eq!(read_answered_request_id(&document), answered, "{xml}");
        }
    }
}
