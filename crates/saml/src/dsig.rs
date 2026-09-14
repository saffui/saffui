use crypto::provider::{CryptoProvider, HashAlg, PublicKey, SignAlg};
use roxmltree::Node;

use crate::c14n::canonicalize_exclusive;

const XMLDSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE_CANONICALIZATION: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Why a signature was not accepted.
///
/// Precise for the log; a caller answering the outside world says one thing
/// whatever the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unverified {
    #[error("the element carries no signature of its own")]
    Unsigned,
    #[error("the signature is not shaped as a SAML signature")]
    Misshapen,
    #[error("the signature names an algorithm this service does not accept")]
    UnacceptedAlgorithm,
    #[error("the signature does not reference the element it sits in alone")]
    ForeignReference,
    #[error("no trusted key verifies the signature")]
    Untrusted,
    #[error("the signed element does not match its digest")]
    DigestMismatch,
}

/// An element whose enveloped signature a trusted key verified.
#[derive(Debug, Clone, Copy)]
pub struct Signed<'a, 'input> {
    element: Node<'a, 'input>,
}

impl<'a, 'input> Signed<'a, 'input> {
    /// The element the signature covers. What the message says is read from
    /// here down, never from its ancestors or siblings.
    pub fn element(&self) -> Node<'a, 'input> {
        self.element
    }
}

/// Verify the enveloped signature an element carries against the keys its
/// issuer is trusted for, and hand the element back as signed.
///
/// The profile is SAML's and no wider: one signature, a direct child of the
/// element; one reference, to the element's own `ID`, which no other element of
/// the document holds; the enveloped-signature transform then exclusive
/// canonicalization, and nothing else; SHA-2 digests, and RSA or ECDSA over
/// SHA-2. A key the signature carries is ignored: only `trusted` keys decide.
pub fn verify_enveloped_signature<'a, 'input>(
    provider: &dyn CryptoProvider,
    element: Node<'a, 'input>,
    trusted: &[PublicKey],
) -> Result<Signed<'a, 'input>, Unverified> {
    let mut signatures =
        element_children(element).filter(|child| is_signature_element(child, "Signature"));
    let signature = signatures.next().ok_or(Unverified::Unsigned)?;
    if signatures.next().is_some() {
        return Err(Unverified::Misshapen);
    }

    let mut parts = element_children(signature);
    let signed_info = next_named(&mut parts, "SignedInfo")?;
    let signature_value = next_named(&mut parts, "SignatureValue")?;
    match (parts.next(), parts.next()) {
        (None, _) => {}
        (Some(key_info), None) if is_signature_element(&key_info, "KeyInfo") => {}
        _ => return Err(Unverified::Misshapen),
    }

    let mut steps = element_children(signed_info);
    let canonicalization = next_named(&mut steps, "CanonicalizationMethod")?;
    let method = next_named(&mut steps, "SignatureMethod")?;
    let reference = next_named(&mut steps, "Reference")?;
    let mut reference_parts = element_children(reference);
    let transforms = next_named(&mut reference_parts, "Transforms")?;
    let digest_method = next_named(&mut reference_parts, "DigestMethod")?;
    let digest_value = next_named(&mut reference_parts, "DigestValue")?;
    let mut applied = element_children(transforms);
    let enveloped = next_named(&mut applied, "Transform")?;
    let exclusive = next_named(&mut applied, "Transform")?;
    if steps.next().is_some()
        || reference_parts.next().is_some()
        || applied.next().is_some()
        || element_children(method).next().is_some()
        || element_children(enveloped).next().is_some()
    {
        return Err(Unverified::Misshapen);
    }

    if canonicalization.attribute("Algorithm") != Some(EXCLUSIVE_CANONICALIZATION)
        || enveloped.attribute("Algorithm") != Some(ENVELOPED_SIGNATURE)
        || exclusive.attribute("Algorithm") != Some(EXCLUSIVE_CANONICALIZATION)
    {
        return Err(Unverified::UnacceptedAlgorithm);
    }
    let algorithm = method
        .attribute("Algorithm")
        .and_then(signature_algorithm_named)
        .ok_or(Unverified::UnacceptedAlgorithm)?;
    let hash = digest_method
        .attribute("Algorithm")
        .and_then(digest_algorithm_named)
        .ok_or(Unverified::UnacceptedAlgorithm)?;

    let identifier = element
        .attribute("ID")
        .filter(|held| !held.is_empty())
        .ok_or(Unverified::ForeignReference)?;
    let holders = element
        .document()
        .descendants()
        .filter(|node| node.attribute("ID") == Some(identifier))
        .count();
    if reference
        .attribute("URI")
        .and_then(|uri| uri.strip_prefix('#'))
        != Some(identifier)
        || holders != 1
    {
        return Err(Unverified::ForeignReference);
    }

    let signed = canonicalize_exclusive(signed_info, None, &listed_prefixes(canonicalization)?)
        .map_err(|_| Unverified::Misshapen)?;
    let mut value = decoded(signature_value)?;
    if algorithm.is_ecdsa() {
        value = crypto::ecdsa::der_from_raw_signature(&value).map_err(|_| Unverified::Untrusted)?;
    }
    let verified = trusted.iter().any(|key| {
        provider
            .signer()
            .verify(algorithm, key, &signed, &value)
            .unwrap_or(false)
    });
    if !verified {
        return Err(Unverified::Untrusted);
    }

    let covered =
        canonicalize_exclusive(element, Some(signature.id()), &listed_prefixes(exclusive)?)
            .map_err(|_| Unverified::Misshapen)?;
    let computed = provider
        .digest()
        .hash(hash, &covered)
        .map_err(|_| Unverified::DigestMismatch)?;
    if !crypto::constant_time::eq(&computed, &decoded(digest_value)?) {
        return Err(Unverified::DigestMismatch);
    }
    Ok(Signed { element })
}

fn signature_algorithm_named(uri: &str) -> Option<SignAlg> {
    match uri {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Some(SignAlg::Rs256),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Some(SignAlg::Rs384),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Some(SignAlg::Rs512),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Some(SignAlg::Es256),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Some(SignAlg::Es384),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => Some(SignAlg::Es512),
        _ => None,
    }
}

fn digest_algorithm_named(uri: &str) -> Option<HashAlg> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some(HashAlg::Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(HashAlg::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// The InclusiveNamespaces PrefixList a canonicalization method carries, if
/// any; anything else inside the method is refused.
fn listed_prefixes<'a>(method: Node<'a, '_>) -> Result<Vec<&'a str>, Unverified> {
    let mut inside = element_children(method);
    let prefixes = match inside.next() {
        None => Vec::new(),
        Some(list)
            if list.tag_name().namespace() == Some(EXCLUSIVE_CANONICALIZATION)
                && list.tag_name().name() == "InclusiveNamespaces" =>
        {
            list.attribute("PrefixList")
                .unwrap_or_default()
                .split_ascii_whitespace()
                .collect()
        }
        Some(_) => return Err(Unverified::Misshapen),
    };
    if inside.next().is_some() {
        return Err(Unverified::Misshapen);
    }
    Ok(prefixes)
}

/// The bytes a base64 value holds, with the whitespace XML Schema allows
/// between its characters.
fn decoded(node: Node<'_, '_>) -> Result<Vec<u8>, Unverified> {
    if element_children(node).next().is_some() {
        return Err(Unverified::Misshapen);
    }
    let compact: Vec<u8> = node
        .text()
        .unwrap_or_default()
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    data_encoding::BASE64
        .decode(&compact)
        .map_err(|_| Unverified::Misshapen)
}

fn element_children<'a, 'input>(
    parent: Node<'a, 'input>,
) -> impl Iterator<Item = Node<'a, 'input>> {
    parent.children().filter(Node::is_element)
}

fn next_named<'a, 'input>(
    children: &mut impl Iterator<Item = Node<'a, 'input>>,
    name: &str,
) -> Result<Node<'a, 'input>, Unverified> {
    children
        .next()
        .filter(|child| is_signature_element(child, name))
        .ok_or(Unverified::Misshapen)
}

fn is_signature_element(node: &Node<'_, '_>, name: &str) -> bool {
    node.tag_name().namespace() == Some(XMLDSIG) && node.tag_name().name() == name
}

#[cfg(test)]
mod tests {
    use super::{Unverified, verify_enveloped_signature};
    use crate::xml::{Limits, read_message};
    use crypto::provider::openssl::OpenSslProvider;
    use crypto::provider::{CryptoConfig, PublicKey};

    const SIGNED_ASSERTION: &str = include_str!("../tests/fixtures/signed-assertion-rsa.xml");
    const SIGNED_ASSERTION_EC: &str = include_str!("../tests/fixtures/signed-assertion-ec.xml");
    const SIGNED_RESPONSE: &str = include_str!("../tests/fixtures/signed-response-rsa.xml");
    const SIGNED_WITH_LIST: &str =
        include_str!("../tests/fixtures/signed-assertion-listed-rsa.xml");
    const SIGNED_BY_OTHER: &str = include_str!("../tests/fixtures/signed-assertion-other-rsa.xml");

    fn key_of(certificate: &str) -> PublicKey {
        let der = data_encoding::BASE64
            .decode(certificate.trim().as_bytes())
            .expect("base64");
        crypto::x509::public_key_of(&der).expect("a certificate")
    }

    fn idp_rsa() -> PublicKey {
        key_of(include_str!("../tests/fixtures/idp-rsa.cer.b64"))
    }

    fn idp_ec() -> PublicKey {
        key_of(include_str!("../tests/fixtures/idp-ec.cer.b64"))
    }

    /// Verify the first element of that local name, and check that what comes
    /// back as signed is that element.
    fn verdict(text: &str, name: &str, trusted: &[PublicKey]) -> Result<(), Unverified> {
        let provider = OpenSslProvider::new(&CryptoConfig::default()).expect("a provider");
        let document = read_message(text, Limits::MESSAGE).expect("a message");
        let element = document
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == name)
            .expect("the element");
        verify_enveloped_signature(&provider, element, trusted)
            .map(|signed| assert_eq!(signed.element().id(), element.id()))
    }

    /// The signature element cut out of a signed document, and the document
    /// without it.
    fn signature_cut_from(text: &str) -> (String, String) {
        let start = text.find("<ds:Signature").expect("a signature");
        let end = text.find("</ds:Signature>").expect("its end") + "</ds:Signature>".len();
        (
            text[start..end].to_owned(),
            format!("{}{}", &text[..start], &text[end..]),
        )
    }

    /// Signatures an issuer made verify under its key: an assertion signed with
    /// RSA and with ECDSA, a whole response, and a transform listing a prefix.
    #[test]
    fn a_signature_verifies_under_its_issuer_key() {
        assert_eq!(verdict(SIGNED_ASSERTION, "Assertion", &[idp_rsa()]), Ok(()));
        assert_eq!(
            verdict(SIGNED_ASSERTION_EC, "Assertion", &[idp_ec()]),
            Ok(())
        );
        assert_eq!(verdict(SIGNED_RESPONSE, "Response", &[idp_rsa()]), Ok(()));
        assert_eq!(
            verdict(SIGNED_WITH_LIST, "Assertion", &[idp_ec(), idp_rsa()]),
            Ok(())
        );
    }

    /// Only a trusted key decides: another key does not verify, no key verifies
    /// nothing, and a document signed by an untrusted key and carrying its
    /// certificate is refused all the same.
    #[test]
    fn only_a_trusted_key_verifies() {
        assert_eq!(
            verdict(SIGNED_ASSERTION, "Assertion", &[idp_ec()]),
            Err(Unverified::Untrusted)
        );
        assert_eq!(
            verdict(SIGNED_ASSERTION, "Assertion", &[]),
            Err(Unverified::Untrusted)
        );
        assert_eq!(
            verdict(SIGNED_BY_OTHER, "Assertion", &[idp_rsa()]),
            Err(Unverified::Untrusted)
        );
    }

    /// A change to what was signed breaks the digest, however small.
    #[test]
    fn a_changed_element_breaks_its_digest() {
        let changed = SIGNED_ASSERTION.replacen(">alice<", ">mallory<", 1);
        assert_eq!(
            verdict(&changed, "Assertion", &[idp_rsa()]),
            Err(Unverified::DigestMismatch)
        );
    }

    /// A signature belongs to the element it sits in: one relabelled to carry
    /// another identifier is refused, as is one whose identifier a second
    /// element also holds, and an element whose only signature sits deeper
    /// or elsewhere carries none of its own.
    #[test]
    fn a_signature_is_bound_to_the_element_it_sits_in() {
        let relabelled = SIGNED_ASSERTION.replacen(
            r#"<saml:Assertion ID="_assertion""#,
            r#"<saml:Assertion ID="_evil""#,
            1,
        );
        assert_eq!(
            verdict(&relabelled, "Assertion", &[idp_rsa()]),
            Err(Unverified::ForeignReference)
        );
        let duplicated = SIGNED_ASSERTION.replacen(
            "</saml:Issuer><samlp:Status>",
            r#"</saml:Issuer><samlp:Extensions><held ID="_assertion"/></samlp:Extensions><samlp:Status>"#,
            1,
        );
        assert_eq!(
            verdict(&duplicated, "Assertion", &[idp_rsa()]),
            Err(Unverified::ForeignReference)
        );
        let (signature, unsigned) = signature_cut_from(SIGNED_ASSERTION);
        let buried = unsigned.replacen("<saml:Subject>", &format!("<saml:Subject>{signature}"), 1);
        assert_eq!(
            verdict(&buried, "Assertion", &[idp_rsa()]),
            Err(Unverified::Unsigned)
        );
        assert_eq!(
            verdict(SIGNED_RESPONSE, "Assertion", &[idp_rsa()]),
            Err(Unverified::Unsigned)
        );
    }

    /// The profile is SAML's and no wider: a second signature or reference, an
    /// object beside the key, an extra transform, canonicalization keeping
    /// comments, and SHA-1 digests or signatures are refused before any key is
    /// tried.
    #[test]
    fn what_the_profile_does_not_allow_is_refused() {
        let (signature, _) = signature_cut_from(SIGNED_ASSERTION);
        let twice = SIGNED_ASSERTION.replacen(&signature, &format!("{signature}{signature}"), 1);
        assert_eq!(
            verdict(&twice, "Assertion", &[idp_rsa()]),
            Err(Unverified::Misshapen)
        );
        let start = SIGNED_ASSERTION.find("<ds:Reference").expect("a reference");
        let end =
            SIGNED_ASSERTION.find("</ds:Reference>").expect("its end") + "</ds:Reference>".len();
        let reference = &SIGNED_ASSERTION[start..end];
        let referenced_twice =
            SIGNED_ASSERTION.replacen(reference, &format!("{reference}{reference}"), 1);
        assert_eq!(
            verdict(&referenced_twice, "Assertion", &[idp_rsa()]),
            Err(Unverified::Misshapen)
        );
        let transformed = SIGNED_ASSERTION.replacen(
            "<ds:Transforms>",
            r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>"#,
            1,
        );
        assert_eq!(
            verdict(&transformed, "Assertion", &[idp_rsa()]),
            Err(Unverified::Misshapen)
        );
        let with_object =
            SIGNED_ASSERTION.replacen("</ds:KeyInfo>", "</ds:KeyInfo><ds:Object/>", 1);
        assert_ne!(with_object, SIGNED_ASSERTION);
        assert_eq!(
            verdict(&with_object, "Assertion", &[idp_rsa()]),
            Err(Unverified::Misshapen)
        );
        for (accepted, refused) in [
            (
                r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>"#,
            ),
            (
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://www.w3.org/2000/09/xmldsig#sha1",
            ),
            (
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            ),
        ] {
            let weakened = SIGNED_ASSERTION.replacen(accepted, refused, 1);
            assert_ne!(weakened, SIGNED_ASSERTION, "{accepted}");
            assert_eq!(
                verdict(&weakened, "Assertion", &[idp_rsa()]),
                Err(Unverified::UnacceptedAlgorithm),
                "{refused}"
            );
        }
    }
}
