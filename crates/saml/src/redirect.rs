use std::io::{Read, Write};

use crypto::provider::{CryptoProvider, PublicKey, SignAlg};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use crate::dsig::{Unverified, signature_algorithm_named};
use crate::xml::Limits;

/// Which message a Redirect query carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carried {
    Request,
    Response,
}

impl Carried {
    fn parameter(self) -> &'static str {
        match self {
            Self::Request => "SAMLRequest",
            Self::Response => "SAMLResponse",
        }
    }
}

/// Why a message could not be put on a Redirect query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unencodable {
    #[error("the message could not be compressed")]
    Compression,
    #[error("the signature algorithm is not one this service signs queries with")]
    UnsupportedAlgorithm,
    #[error("the key did not sign")]
    Unsigned,
}

/// Why a Redirect query was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undecodable {
    #[error("the query is not shaped as the Redirect binding")]
    Misshapen,
    #[error("the message inflates beyond the limit")]
    TooLarge,
    #[error("the signature names an algorithm this service does not accept")]
    UnacceptedAlgorithm,
}

/// A signature a Redirect query carries, and the octets it covers as they arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySignature {
    pub algorithm: SignAlg,
    pub octets: Vec<u8>,
    pub value: Vec<u8>,
}

/// What a Redirect query carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub carried: Carried,
    pub message: String,
    pub relay_state: Option<String>,
    pub signature: Option<QuerySignature>,
}

/// The query string carrying a message over the Redirect binding: compressed,
/// encoded, and signed with `sign` over `SAMLRequest=…&RelayState=…&SigAlg=…`
/// as the binding orders them.
///
/// `sign` answers with what the seam's signer makes. RSA only: a realm signs its
/// requests with its RSA key, and an ECDSA signature would need re-encoding.
pub fn encode_query(
    carried: Carried,
    message: &str,
    relay_state: Option<&str>,
    algorithm: SignAlg,
    sign: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<String, Unencodable> {
    let uri = signature_uri_of(algorithm).ok_or(Unencodable::UnsupportedAlgorithm)?;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(message.as_bytes())
        .map_err(|_| Unencodable::Compression)?;
    let compressed = encoder.finish().map_err(|_| Unencodable::Compression)?;
    let mut query = format!(
        "{}={}",
        carried.parameter(),
        percent_encoded(&data_encoding::BASE64.encode(&compressed))
    );
    if let Some(relay_state) = relay_state {
        query.push_str("&RelayState=");
        query.push_str(&percent_encoded(relay_state));
    }
    query.push_str("&SigAlg=");
    query.push_str(&percent_encoded(uri));
    let signature = sign(query.as_bytes()).ok_or(Unencodable::Unsigned)?;
    query.push_str("&Signature=");
    query.push_str(&percent_encoded(&data_encoding::BASE64.encode(&signature)));
    Ok(query)
}

/// Read a Redirect query as it arrived: the message inflated under `limits`,
/// and any signature kept with the query's own octets, never re-encoded, since
/// senders escape differently. Parameters the binding does not name are left
/// out of both.
pub fn decode_query(raw: &str, limits: Limits) -> Result<Received, Undecodable> {
    let (mut message, mut relay, mut algorithm, mut signature) = (None, None, None, None);
    for pair in raw.split('&') {
        let (name, value) = pair.split_once('=').ok_or(Undecodable::Misshapen)?;
        let slot = match name {
            "SAMLRequest" | "SAMLResponse" => &mut message,
            "RelayState" => &mut relay,
            "SigAlg" => &mut algorithm,
            "Signature" => &mut signature,
            _ => continue,
        };
        if slot.is_some() {
            return Err(Undecodable::Misshapen);
        }
        *slot = Some((name, value));
    }

    let (message_name, message_value) = message.ok_or(Undecodable::Misshapen)?;
    let carried = if message_name == "SAMLRequest" {
        Carried::Request
    } else {
        Carried::Response
    };
    let compressed = data_encoding::BASE64
        .decode(percent_decoded(message_value)?.as_bytes())
        .map_err(|_| Undecodable::Misshapen)?;
    let mut inflated = Vec::new();
    DeflateDecoder::new(compressed.as_slice())
        .take(limits.bytes as u64 + 1)
        .read_to_end(&mut inflated)
        .map_err(|_| Undecodable::Misshapen)?;
    if inflated.len() > limits.bytes {
        return Err(Undecodable::TooLarge);
    }
    let message = String::from_utf8(inflated).map_err(|_| Undecodable::Misshapen)?;
    let relay_state = relay.map(|(_, value)| percent_decoded(value)).transpose()?;

    let signature = match (algorithm, signature) {
        (None, None) => None,
        (Some((_, algorithm_value)), Some((_, signature_value))) => {
            let algorithm = signature_algorithm_named(&percent_decoded(algorithm_value)?)
                .ok_or(Undecodable::UnacceptedAlgorithm)?;
            let mut octets = format!("{message_name}={message_value}");
            if let Some((_, relay_value)) = relay {
                octets.push_str("&RelayState=");
                octets.push_str(relay_value);
            }
            octets.push_str("&SigAlg=");
            octets.push_str(algorithm_value);
            let value = data_encoding::BASE64
                .decode(percent_decoded(signature_value)?.as_bytes())
                .map_err(|_| Undecodable::Misshapen)?;
            Some(QuerySignature {
                algorithm,
                octets: octets.into_bytes(),
                value,
            })
        }
        _ => return Err(Undecodable::Misshapen),
    };
    Ok(Received {
        carried,
        message,
        relay_state,
        signature,
    })
}

/// Verify a Redirect query's signature against the keys its sender is trusted for.
pub fn verify_query_signature(
    provider: &dyn CryptoProvider,
    signature: &QuerySignature,
    trusted: &[PublicKey],
) -> Result<(), Unverified> {
    let value = if signature.algorithm.is_ecdsa() {
        crypto::ecdsa::der_from_raw_signature(&signature.value)
            .map_err(|_| Unverified::Untrusted)?
    } else {
        signature.value.clone()
    };
    let verified = trusted.iter().any(|key| {
        provider
            .signer()
            .verify(signature.algorithm, key, &signature.octets, &value)
            .unwrap_or(false)
    });
    if verified {
        Ok(())
    } else {
        Err(Unverified::Untrusted)
    }
}

fn signature_uri_of(algorithm: SignAlg) -> Option<&'static str> {
    match algorithm {
        SignAlg::Rs256 => Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        SignAlg::Rs384 => Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"),
        SignAlg::Rs512 => Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"),
        _ => None,
    }
}

/// RFC 3986 escaping: the unreserved characters kept, every other byte written
/// as an upper case escape.
fn percent_encoded(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Escapes undone in either case; a `+` stays a `+`, which base64 needs.
fn percent_decoded(value: &str) -> Result<String, Undecodable> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
                .ok_or(Undecodable::Misshapen)?;
            let text = std::str::from_utf8(hex).map_err(|_| Undecodable::Misshapen)?;
            decoded.push(u8::from_str_radix(text, 16).map_err(|_| Undecodable::Misshapen)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| Undecodable::Misshapen)
}

#[cfg(test)]
mod tests {
    use super::{
        Carried, Undecodable, Unencodable, decode_query, encode_query, percent_encoded,
        verify_query_signature,
    };
    use crate::dsig::Unverified;
    use crate::testing::{key_certified_by, private_key_of, provider};
    use crate::xml::Limits;
    use crypto::provider::{CryptoProvider, PublicKey, SignAlg};
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    const MESSAGE: &str = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0" IssueInstant="2026-09-14T08:00:00Z"/>"#;

    fn signed(relay_state: Option<&str>) -> String {
        let provider = provider();
        let key = private_key_of(include_str!("../tests/fixtures/idp-rsa.pk8.b64"));
        encode_query(
            Carried::Request,
            MESSAGE,
            relay_state,
            SignAlg::Rs256,
            &|octets| provider.signer().sign(SignAlg::Rs256, &key, octets).ok(),
        )
        .expect("a query")
    }

    fn trusted() -> Vec<PublicKey> {
        vec![key_certified_by(include_str!(
            "../tests/fixtures/idp-rsa.cer.b64"
        ))]
    }

    /// A signed query carries the message and the relay state back unchanged, with
    /// or without a relay state, and its signature verifies under the signer's key.
    #[test]
    fn a_signed_query_round_trips_and_verifies() {
        for relay_state in [Some("back to the page & more"), None] {
            let query = signed(relay_state);
            let received = decode_query(&query, Limits::MESSAGE).expect("a query");
            assert_eq!(received.carried, Carried::Request);
            assert_eq!(received.message, MESSAGE);
            assert_eq!(received.relay_state.as_deref(), relay_state);
            let signature = received.signature.expect("a signature");
            assert_eq!(
                verify_query_signature(&provider(), &signature, &trusted()),
                Ok(())
            );
        }
    }

    /// The signature covers the query as it arrived: a sender escaping in lower
    /// case still verifies, and a relay state changed after signing does not.
    #[test]
    fn the_signature_covers_the_octets_as_they_arrived() {
        let lowercase = include_str!("../tests/fixtures/redirect-query-lowercase.txt").trim();
        let received = decode_query(lowercase, Limits::MESSAGE).expect("a query");
        assert_eq!(received.relay_state.as_deref(), Some("state & more"));
        let signature = received.signature.expect("a signature");
        assert_eq!(
            verify_query_signature(&provider(), &signature, &trusted()),
            Ok(())
        );

        let moved = signed(Some("back")).replacen("RelayState=back", "RelayState=elsewhere", 1);
        let received = decode_query(&moved, Limits::MESSAGE).expect("a query");
        let signature = received.signature.expect("a signature");
        assert_eq!(
            verify_query_signature(&provider(), &signature, &trusted()),
            Err(Unverified::Untrusted)
        );
    }

    /// What the binding does not allow is refused: a message twice, an algorithm
    /// without a signature, SHA-1, a broken escape, no message, a message that
    /// inflates past the limit, and ECDSA for a query this service signs.
    #[test]
    fn what_the_binding_does_not_allow_is_refused() {
        let query = signed(None);
        let (message, _) = query.split_once("&SigAlg=").expect("a message");
        let without_signature = &query[..query.find("&Signature=").expect("a signature")];
        for (text, refused) in [
            (format!("{message}&{message}"), Undecodable::Misshapen),
            (without_signature.to_owned(), Undecodable::Misshapen),
            (
                query.replacen(
                    "2001%2F04%2Fxmldsig-more%23rsa-sha256",
                    "2000%2F09%2Fxmldsig%23rsa-sha1",
                    1,
                ),
                Undecodable::UnacceptedAlgorithm,
            ),
            (format!("{message}%zz"), Undecodable::Misshapen),
            ("RelayState=alone".to_owned(), Undecodable::Misshapen),
        ] {
            assert_ne!(text, query);
            assert_eq!(
                decode_query(&text, Limits::MESSAGE).err(),
                Some(refused),
                "{text}"
            );
        }

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&vec![b'<'; 300 * 1024])
            .expect("compressed");
        let bomb = encoder.finish().expect("compressed");
        let exploding = format!(
            "SAMLRequest={}",
            percent_encoded(&data_encoding::BASE64.encode(&bomb))
        );
        assert!(exploding.len() < 8 * 1024, "the bomb is small on the wire");
        assert_eq!(
            decode_query(&exploding, Limits::MESSAGE).err(),
            Some(Undecodable::TooLarge)
        );

        let unsigned = encode_query(Carried::Request, MESSAGE, None, SignAlg::Es256, &|_| {
            Some(Vec::new())
        });
        assert_eq!(unsigned, Err(Unencodable::UnsupportedAlgorithm));
    }
}
