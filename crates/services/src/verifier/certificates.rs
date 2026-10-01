//! The certificate chain a credential or a status list carries in its `x5c`
//! header (RFC 7515 §4.1.6), held to the authorities its issuer is trusted
//! through: what HAIP 1.0 §6.1 and §6.1.1 have an issuer sign under.

use chrono::{DateTime, Utc};
use crypto::jose::jws::{
    ES256, ES384, ES512, EdDSA, JwsVerifier, PS256, PS384, PS512, RS256, RS384, RS512,
};
use crypto::provider::PublicKey;
use crypto::x509::{RevocationPoints, Unanchored, read_chained_certificate, verify_chain};
use data_encoding::BASE64;
use serde_json::{Map, Value};

/// How many certificates a chain may carry: a leaf and as many authorities as
/// path validation climbs.
const MOST_CERTIFICATES: usize = 9;

/// The largest certificate read, DER.
const MOST_CERTIFICATE_BYTES: usize = 16 * 1024;

pub const CREDENTIAL_UNCHAINED: &str =
    "a credential carries no certificate chain its issuer is trusted by";
pub const CREDENTIAL_UNANCHORED: &str =
    "a credential's chain reaches none of the authorities its issuer is trusted through";
pub const CREDENTIAL_CHAIN_OUT_OF_VALIDITY: &str =
    "a certificate of a credential's chain is not valid now";
pub const CREDENTIAL_NOT_SIGNED_BY_A_SIGNER: &str =
    "a credential is not signed by a certificate an authority issued for signing";
pub const CREDENTIAL_CHAIN_TOO_WEAK: &str =
    "a certificate of a credential's chain holds a key or a signature too weak to trust";
pub const LIST_UNCHAINED: &str =
    "the status list carries no certificate chain its issuer is trusted by";
pub const LIST_UNANCHORED: &str =
    "the status list's chain reaches none of the authorities its issuer is trusted through";
pub const LIST_CHAIN_OUT_OF_VALIDITY: &str =
    "a certificate of the status list's chain is not valid now";
pub const LIST_NOT_SIGNED_BY_A_SIGNER: &str =
    "the status list is not signed by a certificate an authority issued for signing";
pub const LIST_CHAIN_TOO_WEAK: &str =
    "a certificate of the status list's chain holds a key or a signature too weak to trust";

/// Why a chain was not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Untrusted {
    /// No `x5c`, or one that is not certificates in standard base64 within
    /// the bounds.
    NoChain,
    /// The chain reaches none of the issuer's authorities, or does not verify.
    NoAuthority,
    /// A certificate of the chain is not valid now.
    OutOfValidity,
    /// The first certificate issues itself, or is not for signatures.
    NotASigner,
    /// A key or a signature of the chain is under 112 bits of security.
    TooWeak,
}

impl Untrusted {
    /// What a credential's refusal for this says.
    pub fn of_credential(self) -> &'static str {
        match self {
            Self::NoChain => CREDENTIAL_UNCHAINED,
            Self::NoAuthority => CREDENTIAL_UNANCHORED,
            Self::OutOfValidity => CREDENTIAL_CHAIN_OUT_OF_VALIDITY,
            Self::NotASigner => CREDENTIAL_NOT_SIGNED_BY_A_SIGNER,
            Self::TooWeak => CREDENTIAL_CHAIN_TOO_WEAK,
        }
    }

    /// What a status list's refusal for this says.
    pub fn of_list(self) -> &'static str {
        match self {
            Self::NoChain => LIST_UNCHAINED,
            Self::NoAuthority => LIST_UNANCHORED,
            Self::OutOfValidity => LIST_CHAIN_OUT_OF_VALIDITY,
            Self::NotASigner => LIST_NOT_SIGNED_BY_A_SIGNER,
            Self::TooWeak => LIST_CHAIN_TOO_WEAK,
        }
    }
}

/// A certificate of a trusted chain below its anchor, with the authority that
/// issued it: what its revocation is read under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLink {
    /// The serial's magnitude, big-endian.
    pub serial: Vec<u8>,
    pub revocation: RevocationPoints,
    /// The issuing authority's certificate, DER: the next one up the path, or
    /// the anchor.
    pub authority: Vec<u8>,
}

/// A chain held to one of its issuer's authorities.
#[derive(Debug, Clone)]
pub struct TrustedChain {
    /// The leaf's key, which signed what carries the chain.
    pub leaf_key: PublicKey,
    /// The certificates of the path verified below its anchor, leaf first.
    pub links: Vec<ChainLink>,
    /// The authority key identifiers the certificates of the path verified
    /// state: one presented beside the path says nothing of who issued it.
    pub authority_key_identifiers: Vec<Vec<u8>>,
}

/// Hold the chain a JOSE header carries in `x5c`, leaf first, to `anchors`,
/// DER, at `now`: path validated in strict mode up to one of them, its keys
/// and signatures strong enough, the leaf issued by an authority and for
/// signatures.
pub fn trust_chain(
    header: &Map<String, Value>,
    anchors: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<TrustedChain, Untrusted> {
    let chain = read_x5c(header).ok_or(Untrusted::NoChain)?;
    let anchored = verify_chain(&chain, anchors, now.timestamp()).map_err(|why| match why {
        Unanchored::Empty | Unanchored::Unreadable => Untrusted::NoChain,
        Unanchored::OutOfValidity => Untrusted::OutOfValidity,
        Unanchored::SelfSigned | Unanchored::NotForSigning => Untrusted::NotASigner,
        Unanchored::TooWeak => Untrusted::TooWeak,
        Unanchored::NoAnchor | Unanchored::Refused(_) => Untrusted::NoAuthority,
    })?;
    let mut links = Vec::new();
    let mut authority_key_identifiers = Vec::new();
    for pair in anchored.path.windows(2) {
        let read = read_chained_certificate(&pair[0]).ok_or(Untrusted::NoChain)?;
        authority_key_identifiers.extend(read.authority_key_identifier);
        links.push(ChainLink {
            serial: read.serial,
            revocation: read.revocation,
            authority: pair[1].clone(),
        });
    }
    Ok(TrustedChain {
        leaf_key: anchored.leaf_key,
        links,
        authority_key_identifiers,
    })
}

/// The certificates of an `x5c` member, DER: one to nine, each standard
/// base64 of at most 16 KiB.
fn read_x5c(header: &Map<String, Value>) -> Option<Vec<Vec<u8>>> {
    let written = header.get("x5c")?.as_array()?;
    if written.is_empty() || written.len() > MOST_CERTIFICATES {
        return None;
    }
    written
        .iter()
        .map(|certificate| {
            let decoded = BASE64.decode(certificate.as_str()?.as_bytes()).ok()?;
            (decoded.len() <= MOST_CERTIFICATE_BYTES).then_some(decoded)
        })
        .collect()
}

/// A verifier for the algorithm a header names, over the key a certificate
/// certifies. Any other pairing is no verifier.
pub fn verifier_for_certified(algorithm: &str, key: &PublicKey) -> Option<Box<dyn JwsVerifier>> {
    let der = key.der();
    let verifier: Box<dyn JwsVerifier> = match algorithm {
        "ES256" => Box::new(ES256.verifier_from_der(der).ok()?),
        "ES384" => Box::new(ES384.verifier_from_der(der).ok()?),
        "ES512" => Box::new(ES512.verifier_from_der(der).ok()?),
        "EdDSA" => Box::new(EdDSA.verifier_from_der(der).ok()?),
        "RS256" => Box::new(RS256.verifier_from_der(der).ok()?),
        "RS384" => Box::new(RS384.verifier_from_der(der).ok()?),
        "RS512" => Box::new(RS512.verifier_from_der(der).ok()?),
        "PS256" => Box::new(PS256.verifier_from_der(der).ok()?),
        "PS384" => Box::new(PS384.verifier_from_der(der).ok()?),
        "PS512" => Box::new(PS512.verifier_from_der(der).ok()?),
        _ => return None,
    };
    Some(verifier)
}

/// Certificates issued by the crypto crate as a test asks for them.
#[cfg(test)]
pub(crate) mod testing {
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Certifying, certify_key};
    use data_encoding::BASE64;
    use serde_json::{Map, Value, json};

    /// The instant the certificates of a test are valid around.
    pub(crate) const NOW: i64 = 1_790_000_000;

    /// A key and the certificate issued for it.
    pub(crate) struct Certified {
        pub key: EcKeyPair,
        pub certificate: Vec<u8>,
    }

    impl Certified {
        pub(crate) fn public(&self) -> PublicKey {
            PublicKey::from_der(self.key.to_der_public_key())
        }
    }

    /// What one certificate is issued as.
    pub(crate) struct Issued<'a> {
        pub name: &'a str,
        /// Absent for a certificate that issues itself.
        pub issuer: Option<&'a Certified>,
        pub authority: bool,
        pub serial: u8,
        pub revocation_list: Option<&'a str>,
        /// Seconds from `NOW`.
        pub valid: (i64, i64),
    }

    pub(crate) const YEAR: (i64, i64) = (-3_600, 365 * 86_400);

    pub(crate) fn certify(asked: Issued<'_>) -> Certified {
        let key = EcKeyPair::generate(EcCurve::P256).expect("a key");
        let own = PrivateKey::from_der(key.to_der_private_key());
        let issuer_key = asked.issuer.map_or(own, |issuer| {
            PrivateKey::from_der(issuer.key.to_der_private_key())
        });
        let certificate = certify_key(&Certifying {
            subject_key: &PublicKey::from_der(key.to_der_public_key()),
            subject_name: asked.name,
            issuer_certificate: asked.issuer.map(|issuer| issuer.certificate.as_slice()),
            issuer_key: &issuer_key,
            serial: &[asked.serial],
            not_before: NOW + asked.valid.0,
            not_after: NOW + asked.valid.1,
            authority: asked.authority,
            revocation_list: asked.revocation_list,
        })
        .expect("a certificate issued by the crypto crate");
        Certified { key, certificate }
    }

    /// A root, the authority it certified, and a signer under that one.
    pub(crate) struct Hierarchy {
        pub root: Certified,
        pub issuing: Certified,
        pub signer: Certified,
    }

    pub(crate) const ROOT_LIST: &str = "http://ca.example/root.crl";
    pub(crate) const ISSUING_LIST: &str = "http://ca.example/issuing.crl";

    impl Hierarchy {
        pub(crate) fn new() -> Self {
            let root = certify(Issued {
                name: "Root",
                issuer: None,
                authority: true,
                serial: 0x01,
                revocation_list: None,
                valid: YEAR,
            });
            let issuing = certify(Issued {
                name: "Issuing CA",
                issuer: Some(&root),
                authority: true,
                serial: 0x11,
                revocation_list: Some(ROOT_LIST),
                valid: YEAR,
            });
            let signer = certify(Issued {
                name: "Signer",
                issuer: Some(&issuing),
                authority: false,
                serial: 0x21,
                revocation_list: Some(ISSUING_LIST),
                valid: YEAR,
            });
            Self {
                root,
                issuing,
                signer,
            }
        }

        /// A signer the issuing authority certified as `change` says.
        pub(crate) fn signer_issued(&self, change: impl FnOnce(&mut Issued<'_>)) -> Certified {
            let mut asked = Issued {
                name: "Signer",
                issuer: Some(&self.issuing),
                authority: false,
                serial: 0x22,
                revocation_list: Some(ISSUING_LIST),
                valid: YEAR,
            };
            change(&mut asked);
            certify(asked)
        }
    }

    /// A JOSE header carrying `chain` in `x5c`, as RFC 7515 writes it.
    pub(crate) fn header_carrying(chain: &[&[u8]]) -> Map<String, Value> {
        let written: Vec<String> = chain.iter().map(|der| BASE64.encode(der)).collect();
        let Value::Object(header) = json!({ "alg": "ES256", "x5c": written }) else {
            unreachable!()
        };
        header
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{
        Hierarchy, ISSUING_LIST, Issued, NOW, ROOT_LIST, YEAR, certify, header_carrying,
    };
    use super::*;
    use crypto::x509::subject_key_identifier;
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(NOW, 0).expect("a time")
    }

    fn published_at(address: &str) -> RevocationPoints {
        RevocationPoints {
            addresses: vec![address.to_owned()],
            unreadable: false,
        }
    }

    /// A chain held to an authority gives the key that signed, each
    /// certificate below the authority with the one that issued it, and the
    /// authorities the path verified names: a certificate carried beside the
    /// path adds none.
    #[test]
    fn a_chain_is_held_to_its_issuers_authorities_along_the_path_verified() {
        let held = Hierarchy::new();
        let (root, issuing, signer) = (&held.root, &held.issuing, &held.signer);
        let signer_link = ChainLink {
            serial: vec![0x21],
            revocation: published_at(ISSUING_LIST),
            authority: issuing.certificate.clone(),
        };
        let issuing_link = ChainLink {
            serial: vec![0x11],
            revocation: published_at(ROOT_LIST),
            authority: root.certificate.clone(),
        };
        let identifier = |of: &[u8]| subject_key_identifier(of).expect("a key identifier");

        let trusted = trust_chain(
            &header_carrying(&[&signer.certificate, &issuing.certificate]),
            std::slice::from_ref(&root.certificate),
            now(),
        )
        .expect("a chain up to the root");
        assert_eq!(trusted.leaf_key.der(), signer.public().der());
        assert_eq!(trusted.links, [signer_link.clone(), issuing_link.clone()]);
        assert_eq!(
            trusted.authority_key_identifiers,
            [
                identifier(&issuing.certificate),
                identifier(&root.certificate)
            ]
        );

        // An authority deposited is where the path ends, whatever issued it.
        let stranger = Hierarchy::new();
        let trusted = trust_chain(
            &header_carrying(&[&signer.certificate, &issuing.certificate]),
            &[
                stranger.root.certificate.clone(),
                issuing.certificate.clone(),
            ],
            now(),
        )
        .expect("a chain up to the issuing authority");
        assert_eq!(trusted.links, std::slice::from_ref(&signer_link));
        assert_eq!(
            trusted.authority_key_identifiers,
            [identifier(&issuing.certificate)]
        );

        let beside = trust_chain(
            &header_carrying(&[
                &signer.certificate,
                &issuing.certificate,
                &stranger.signer.certificate,
                &stranger.issuing.certificate,
            ]),
            std::slice::from_ref(&root.certificate),
            now(),
        )
        .expect("a chain up to the root");
        assert_eq!(beside.links, [signer_link, issuing_link]);
        assert_eq!(
            beside.authority_key_identifiers,
            [
                identifier(&issuing.certificate),
                identifier(&root.certificate)
            ]
        );

        // A certificate publishing no list is held to its validity alone.
        let unpublished = held.signer_issued(|asked| asked.revocation_list = None);
        let trusted = trust_chain(
            &header_carrying(&[&unpublished.certificate]),
            std::slice::from_ref(&issuing.certificate),
            now(),
        )
        .expect("a chain up to the issuing authority");
        assert_eq!(
            trusted.links,
            [ChainLink {
                serial: vec![0x22],
                revocation: RevocationPoints::default(),
                authority: issuing.certificate.clone(),
            }]
        );
    }

    /// A header's `x5c` is one to nine certificates in standard base64, each
    /// of sixteen kibibytes at most; anything else is no chain.
    #[test]
    fn a_header_carries_a_chain_within_the_bounds_or_none() {
        let certificate = |length: usize| BASE64.encode(&vec![0x30; length]);
        let carrying = |written: Value| {
            let Value::Object(header) = json!({ "x5c": written }) else {
                unreachable!()
            };
            read_x5c(&header)
        };
        assert_eq!(
            carrying(json!([certificate(MOST_CERTIFICATE_BYTES)])),
            Some(vec![vec![0x30; MOST_CERTIFICATE_BYTES]])
        );
        assert_eq!(
            carrying(json!(vec![certificate(3); MOST_CERTIFICATES])),
            Some(vec![vec![0x30; 3]; MOST_CERTIFICATES])
        );
        for written in [
            json!([]),
            json!(certificate(3)),
            json!(vec![certificate(3); MOST_CERTIFICATES + 1]),
            json!([certificate(MOST_CERTIFICATE_BYTES + 1)]),
            json!([certificate(3), 7]),
            json!([certificate(3), BASE64URL_NOPAD.encode(&[0xfb, 0xff])]),
            json!([certificate(3), "MDAw MDAw"]),
        ] {
            assert_eq!(carrying(written.clone()), None, "{written}");
        }
        assert_eq!(read_x5c(&Map::new()), None);

        let anchors = [Hierarchy::new().root.certificate];
        for header in [
            Map::new(),
            header_carrying(&[b"no certificate"]),
            header_carrying(&[]),
        ] {
            assert_eq!(
                trust_chain(&header, &anchors, now()).map(|_| ()),
                Err(Untrusted::NoChain),
                "{header:?}"
            );
        }
    }

    /// A chain is refused for what its path does not hold: an authority of
    /// its issuer, validity now, a first certificate an authority issued for
    /// signatures.
    #[test]
    fn a_chain_is_refused_for_what_its_path_does_not_hold() {
        let held = Hierarchy::new();
        let stranger = Hierarchy::new();
        let root = std::slice::from_ref(&held.root.certificate);
        let alone = certify(Issued {
            name: "Signer",
            issuer: None,
            authority: false,
            serial: 0x31,
            revocation_list: None,
            valid: YEAR,
        });
        let lapsed = held.signer_issued(|asked| asked.valid = (-7_200, -3_600));
        let not_yet = held.signer_issued(|asked| asked.valid = (3_600, 7_200));
        let chained = [&held.signer.certificate, &held.issuing.certificate];
        let refused = |chain: &[&Vec<u8>], anchors: &[Vec<u8>]| {
            let chain: Vec<&[u8]> = chain.iter().map(|der| der.as_slice()).collect();
            trust_chain(&header_carrying(&chain), anchors, now())
                .map(|_| ())
                .expect_err("a chain refused")
        };

        assert_eq!(
            refused(&chained, std::slice::from_ref(&stranger.root.certificate)),
            Untrusted::NoAuthority
        );
        assert_eq!(refused(&chained, &[]), Untrusted::NoAuthority);
        assert_eq!(
            refused(&[&held.signer.certificate], root),
            Untrusted::NoAuthority,
            "the authority between left out"
        );
        assert_eq!(
            refused(
                &[&stranger.signer.certificate, &held.issuing.certificate],
                root
            ),
            Untrusted::NoAuthority,
            "a signer another authority of the same name issued"
        );
        for out_of_validity in [&lapsed, &not_yet] {
            assert_eq!(
                refused(
                    &[&out_of_validity.certificate, &held.issuing.certificate],
                    root
                ),
                Untrusted::OutOfValidity
            );
        }
        assert_eq!(refused(&[&alone.certificate], root), Untrusted::NotASigner);
        assert_eq!(
            refused(
                &[&alone.certificate],
                std::slice::from_ref(&alone.certificate)
            ),
            Untrusted::NotASigner,
            "a certificate issuing itself, even deposited"
        );
        assert_eq!(
            refused(&[&held.issuing.certificate], root),
            Untrusted::NotASigner,
            "an authority's certificate, which is not for signatures"
        );

        // A key under 2048 bits is too weak, whoever certified it.
        let weak = {
            use crypto::jose::jwk::KeyPair;
            use crypto::jose::jwk::alg::rsa::RsaKeyPair;
            use crypto::provider::{PrivateKey, PublicKey};
            use crypto::x509::{Certifying, certify_key};
            let key = RsaKeyPair::generate(1024).expect("a key");
            certify_key(&Certifying {
                subject_key: &PublicKey::from_der(key.to_der_public_key()),
                subject_name: "Signer",
                issuer_certificate: Some(&held.issuing.certificate),
                issuer_key: &PrivateKey::from_der(held.issuing.key.to_der_private_key()),
                serial: &[0x23],
                not_before: NOW - 3_600,
                not_after: NOW + 86_400,
                authority: false,
                revocation_list: None,
            })
            .expect("a certificate issued by the crypto crate")
        };
        assert_eq!(
            refused(&[&weak, &held.issuing.certificate], root),
            Untrusted::TooWeak
        );
    }

    #[test]
    fn a_refusal_is_said_of_a_credential_or_of_a_list() {
        for (why, credential, list) in [
            (Untrusted::NoChain, CREDENTIAL_UNCHAINED, LIST_UNCHAINED),
            (
                Untrusted::NoAuthority,
                CREDENTIAL_UNANCHORED,
                LIST_UNANCHORED,
            ),
            (
                Untrusted::OutOfValidity,
                CREDENTIAL_CHAIN_OUT_OF_VALIDITY,
                LIST_CHAIN_OUT_OF_VALIDITY,
            ),
            (
                Untrusted::NotASigner,
                CREDENTIAL_NOT_SIGNED_BY_A_SIGNER,
                LIST_NOT_SIGNED_BY_A_SIGNER,
            ),
            (
                Untrusted::TooWeak,
                CREDENTIAL_CHAIN_TOO_WEAK,
                LIST_CHAIN_TOO_WEAK,
            ),
        ] {
            assert_eq!((why.of_credential(), why.of_list()), (credential, list));
        }
    }

    /// A certified key verifies under the algorithms of its own family, and
    /// under no other the header may name.
    #[test]
    fn a_certified_key_is_paired_with_its_own_family_of_algorithms() {
        use crypto::jose::jwk::alg::ed::EdKeyPair;
        use crypto::jose::jwk::alg::rsa::RsaKeyPair;
        use crypto::jose::jwk::{Ed25519, KeyPair};
        let signer = Hierarchy::new().signer;
        let edwards = EdKeyPair::generate(Ed25519).expect("a key");
        let rsa = RsaKeyPair::generate(2048).expect("a key");
        let every = [
            "ES256", "ES384", "ES512", "EdDSA", "RS256", "RS384", "RS512", "PS256", "PS384",
            "PS512", "HS256", "none", "", "es256", "ES256K",
        ];
        for (key, verified_under) in [
            (signer.public(), &["ES256"][..]),
            (
                PublicKey::from_der(edwards.to_der_public_key()),
                &["EdDSA"][..],
            ),
            (
                PublicKey::from_der(rsa.to_der_public_key()),
                &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"][..],
            ),
        ] {
            for algorithm in every {
                assert_eq!(
                    verifier_for_certified(algorithm, &key).is_some(),
                    verified_under.contains(&algorithm),
                    "{algorithm} under {verified_under:?}"
                );
            }
        }
    }
}
