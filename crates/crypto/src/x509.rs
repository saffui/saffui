use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509Builder, X509Name, X509NameBuilder, X509StoreContext};

use crate::provider::{PrivateKey, PublicKey};

/// The public key a DER certificate certifies, as the SubjectPublicKeyInfo the
/// signer verifies with; nothing when the bytes are not a certificate.
pub fn public_key_of(der: &[u8]) -> Option<PublicKey> {
    let certificate = openssl::x509::X509::from_der(der).ok()?;
    let key = certificate.public_key().ok()?;
    key.public_key_to_der().ok().map(PublicKey::from_der)
}

/// The URI subject-alternative-names of a DER certificate, in order. What a
/// workload mesh writes its identity in; empty when the certificate has
/// none, nothing when it is not a certificate at all.
pub fn san_uris(der: &[u8]) -> Option<Vec<String>> {
    let certificate = openssl::x509::X509::from_der(der).ok()?;
    Some(
        certificate
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.uri().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// The DNS subject-alternative-names of a DER certificate, in order. Empty
/// when the certificate has none, nothing when it is not a certificate.
pub fn san_dns(der: &[u8]) -> Option<Vec<String>> {
    let certificate = openssl::x509::X509::from_der(der).ok()?;
    Some(
        certificate
            .subject_alt_names()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.dnsname().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// The subject DN of a DER certificate, as this build canonicalises it:
/// RFC 4514 order (most specific entry first), short attribute names, and
/// RFC 4514 escaping. The one rendering, stated so a registration knows
/// exactly what to hold: what openssl parsed, reversed, joined by commas,
/// with no spaces this function did not escape.
pub fn subject_dn(der: &[u8]) -> Option<String> {
    let certificate = openssl::x509::X509::from_der(der).ok()?;
    let mut entries = Vec::new();
    for entry in certificate.subject_name().entries() {
        let name = entry
            .object()
            .nid()
            .short_name()
            .map(str::to_owned)
            // A type openssl has no name for is its dotted OID, which is
            // what RFC 4514 says to write.
            .unwrap_or_else(|_| entry.object().to_string());
        // Strictly UTF-8, and never a NUL: a name that truncates at an
        // interior NUL is the classic impersonation, so a DN holding one is
        // no DN at all rather than a shorter one.
        let value = std::str::from_utf8(entry.data().as_slice()).ok()?;
        if value.contains('\0') {
            return None;
        }
        entries.push(format!("{name}={}", dn_escaped(value)));
    }
    entries.reverse();
    Some(entries.join(","))
}

/// RFC 4514 §2.4: the characters that would read as structure are escaped,
/// and so are the blanks and the hash that would move at the edges.
fn dn_escaped(value: &str) -> String {
    let mut written = String::with_capacity(value.len());
    let last = value.chars().count().saturating_sub(1);
    for (place, held) in value.chars().enumerate() {
        let edge = (place == 0 && (held == ' ' || held == '#')) || (place == last && held == ' ');
        if edge || matches!(held, '"' | '+' | ',' | ';' | '<' | '>' | '\\' | '=') {
            written.push('\\');
        }
        written.push(held);
    }
    written
}

/// What a certificate is issued for and under.
#[derive(Debug, Clone, Copy)]
pub struct Issuance<'a> {
    pub subject_key: &'a PublicKey,
    /// The common name the certificate gives its subject.
    pub subject_name: &'a str,
    /// An RSA key, whose signatures are deterministic.
    pub issuer_key: &'a PrivateKey,
    pub issuer_name: &'a str,
    /// Big-endian; a positive number whose encoding fits 20 octets (RFC 5280 §4.1.2.2).
    pub serial: &'a [u8],
    /// Seconds since the epoch.
    pub not_before: i64,
    pub not_after: i64,
}

/// The kind and strength of the key a certificate certifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedKey {
    Rsa {
        bits: u32,
    },
    /// On the curve JOSE names P-256, P-384 or P-521, or on another one.
    Ec {
        curve: Option<&'static str>,
    },
    Other,
}

/// What decides whether a certificate's key is fit to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateFacts {
    pub key: CertifiedKey,
    /// Seconds since the epoch.
    pub not_after: i64,
}

/// A version 3 certificate for the subject's key, signed with SHA-256 under the
/// issuer's RSA key. The same issuance gives the same bytes, so a realm can publish
/// certificates for its keys without storing them. Nothing when a key does not
/// parse, the issuer is not RSA, the serial is out of bounds or a time does not fit.
pub fn issue_certificate(issuance: &Issuance<'_>) -> Option<Vec<u8>> {
    let issuer = PKey::private_key_from_der(issuance.issuer_key.der()).ok()?;
    if issuer.id() != Id::RSA {
        return None;
    }
    let number = BigNum::from_slice(issuance.serial).ok()?;
    if !(1..=159).contains(&number.num_bits()) {
        return None;
    }
    let subject = PKey::public_key_from_der(issuance.subject_key.der()).ok()?;
    let serial = number.to_asn1_integer().ok()?;
    let subject_name = build_common_name(issuance.subject_name)?;
    let issuer_name = build_common_name(issuance.issuer_name)?;
    let not_before = Asn1Time::from_unix(issuance.not_before).ok()?;
    let not_after = Asn1Time::from_unix(issuance.not_after).ok()?;
    let mut builder = X509Builder::new().ok()?;
    builder.set_version(2).ok()?;
    builder.set_serial_number(&serial).ok()?;
    builder.set_subject_name(&subject_name).ok()?;
    builder.set_issuer_name(&issuer_name).ok()?;
    builder.set_pubkey(&subject).ok()?;
    builder.set_not_before(&not_before).ok()?;
    builder.set_not_after(&not_after).ok()?;
    builder.sign(&issuer, MessageDigest::sha256()).ok()?;
    builder.build().to_der().ok()
}

/// The facts of a DER certificate; nothing when it is not a certificate.
pub fn read_certificate_facts(der: &[u8]) -> Option<CertificateFacts> {
    let certificate = X509::from_der(der).ok()?;
    let key = certificate.public_key().ok()?;
    let certified = match key.id() {
        Id::RSA => CertifiedKey::Rsa { bits: key.bits() },
        Id::EC => CertifiedKey::Ec {
            curve: match key.ec_key().ok()?.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => Some("P-256"),
                Some(Nid::SECP384R1) => Some("P-384"),
                Some(Nid::SECP521R1) => Some("P-521"),
                _ => None,
            },
        },
        _ => CertifiedKey::Other,
    };
    let lived = Asn1Time::from_unix(0)
        .ok()?
        .diff(certificate.not_after())
        .ok()?;
    Some(CertificateFacts {
        key: certified,
        not_after: i64::from(lived.days) * 86_400 + i64::from(lived.secs),
    })
}

/// How many certificates OpenSSL may climb from a leaf to its anchor: more than
/// any real hierarchy needs, and a bound on the work a presented chain asks for.
const CHAIN_DEPTH: i32 = 8;

/// A chain that ends at one of the anchors a caller trusts.
#[derive(Debug, Clone)]
pub struct AnchoredChain {
    /// The leaf's SubjectPublicKeyInfo, as the signer verifies with.
    pub leaf_key: PublicKey,
    /// Which of the anchors handed in the chain ended at.
    pub anchor: usize,
}

/// Why a chain ends at no anchor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unanchored {
    #[error("no certificate was presented")]
    Empty,
    #[error("a certificate does not parse")]
    Unreadable,
    #[error("the chain reaches none of the trusted anchors")]
    NoAnchor,
    #[error("a certificate in the chain is not valid at the instant asked")]
    OutOfValidity,
    #[error("the chain does not verify: {0}")]
    Refused(String),
}

/// Verify a chain, leaf first as `x5c` carries it, up to one of `anchors`, at
/// the instant `at` in seconds since the epoch rather than at the clock's.
///
/// Path validation is OpenSSL's, in strict mode. An anchor may be an
/// intermediate authority: trusting it is what depositing it means, and the
/// chain need not climb past it. Nothing is fetched, so revocation lists and
/// OCSP are not consulted.
pub fn verify_chain(
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: i64,
) -> Result<AnchoredChain, Unanchored> {
    let (leaf, intermediates) = chain.split_first().ok_or(Unanchored::Empty)?;
    let leaf = X509::from_der(leaf).map_err(|_| Unanchored::Unreadable)?;
    let mut presented = Stack::new().map_err(|_| unverifiable())?;
    for der in intermediates {
        let certificate = X509::from_der(der).map_err(|_| Unanchored::Unreadable)?;
        presented.push(certificate).map_err(|_| unverifiable())?;
    }

    let mut trusted = Vec::with_capacity(anchors.len());
    let mut store = X509StoreBuilder::new().map_err(|_| unverifiable())?;
    for der in anchors {
        let anchor = X509::from_der(der).map_err(|_| Unanchored::Unreadable)?;
        trusted.push(anchor.to_der().map_err(|_| unverifiable())?);
        store.add_cert(anchor).map_err(|_| unverifiable())?;
    }
    let mut judged = X509VerifyParam::new().map_err(|_| unverifiable())?;
    judged
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::PARTIAL_CHAIN)
        .map_err(|_| unverifiable())?;
    judged.set_time(at);
    judged.set_depth(CHAIN_DEPTH);
    store.set_param(&judged).map_err(|_| unverifiable())?;
    let store = store.build();

    let mut context = X509StoreContext::new().map_err(|_| unverifiable())?;
    let (verified, error, reached) = context
        .init(&store, &leaf, &presented, |context| {
            let verified = context.verify_cert()?;
            let reached = context
                .chain()
                .and_then(|chain| chain.iter().last())
                .map(|anchor| anchor.to_der())
                .transpose()?;
            Ok((verified, context.error(), reached))
        })
        .map_err(|_| unverifiable())?;
    if !verified {
        return Err(match error.as_raw() {
            openssl_sys::X509_V_ERR_CERT_NOT_YET_VALID
            | openssl_sys::X509_V_ERR_CERT_HAS_EXPIRED => Unanchored::OutOfValidity,
            openssl_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
            | openssl_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            | openssl_sys::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
            | openssl_sys::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN => Unanchored::NoAnchor,
            _ => Unanchored::Refused(error.error_string().to_owned()),
        });
    }

    let anchor = reached
        .and_then(|reached| trusted.iter().position(|anchor| *anchor == reached))
        .ok_or(Unanchored::NoAnchor)?;
    let leaf_key = leaf
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|_| Unanchored::Unreadable)?;
    Ok(AnchoredChain {
        leaf_key: PublicKey::from_der(leaf_key),
        anchor,
    })
}

fn unverifiable() -> Unanchored {
    Unanchored::Refused("the chain could not be put to OpenSSL".to_owned())
}

/// The subject key identifier a certificate states: how a certificate issued
/// under it names it (RFC 5280 §4.2.1.2), and how a verifier asks a wallet for
/// credentials under that authority. Nothing when it states none.
pub fn subject_key_identifier(der: &[u8]) -> Option<Vec<u8>> {
    let certificate = X509::from_der(der).ok()?;
    certificate
        .subject_key_id()
        .map(|identifier| identifier.as_slice().to_vec())
}

fn build_common_name(name: &str) -> Option<X509Name> {
    let mut builder = X509NameBuilder::new().ok()?;
    builder.append_entry_by_nid(Nid::COMMONNAME, name).ok()?;
    Some(builder.build())
}

#[cfg(test)]
mod tests {
    use super::{
        CertificateFacts, CertifiedKey, Issuance, issue_certificate, public_key_of,
        read_certificate_facts,
    };
    use crate::provider::{PrivateKey, PublicKey};
    use openssl::asn1::{Asn1Time, Asn1TimeRef};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509Builder, X509NameBuilder};

    /// A certificate hands back the key it certifies, in the form the signer
    /// verifies with, and bytes that are no certificate hand back nothing.
    #[test]
    fn a_certificate_hands_back_the_key_it_certifies() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        let key = PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key");
        let mut name = X509NameBuilder::new().expect("a name");
        name.append_entry_by_text("CN", "idp.test")
            .expect("a common name");
        let name = name.build();
        let mut builder = X509Builder::new().expect("a builder");
        builder.set_version(2).expect("version 3");
        builder.set_subject_name(&name).expect("a subject");
        builder.set_issuer_name(&name).expect("an issuer");
        builder.set_pubkey(&key).expect("the key");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("now"))
            .expect("a start");
        builder
            .set_not_after(&Asn1Time::days_from_now(1).expect("tomorrow"))
            .expect("an end");
        builder.sign(&key, MessageDigest::sha256()).expect("signed");
        let der = builder.build().to_der().expect("DER");

        let held = public_key_of(&der).expect("a key");
        assert_eq!(
            held.der(),
            key.public_key_to_der().expect("SPKI").as_slice()
        );
        assert!(public_key_of(b"not a certificate").is_none());
    }

    fn rsa_key(bits: u32) -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(bits).expect("an RSA key")).expect("a key")
    }

    fn ec_key(curve: Nid) -> PKey<Private> {
        let group = EcGroup::from_curve_name(curve).expect("a curve");
        PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key")
    }

    fn seconds_of(time: &Asn1TimeRef) -> i64 {
        let lived = Asn1Time::from_unix(0)
            .expect("the epoch")
            .diff(time)
            .expect("a difference");
        i64::from(lived.days) * 86_400 + i64::from(lived.secs)
    }

    /// A certificate is issued for the subject's key under the issuer's RSA key with
    /// the names, serial and validity asked, signed with SHA-256, and issuing it again
    /// gives the same bytes; an issuer that is not RSA, a key that does not parse or a
    /// serial that is empty, zero or longer than 20 octets gives none.
    #[test]
    fn a_certificate_is_issued_the_same_every_time() {
        let issuer = rsa_key(2048);
        let issuer_key = PrivateKey::from_der(issuer.private_key_to_der().expect("PKCS#8"));
        let subject = ec_key(Nid::X9_62_PRIME256V1);
        let subject_key = PublicKey::from_der(subject.public_key_to_der().expect("SPKI"));
        let serial = [0x7f, 0x01, 0x02];
        let issuance = Issuance {
            subject_key: &subject_key,
            subject_name: "encryption of main",
            issuer_key: &issuer_key,
            issuer_name: "signing of main",
            serial: &serial,
            not_before: 1_789_372_800,
            not_after: 2_104_992_000,
        };
        let der = issue_certificate(&issuance).expect("a certificate");
        assert_eq!(issue_certificate(&issuance), Some(der.clone()));

        let certificate = X509::from_der(&der).expect("a certificate");
        assert_eq!(certificate.version(), 2);
        assert_eq!(
            certificate
                .serial_number()
                .to_bn()
                .expect("a number")
                .to_vec(),
            serial
        );
        for (name, expected) in [
            (certificate.subject_name(), "encryption of main"),
            (certificate.issuer_name(), "signing of main"),
        ] {
            let entries: Vec<_> = name
                .entries()
                .map(|entry| {
                    let text = std::str::from_utf8(entry.data().as_slice())
                        .expect("text")
                        .to_owned();
                    (entry.object().nid(), text)
                })
                .collect();
            assert_eq!(entries, [(Nid::COMMONNAME, expected.to_owned())]);
        }
        assert_eq!(seconds_of(certificate.not_before()), issuance.not_before);
        assert_eq!(seconds_of(certificate.not_after()), issuance.not_after);
        assert_eq!(
            certificate
                .public_key()
                .expect("a key")
                .public_key_to_der()
                .expect("SPKI"),
            subject_key.der()
        );
        assert_eq!(
            certificate.signature_algorithm().object().nid(),
            Nid::SHA256WITHRSAENCRYPTION
        );
        assert!(certificate.verify(&issuer).expect("a verification"));

        assert!(
            issue_certificate(&Issuance {
                serial: &[0x7f; 20],
                ..issuance
            })
            .is_some()
        );
        let elliptic_issuer = PrivateKey::from_der(
            ec_key(Nid::X9_62_PRIME256V1)
                .private_key_to_der()
                .expect("PKCS#8"),
        );
        let not_a_private_key = PrivateKey::from_der(b"not a key".to_vec());
        let not_a_public_key = PublicKey::from_der(b"not a key".to_vec());
        for refused in [
            Issuance {
                issuer_key: &elliptic_issuer,
                ..issuance
            },
            Issuance {
                issuer_key: &not_a_private_key,
                ..issuance
            },
            Issuance {
                subject_key: &not_a_public_key,
                ..issuance
            },
            Issuance {
                serial: &[],
                ..issuance
            },
            Issuance {
                serial: &[0, 0],
                ..issuance
            },
            Issuance {
                serial: &[0x80; 20],
                ..issuance
            },
            Issuance {
                serial: &[0x01; 21],
                ..issuance
            },
        ] {
            assert_eq!(issue_certificate(&refused), None);
        }
    }

    /// A certificate tells its key's kind and strength, its curve among those JOSE
    /// names or none, and the end of its validity; bytes that are no certificate tell
    /// nothing.
    #[test]
    fn a_certificate_tells_the_kind_and_strength_of_its_key() {
        let issuer_key = PrivateKey::from_der(rsa_key(2048).private_key_to_der().expect("PKCS#8"));
        let facts_for = |subject: &PKey<Private>| {
            let subject_key = PublicKey::from_der(subject.public_key_to_der().expect("SPKI"));
            let der = issue_certificate(&Issuance {
                subject_key: &subject_key,
                subject_name: "subject",
                issuer_key: &issuer_key,
                issuer_name: "issuer",
                serial: &[1],
                not_before: 1_789_372_800,
                not_after: 2_104_992_000,
            })
            .expect("a certificate");
            read_certificate_facts(&der).expect("facts")
        };
        for (subject, key) in [
            (rsa_key(2048), CertifiedKey::Rsa { bits: 2048 }),
            (rsa_key(1024), CertifiedKey::Rsa { bits: 1024 }),
            (
                ec_key(Nid::X9_62_PRIME256V1),
                CertifiedKey::Ec {
                    curve: Some("P-256"),
                },
            ),
            (
                ec_key(Nid::SECP384R1),
                CertifiedKey::Ec {
                    curve: Some("P-384"),
                },
            ),
            (
                ec_key(Nid::SECP521R1),
                CertifiedKey::Ec {
                    curve: Some("P-521"),
                },
            ),
            (ec_key(Nid::SECP256K1), CertifiedKey::Ec { curve: None }),
            (
                PKey::generate_ed25519().expect("an Ed25519 key"),
                CertifiedKey::Other,
            ),
        ] {
            assert_eq!(
                facts_for(&subject),
                CertificateFacts {
                    key,
                    not_after: 2_104_992_000,
                }
            );
        }
        assert_eq!(read_certificate_facts(b"not a certificate"), None);
    }
}

#[cfg(test)]
mod chains {
    use super::{Unanchored, subject_key_identifier, verify_chain};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509, X509Builder, X509NameBuilder};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// The instant every chain here is judged at, so the clock never decides.
    const AT: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    struct Held {
        certificate: X509,
        key: PKey<Private>,
    }

    impl Held {
        fn der(&self) -> Vec<u8> {
            self.certificate.to_der().expect("DER")
        }
    }

    /// What one certificate is issued as.
    struct Issuing<'a> {
        name: &'a str,
        /// Absent for a certificate that issues itself.
        issuer: Option<&'a Held>,
        authority: bool,
        path_length: Option<u32>,
        /// Days from `AT`.
        valid: (i64, i64),
        key_identifiers: bool,
    }

    impl<'a> Issuing<'a> {
        fn authority(name: &'a str, issuer: Option<&'a Held>) -> Self {
            Self {
                name,
                issuer,
                authority: true,
                path_length: None,
                valid: (-10, 365),
                key_identifiers: true,
            }
        }

        fn leaf(name: &'a str, issuer: &'a Held) -> Self {
            Self {
                authority: false,
                ..Self::authority(name, Some(issuer))
            }
        }
    }

    fn issue(asked: Issuing<'_>) -> Held {
        static SERIAL: AtomicU32 = AtomicU32::new(1);
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        let key = PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key");
        let named = |name: &str| {
            let mut built = X509NameBuilder::new().expect("a name");
            built
                .append_entry_by_nid(Nid::COMMONNAME, name)
                .expect("a common name");
            built.build()
        };

        let mut builder = X509Builder::new().expect("a builder");
        builder.set_version(2).expect("version 3");
        let serial = BigNum::from_u32(SERIAL.fetch_add(1, Ordering::Relaxed)).expect("a serial");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("an integer"))
            .expect("the serial");
        builder
            .set_subject_name(&named(asked.name))
            .expect("a subject");
        match asked.issuer {
            Some(issuer) => builder
                .set_issuer_name(issuer.certificate.subject_name())
                .expect("an issuer"),
            None => builder.set_issuer_name(&named(asked.name)).expect("itself"),
        }
        builder.set_pubkey(&key).expect("the key");
        let (from, until) = asked.valid;
        builder
            .set_not_before(&Asn1Time::from_unix(AT + from * DAY).expect("a start"))
            .expect("a start");
        builder
            .set_not_after(&Asn1Time::from_unix(AT + until * DAY).expect("an end"))
            .expect("an end");

        let mut constraints = BasicConstraints::new();
        constraints.critical();
        if asked.authority {
            constraints.ca();
            if let Some(length) = asked.path_length {
                constraints.pathlen(length);
            }
        }
        builder
            .append_extension(constraints.build().expect("constraints"))
            .expect("constraints");
        let mut usage = KeyUsage::new();
        usage.critical();
        if asked.authority {
            usage.key_cert_sign().crl_sign();
        } else {
            usage.digital_signature();
        }
        builder
            .append_extension(usage.build().expect("a usage"))
            .expect("a usage");
        if asked.key_identifiers {
            let issuer = asked.issuer.map(|issuer| issuer.certificate.as_ref());
            let subject = SubjectKeyIdentifier::new()
                .build(&builder.x509v3_context(issuer, None))
                .expect("a subject key identifier");
            builder
                .append_extension(subject)
                .expect("a subject key identifier");
            if issuer.is_some() {
                let authority = AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .build(&builder.x509v3_context(issuer, None))
                    .expect("an authority key identifier");
                builder
                    .append_extension(authority)
                    .expect("an authority key identifier");
            }
        }
        let signer = asked.issuer.map_or(&key, |issuer| &issuer.key);
        builder
            .sign(signer, MessageDigest::sha256())
            .expect("signed");
        Held {
            certificate: builder.build(),
            key,
        }
    }

    /// A root, an intermediate under it, a leaf under that.
    fn hierarchy() -> (Held, Held, Held) {
        let root = issue(Issuing::authority("Root", None));
        let intermediate = issue(Issuing::authority("Intermediate", Some(&root)));
        let leaf = issue(Issuing::leaf("Leaf", &intermediate));
        (root, intermediate, leaf)
    }

    /// A chain presented leaf first reaches the anchor that issued it, and
    /// hands back the leaf's key and which anchor it reached.
    #[test]
    fn a_chain_reaches_the_anchor_it_was_issued_under() {
        let (root, intermediate, leaf) = hierarchy();
        let other = issue(Issuing::authority("Other root", None));
        let anchored = verify_chain(
            &[leaf.der(), intermediate.der()],
            &[other.der(), root.der()],
            AT,
        )
        .expect("anchored");
        assert_eq!(anchored.anchor, 1, "the chain ended at another anchor");
        assert_eq!(
            anchored.leaf_key.der(),
            leaf.key.public_key_to_der().expect("SPKI").as_slice()
        );
    }

    /// Trusting an intermediate is what depositing it means: a chain ends
    /// there without climbing to the root that issued it.
    #[test]
    fn an_intermediate_can_be_the_anchor() {
        let (_, intermediate, leaf) = hierarchy();
        let anchored = verify_chain(&[leaf.der()], &[intermediate.der()], AT).expect("anchored");
        assert_eq!(anchored.anchor, 0);
    }

    /// A chain under an authority nobody deposited reaches no anchor, and
    /// neither does any chain when nothing is trusted.
    #[test]
    fn a_chain_under_nobody_trusted_reaches_no_anchor() {
        let (_, intermediate, leaf) = hierarchy();
        let other = issue(Issuing::authority("Other root", None));
        for anchors in [vec![other.der()], Vec::new()] {
            assert_eq!(
                verify_chain(&[leaf.der(), intermediate.der()], &anchors, AT).unwrap_err(),
                Unanchored::NoAnchor
            );
        }
    }

    /// Validity is judged at the instant asked, whatever the clock says, and a
    /// leaf past its end or before its start anchors nothing.
    #[test]
    fn validity_is_judged_at_the_instant_asked() {
        let (root, intermediate, _) = hierarchy();
        for valid in [(-10, -1), (1, 10)] {
            let leaf = issue(Issuing {
                valid,
                ..Issuing::leaf("Leaf", &intermediate)
            });
            assert_eq!(
                verify_chain(&[leaf.der(), intermediate.der()], &[root.der()], AT).unwrap_err(),
                Unanchored::OutOfValidity,
                "{valid:?}"
            );
            let inside = AT + (valid.0 + 1) * DAY;
            assert!(
                verify_chain(&[leaf.der(), intermediate.der()], &[root.der()], inside).is_ok(),
                "{valid:?} did not anchor inside its own window"
            );
        }
    }

    /// Only an authority issues: a certificate that is not one cannot stand
    /// between a leaf and its anchor, and a root that allows no authority
    /// below it allows none.
    #[test]
    fn only_an_authority_issues_and_only_as_deep_as_allowed() {
        let root = issue(Issuing::authority("Root", None));
        let plain = issue(Issuing {
            authority: false,
            ..Issuing::authority("Not an authority", Some(&root))
        });
        let leaf = issue(Issuing::leaf("Leaf", &plain));
        assert!(matches!(
            verify_chain(&[leaf.der(), plain.der()], &[root.der()], AT),
            Err(Unanchored::Refused(_))
        ));

        let narrow = issue(Issuing {
            path_length: Some(0),
            ..Issuing::authority("Narrow root", None)
        });
        let intermediate = issue(Issuing::authority("Intermediate", Some(&narrow)));
        let leaf = issue(Issuing::leaf("Leaf", &intermediate));
        assert!(matches!(
            verify_chain(&[leaf.der(), intermediate.der()], &[narrow.der()], AT),
            Err(Unanchored::Refused(_))
        ));
    }

    /// A leaf signed by a key other than the one its issuer's certificate
    /// certifies anchors nothing, whatever names it carries.
    #[test]
    fn a_leaf_signed_by_another_key_anchors_nothing() {
        let (root, intermediate, _) = hierarchy();
        let impostor = issue(Issuing::authority("Intermediate", Some(&root)));
        let forged = issue(Issuing::leaf("Leaf", &impostor));
        assert!(verify_chain(&[forged.der(), intermediate.der()], &[root.der()], AT).is_err());
    }

    /// A chain deeper than any real hierarchy is refused, and strict path
    /// validation refuses a certificate that does not name its issuer's key.
    #[test]
    fn a_chain_is_bounded_and_held_to_strict_validation() {
        let root = issue(Issuing::authority("Root", None));
        let mut ladder = vec![issue(Issuing::authority("Step 0", Some(&root)))];
        for step in 1..10 {
            let name = format!("Step {step}");
            let next = issue(Issuing::authority(&name, ladder.last()));
            ladder.push(next);
        }
        let leaf = issue(Issuing::leaf("Leaf", ladder.last().expect("a step")));
        let mut chain = vec![leaf.der()];
        chain.extend(ladder.iter().rev().map(Held::der));
        assert!(matches!(
            verify_chain(&chain, &[root.der()], AT),
            Err(Unanchored::Refused(_))
        ));

        let unnamed = issue(Issuing {
            key_identifiers: false,
            ..Issuing::authority("Intermediate", Some(&root))
        });
        let leaf = issue(Issuing {
            key_identifiers: false,
            ..Issuing::leaf("Leaf", &unnamed)
        });
        assert!(matches!(
            verify_chain(&[leaf.der(), unnamed.der()], &[root.der()], AT),
            Err(Unanchored::Refused(_))
        ));
    }

    /// Nothing presented, or bytes that are no certificate, are said to be so.
    #[test]
    fn what_is_not_a_chain_is_said_to_be_so() {
        let (root, intermediate, leaf) = hierarchy();
        assert_eq!(
            verify_chain(&[], &[root.der()], AT).unwrap_err(),
            Unanchored::Empty
        );
        for (chain, anchors) in [
            (vec![b"not a certificate".to_vec()], vec![root.der()]),
            (vec![leaf.der(), b"no".to_vec()], vec![root.der()]),
            (vec![leaf.der(), intermediate.der()], vec![b"no".to_vec()]),
        ] {
            assert_eq!(
                verify_chain(&chain, &anchors, AT).unwrap_err(),
                Unanchored::Unreadable
            );
        }
    }

    /// The key identifier is the one the certificate states.
    #[test]
    fn the_key_identifier_is_the_one_stated() {
        let (_, intermediate, leaf) = hierarchy();
        let stated = subject_key_identifier(&intermediate.der()).expect("an identifier");
        assert_eq!(
            leaf.certificate
                .authority_key_id()
                .expect("an authority key identifier")
                .as_slice(),
            stated.as_slice(),
            "the leaf names its issuer by another identifier"
        );
        let unnamed = issue(Issuing {
            key_identifiers: false,
            ..Issuing::authority("Unnamed", None)
        });
        assert_eq!(subject_key_identifier(&unnamed.der()), None);
        assert_eq!(subject_key_identifier(b"not a certificate"), None);
    }
}
