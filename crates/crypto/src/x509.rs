use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::x509::{X509, X509Builder, X509Name, X509NameBuilder};

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
