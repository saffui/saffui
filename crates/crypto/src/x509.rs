use std::cmp::Ordering;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time, Asn1TimeRef};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey};
use openssl::stack::Stack;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{
    X509, X509Builder, X509Extension, X509Name, X509NameBuilder, X509ReqBuilder, X509StoreContext,
};

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

impl CertifiedKey {
    /// Why this build would not trust the key, in words: RSA under 2048 bits, a
    /// curve JOSE does not name, or a kind it does not verify. Nothing for a
    /// key it would.
    pub fn weakness(self) -> Option<&'static str> {
        match self {
            Self::Rsa { bits } if bits < 2048 => Some("RSA below 2048 bits"),
            Self::Rsa { .. } => None,
            Self::Ec { curve } => curve
                .is_none()
                .then_some("a curve other than P-256, P-384 or P-521"),
            Self::Other => Some("a key of a kind not verified here"),
        }
    }
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
    issued(issuance, false)
}

/// A certificate for an authority: what `issue_certificate` makes, with the
/// basic constraints of a CA, key usage for signing certificates and
/// revocation lists, and the subject key identifier certificates issued under
/// it name it by.
pub fn issue_authority_certificate(issuance: &Issuance<'_>) -> Option<Vec<u8>> {
    issued(issuance, true)
}

fn issued(issuance: &Issuance<'_>, authority: bool) -> Option<Vec<u8>> {
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
    if authority {
        let mut constraints = BasicConstraints::new();
        constraints.critical().ca();
        builder.append_extension(constraints.build().ok()?).ok()?;
        let mut usage = KeyUsage::new();
        usage.critical().key_cert_sign().crl_sign();
        builder.append_extension(usage.build().ok()?).ok()?;
        let identifier = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .ok()?;
        builder.append_extension(identifier).ok()?;
    }
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

/// The security level OpenSSL holds a chain's keys and signatures to: 112
/// bits, so no RSA key under 2048 bits, no curve under 224, no SHA-1.
const CHAIN_STRENGTH: i32 = 2;

/// A chain that ends at one of the anchors a caller trusts.
#[derive(Debug, Clone)]
pub struct AnchoredChain {
    /// The leaf's SubjectPublicKeyInfo, as the signer verifies with.
    pub leaf_key: PublicKey,
    /// Which of the anchors handed in the chain ended at.
    pub anchor: usize,
    /// The path verified, DER, leaf first and the anchor last: what each
    /// certificate's revocation is read along.
    pub path: Vec<Vec<u8>>,
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
    #[error("the first certificate signs itself: an authority must issue it")]
    SelfSigned,
    #[error("the first certificate is not for digital signatures")]
    NotForSigning,
    #[error("a certificate in the chain holds a key or a signature too weak to trust")]
    TooWeak,
    #[error("the chain does not verify: {0}")]
    Refused(String),
}

/// Verify a chain, leaf first as `x5c` carries it, up to one of `anchors`, at
/// the instant `at` in seconds since the epoch rather than at the clock's.
///
/// Path validation is OpenSSL's, in strict mode, every key and every
/// signature below the anchor held to 112 bits of security. An anchor may be
/// an intermediate authority: trusting it is what depositing it means, and the
/// chain need not climb past it. The leaf signs: it is issued by an authority
/// rather than by itself, even one deposited as an anchor, and is for digital
/// signatures when it says what its key is for. Nothing is fetched, so
/// revocation lists and OCSP are not consulted here.
pub fn verify_chain(
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: i64,
) -> Result<AnchoredChain, Unanchored> {
    let (leaf, intermediates) = chain.split_first().ok_or(Unanchored::Empty)?;
    let leaf = X509::from_der(leaf).map_err(|_| Unanchored::Unreadable)?;
    if signs_itself(&leaf) {
        return Err(Unanchored::SelfSigned);
    }
    if !is_for_signing(&leaf) {
        return Err(Unanchored::NotForSigning);
    }
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
    judged.set_auth_level(CHAIN_STRENGTH);
    store.set_param(&judged).map_err(|_| unverifiable())?;
    let store = store.build();

    let mut context = X509StoreContext::new().map_err(|_| unverifiable())?;
    let (verified, error, path) = context
        .init(&store, &leaf, &presented, |context| {
            let verified = context.verify_cert()?;
            let path = context
                .chain()
                .map(|chain| {
                    chain
                        .iter()
                        .map(|certificate| certificate.to_der())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            Ok((verified, context.error(), path))
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
            openssl_sys::X509_V_ERR_EE_KEY_TOO_SMALL
            | openssl_sys::X509_V_ERR_CA_KEY_TOO_SMALL
            | openssl_sys::X509_V_ERR_CA_MD_TOO_WEAK => Unanchored::TooWeak,
            _ => Unanchored::Refused(error.error_string().to_owned()),
        });
    }

    let anchor = path
        .last()
        .and_then(|reached| trusted.iter().position(|anchor| anchor == reached))
        .ok_or(Unanchored::NoAnchor)?;
    let leaf_key = leaf
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|_| Unanchored::Unreadable)?;
    Ok(AnchoredChain {
        leaf_key: PublicKey::from_der(leaf_key),
        anchor,
        path,
    })
}

fn unverifiable() -> Unanchored {
    Unanchored::Refused("the chain could not be put to OpenSSL".to_owned())
}

/// The certificates a PEM text carries, in order, as DER. Nothing when it
/// carries none, or when one of them does not parse.
pub fn read_pem_certificates(pem: &[u8]) -> Option<Vec<Vec<u8>>> {
    let certificates = X509::stack_from_pem(pem).ok()?;
    if certificates.is_empty() {
        return None;
    }
    certificates
        .iter()
        .map(|certificate| certificate.to_der().ok())
        .collect()
}

/// Whether a certificate is a certification authority's: basic constraints
/// that say CA, which is what OpenSSL itself asks of any certificate issuing
/// another, and extensions it could read. False for bytes that are none.
pub fn is_authority(der: &[u8]) -> bool {
    let Ok(certificate) = X509::from_der(der) else {
        return false;
    };
    // SAFETY: the pointer is the live certificate held above; the call reads
    // and caches its extension flags and keeps no reference to it.
    let flags = unsafe { openssl_sys::X509_get_extension_flags(certificate.as_ptr()) };
    flags & openssl_sys::EXFLAG_CA != 0 && flags & openssl_sys::EXFLAG_INVALID == 0
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

/// How an access certificate names a verifier (ETSI TS 119 411-8): what a
/// certificate request asks an authority to certify a key under.
#[derive(Debug, Clone, Copy)]
pub struct RequestedSubject<'a> {
    pub common_name: &'a str,
    pub organization: Option<&'a str>,
    /// The organization's registered identifier, as EN 319 412-1 writes it.
    pub organization_identifier: Option<&'a str>,
    /// ISO 3166-1 alpha-2.
    pub country: Option<&'a str>,
}

/// The X.520 organizationIdentifier, for which OpenSSL's Rust binding names
/// no constant.
const ORGANIZATION_IDENTIFIER: &str = "2.5.4.97";

/// A PKCS#10 request for the key `private` holds, naming `subject` from the
/// country down to the common name, signed with SHA-256 under that very key:
/// what shows an authority the requester holds it. PEM. Nothing when the key
/// does not parse or a name does not fit.
pub fn request_certificate(private: &PrivateKey, subject: &RequestedSubject<'_>) -> Option<String> {
    let key = PKey::private_key_from_der(private.der()).ok()?;
    let mut name = X509NameBuilder::new().ok()?;
    if let Some(country) = subject.country {
        name.append_entry_by_nid(Nid::COUNTRYNAME, country).ok()?;
    }
    if let Some(organization) = subject.organization {
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, organization)
            .ok()?;
    }
    if let Some(identifier) = subject.organization_identifier {
        name.append_entry_by_text(ORGANIZATION_IDENTIFIER, identifier)
            .ok()?;
    }
    name.append_entry_by_nid(Nid::COMMONNAME, subject.common_name)
        .ok()?;
    let mut request = X509ReqBuilder::new().ok()?;
    request.set_version(0).ok()?;
    request.set_subject_name(&name.build()).ok()?;
    request.set_pubkey(&key).ok()?;
    request.sign(&key, MessageDigest::sha256()).ok()?;
    String::from_utf8(request.build().to_pem().ok()?).ok()
}

/// A certificate chain taken for a key: leaf first, its issuers after, the
/// trust anchor left out, as a JWS `x5c` header carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakenChain {
    pub chain: Vec<Vec<u8>>,
    /// The leaf's validity, in seconds since the epoch.
    pub not_before: i64,
    pub not_after: i64,
}

/// Why a chain was not taken as the certificate of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Untaken {
    #[error("the text carries no certificate, or one that does not parse")]
    Unreadable,
    #[error("the chain holds more certificates than an authority's hierarchy does")]
    TooLong,
    #[error("the first certificate certifies another key than this one")]
    AnotherKey,
    #[error("the first certificate signs itself: an authority must issue it")]
    SelfSigned,
    #[error("the first certificate is not for digital signatures")]
    NotForSigning,
    #[error("a certificate of the chain is not valid now")]
    OutOfValidity,
    #[error("a certificate of the chain is not issued by the one after it")]
    Unlinked,
}

/// Take the chain `pem` carries as the certificate of `key`, at the instant
/// `at` in seconds since the epoch: the first certificate certifies exactly
/// this key, under an authority rather than by itself, and for digital
/// signatures when it says what its key is for; each certificate is issued by
/// the one after it, and every one is valid at `at`. A self-signed
/// certificate closing the chain is its trust anchor: it is checked against
/// and left out of what is kept. Whether the anchor is to be trusted is for
/// whoever is shown the chain to say.
pub fn take_certificate_chain(pem: &[u8], key: &PublicKey, at: i64) -> Result<TakenChain, Untaken> {
    let mut chain = read_pem_certificates(pem).ok_or(Untaken::Unreadable)?;
    if chain.len() > CHAIN_DEPTH as usize + 1 {
        return Err(Untaken::TooLong);
    }
    let read = chain
        .iter()
        .map(|der| X509::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Untaken::Unreadable)?;
    let leaf = &read[0];
    let certified = leaf
        .public_key()
        .and_then(|certified| certified.public_key_to_der())
        .map_err(|_| Untaken::Unreadable)?;
    if certified != key.der() {
        return Err(Untaken::AnotherKey);
    }
    if signs_itself(leaf) {
        return Err(Untaken::SelfSigned);
    }
    if !is_for_signing(leaf) {
        return Err(Untaken::NotForSigning);
    }
    let mut leaf_validity = None;
    for certificate in &read {
        let from = unix_seconds(certificate.not_before()).ok_or(Untaken::Unreadable)?;
        let until = unix_seconds(certificate.not_after()).ok_or(Untaken::Unreadable)?;
        if at < from || at >= until {
            return Err(Untaken::OutOfValidity);
        }
        leaf_validity.get_or_insert((from, until));
    }
    for pair in read.windows(2) {
        let named = pair[0]
            .issuer_name()
            .try_cmp(pair[1].subject_name())
            .map_err(|_| Untaken::Unreadable)?
            == Ordering::Equal;
        let signed = pair[1]
            .public_key()
            .and_then(|issuer| pair[0].verify(&issuer))
            .unwrap_or(false);
        if !named || !signed {
            return Err(Untaken::Unlinked);
        }
    }
    if read.len() > 1 && read.last().is_some_and(signs_itself) {
        chain.pop();
    }
    let (not_before, not_after) = leaf_validity.ok_or(Untaken::Unreadable)?;
    Ok(TakenChain {
        chain,
        not_before,
        not_after,
    })
}

/// Whether a certificate's signature holds under its own key.
fn signs_itself(certificate: &X509) -> bool {
    certificate
        .public_key()
        .and_then(|own| certificate.verify(&own))
        .unwrap_or(false)
}

/// Whether a certificate's key may sign, as its key usage says when it says.
/// OpenSSL reads a certificate saying nothing of it as fit for every usage,
/// and one whose extensions it cannot read as fit for none.
fn is_for_signing(certificate: &X509) -> bool {
    // SAFETY: the pointer is the live certificate passed in; the call reads
    // and caches its extensions and keeps no reference to it.
    let usage = unsafe { openssl_sys::X509_get_key_usage(certificate.as_ptr()) };
    usage & openssl_sys::X509v3_KU_DIGITAL_SIGNATURE != 0
}

/// Where a certificate's revocation is published (RFC 5280 §4.2.1.13): the
/// http(s) address of each distribution point this build reads, and whether
/// one names its list otherwise, partitions it by reason or has another
/// authority issue it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationPoints {
    pub addresses: Vec<String>,
    pub unreadable: bool,
}

/// What the verifier of a chain reads of one of its certificates beyond the
/// path: the serial its authority revokes it by, the identifier of that
/// authority's key, and where its revocation is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainedCertificate {
    /// The serial number's magnitude, big-endian, as a revocation list names it.
    pub serial: Vec<u8>,
    pub authority_key_identifier: Option<Vec<u8>>,
    pub revocation: RevocationPoints,
}

/// Read what the verifier of a chain needs of a DER certificate; nothing when
/// the bytes are no certificate.
pub fn read_chained_certificate(der: &[u8]) -> Option<ChainedCertificate> {
    let certificate = X509::from_der(der).ok()?;
    let serial = certificate.serial_number().to_bn().ok()?.to_vec();
    let points = certificate.crl_distribution_points();
    // SAFETY: the pointer is the live certificate parsed above; the call reads
    // its extensions and keeps no reference to it.
    let stated = unsafe {
        openssl_sys::X509_get_ext_by_NID(
            certificate.as_ptr(),
            openssl_sys::NID_crl_distribution_points,
            -1,
        ) >= 0
    };
    let mut revocation = RevocationPoints {
        addresses: Vec::new(),
        // An extension stated but unparsed publishes nothing this build reads.
        unreadable: stated && points.is_none(),
    };
    for point in points.iter().flatten() {
        // SAFETY: the point is a live entry of the stack read above; the
        // fields are read, never kept past it.
        let (partitioned, delegated) = unsafe {
            let raw = point.as_ptr();
            (!(*raw).reasons.is_null(), !(*raw).CRLissuer.is_null())
        };
        let address = point
            .distpoint()
            .and_then(|name| name.fullname())
            .and_then(|names| {
                names.iter().find_map(|name| {
                    name.uri().filter(|uri| {
                        let lowered = uri.to_ascii_lowercase();
                        lowered.starts_with("https://") || lowered.starts_with("http://")
                    })
                })
            })
            .filter(|_| !partitioned && !delegated);
        match address {
            Some(address) => revocation.addresses.push(address.to_owned()),
            None => revocation.unreadable = true,
        }
    }
    Some(ChainedCertificate {
        serial,
        authority_key_identifier: certificate
            .authority_key_id()
            .map(|identifier| identifier.as_slice().to_vec()),
        revocation,
    })
}

/// A certificate issued as a real hierarchy issues one: its own key and its
/// issuer's identified (RFC 5280 §4.2.1.1, §4.2.1.2), for issuing or for
/// signatures, and naming where its revocation is published. For tests to
/// build the chains wallets present.
#[derive(Debug, Clone, Copy)]
pub struct Certifying<'a> {
    pub subject_key: &'a PublicKey,
    pub subject_name: &'a str,
    /// The issuer's certificate, DER; absent for a root, which issues itself
    /// under `issuer_key`, the private half of `subject_key`.
    pub issuer_certificate: Option<&'a [u8]>,
    pub issuer_key: &'a PrivateKey,
    pub serial: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    pub authority: bool,
    /// The http(s) address its revocation list is published at.
    pub revocation_list: Option<&'a str>,
}

/// Issue the certificate `certifying` describes, signed with SHA-256 under the
/// issuer's key, of any kind. Nothing when a key or the issuer's certificate
/// does not parse, the serial is out of bounds or a time does not fit.
pub fn certify_key(certifying: &Certifying<'_>) -> Option<Vec<u8>> {
    let issuer_key = PKey::private_key_from_der(certifying.issuer_key.der()).ok()?;
    let subject = PKey::public_key_from_der(certifying.subject_key.der()).ok()?;
    let issuer = certifying
        .issuer_certificate
        .map(X509::from_der)
        .transpose()
        .ok()?;
    let number = BigNum::from_slice(certifying.serial).ok()?;
    if !(1..=159).contains(&number.num_bits()) {
        return None;
    }
    let subject_name = build_common_name(certifying.subject_name)?;
    let serial = number.to_asn1_integer().ok()?;
    let not_before = Asn1Time::from_unix(certifying.not_before).ok()?;
    let not_after = Asn1Time::from_unix(certifying.not_after).ok()?;
    let mut builder = X509Builder::new().ok()?;
    builder.set_version(2).ok()?;
    builder.set_serial_number(&serial).ok()?;
    builder.set_subject_name(&subject_name).ok()?;
    match &issuer {
        Some(issuer) => builder.set_issuer_name(issuer.subject_name()).ok()?,
        None => builder.set_issuer_name(&subject_name).ok()?,
    }
    builder.set_pubkey(&subject).ok()?;
    builder.set_not_before(&not_before).ok()?;
    builder.set_not_after(&not_after).ok()?;
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if certifying.authority {
        constraints.ca();
    }
    builder.append_extension(constraints.build().ok()?).ok()?;
    let mut usage = KeyUsage::new();
    usage.critical();
    if certifying.authority {
        usage.key_cert_sign().crl_sign();
    } else {
        usage.digital_signature();
    }
    builder.append_extension(usage.build().ok()?).ok()?;
    let identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .ok()?;
    builder.append_extension(identifier).ok()?;
    let authority_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(issuer.as_deref(), None))
        .ok()?;
    builder.append_extension(authority_identifier).ok()?;
    if let Some(address) = certifying.revocation_list {
        builder
            .append_extension(build_revocation_point(address)?)
            .ok()?;
    }
    builder.sign(&issuer_key, MessageDigest::sha256()).ok()?;
    builder.build().to_der().ok()
}

/// The CRL distribution points extension naming one address (RFC 5280
/// §4.2.1.13), written out, since OpenSSL's Rust binding builds none: a point
/// whose full name is that one URI.
fn build_revocation_point(address: &str) -> Option<X509Extension> {
    let uri = encode_der(0x86, address.as_bytes())?;
    let full_name = encode_der(0xa0, &uri)?;
    let point_name = encode_der(0xa0, &full_name)?;
    let points = encode_der(0x30, &encode_der(0x30, &point_name)?)?;
    let named = Asn1Object::from_str("2.5.29.31").ok()?;
    let contents = Asn1OctetString::new_from_bytes(&points).ok()?;
    X509Extension::new_from_der(&named, false, &contents).ok()
}

/// One DER element: its tag, its length in the shortest form, its contents.
pub(crate) fn encode_der(tag: u8, contents: &[u8]) -> Option<Vec<u8>> {
    let length = contents.len();
    let mut written = vec![tag];
    match length {
        0..=0x7f => written.push(u8::try_from(length).ok()?),
        0x80..=0xff => written.extend([0x81, u8::try_from(length).ok()?]),
        _ => written.extend(
            [0x82]
                .iter()
                .chain(&u16::try_from(length).ok()?.to_be_bytes()),
        ),
    }
    written.extend_from_slice(contents);
    Some(written)
}

/// A certificate time in seconds since the epoch.
pub(crate) fn unix_seconds(time: &Asn1TimeRef) -> Option<i64> {
    let lived = Asn1Time::from_unix(0).ok()?.diff(time).ok()?;
    Some(i64::from(lived.days) * 86_400 + i64::from(lived.secs))
}

fn build_common_name(name: &str) -> Option<X509Name> {
    let mut builder = X509NameBuilder::new().ok()?;
    builder.append_entry_by_nid(Nid::COMMONNAME, name).ok()?;
    Some(builder.build())
}

#[cfg(test)]
mod tests {
    use super::{
        CertificateFacts, CertifiedKey, Certifying, ChainedCertificate, Issuance, RequestedSubject,
        RevocationPoints, TakenChain, Unanchored, Untaken, certify_key, encode_der, is_authority,
        issue_authority_certificate, issue_certificate, public_key_of, read_certificate_facts,
        read_chained_certificate, request_certificate, subject_key_identifier,
        take_certificate_chain, verify_chain,
    };
    use crate::provider::{PrivateKey, PublicKey};
    use openssl::asn1::{Asn1Time, Asn1TimeRef};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509Builder, X509NameBuilder, X509Req};

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

    /// An authority's certificate is one: basic constraints that say CA, a key
    /// identifier to be named by, and the same bytes every time; the plain
    /// issuance of the same key is no authority.
    #[test]
    fn an_authority_certificate_is_issued_as_one() {
        let issuer = rsa_key(2048);
        let issuer_key = PrivateKey::from_der(issuer.private_key_to_der().expect("PKCS#8"));
        let subject_key = PublicKey::from_der(issuer.public_key_to_der().expect("SPKI"));
        let issuance = Issuance {
            subject_key: &subject_key,
            subject_name: "Authority",
            issuer_key: &issuer_key,
            issuer_name: "Authority",
            serial: &[1],
            not_before: 1_789_372_800,
            not_after: 2_104_992_000,
        };
        let authority = issue_authority_certificate(&issuance).expect("a certificate");
        assert_eq!(
            issue_authority_certificate(&issuance),
            Some(authority.clone())
        );
        assert!(is_authority(&authority));
        assert!(subject_key_identifier(&authority).is_some());

        let plain = issue_certificate(&issuance).expect("a certificate");
        assert!(!is_authority(&plain));
        assert_eq!(subject_key_identifier(&plain), None);
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

    /// A key is weighed by its kind and strength: RSA from 2048 bits and the
    /// curves JOSE names are trusted, and what is not says why.
    #[test]
    fn a_key_is_weighed_by_its_kind_and_strength() {
        assert_eq!(
            CertifiedKey::Rsa { bits: 2047 }.weakness(),
            Some("RSA below 2048 bits")
        );
        assert_eq!(CertifiedKey::Rsa { bits: 2048 }.weakness(), None);
        assert_eq!(
            CertifiedKey::Ec {
                curve: Some("P-256")
            }
            .weakness(),
            None
        );
        assert_eq!(
            CertifiedKey::Ec { curve: None }.weakness(),
            Some("a curve other than P-256, P-384 or P-521")
        );
        assert_eq!(
            CertifiedKey::Other.weakness(),
            Some("a key of a kind not verified here")
        );
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

    fn private_of(key: &PKey<Private>) -> PrivateKey {
        PrivateKey::from_der(key.private_key_to_der().expect("PKCS#8"))
    }

    fn public_of(key: &PKey<Private>) -> PublicKey {
        PublicKey::from_der(key.public_key_to_der().expect("SPKI"))
    }

    /// A request names its subject from the country down to the common name,
    /// and is signed by the key it asks to have certified.
    #[test]
    fn a_request_names_its_subject_and_proves_its_key() {
        let key = ec_key(Nid::X9_62_PRIME256V1);
        let pem = request_certificate(
            &private_of(&key),
            &RequestedSubject {
                common_name: "Acme verifier",
                organization: Some("Acme SA"),
                organization_identifier: Some("VATFR-12345678901"),
                country: Some("FR"),
            },
        )
        .expect("a request");
        let request = X509Req::from_pem(pem.as_bytes()).expect("PKCS#10");
        assert!(request.verify(&key).expect("verifiable"));
        assert_eq!(request.version(), 0, "a PKCS#10 request is version 1");
        // ecdsa-with-SHA256, 1.2.840.10045.4.3.2, as the request's DER writes it.
        let signed_with = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        assert!(
            request
                .to_der()
                .expect("DER")
                .windows(signed_with.len())
                .any(|held| held == signed_with),
            "the request is not signed ECDSA with SHA-256"
        );
        assert_eq!(
            request
                .public_key()
                .and_then(|held| held.public_key_to_der())
                .expect("SPKI"),
            key.public_key_to_der().expect("SPKI")
        );
        let named: Vec<(String, String)> = request
            .subject_name()
            .entries()
            .map(|entry| {
                (
                    entry
                        .object()
                        .nid()
                        .short_name()
                        .expect("a name")
                        .to_owned(),
                    entry.data().to_string().expect("text"),
                )
            })
            .collect();
        let expected = [
            ("C", "FR"),
            ("O", "Acme SA"),
            ("organizationIdentifier", "VATFR-12345678901"),
            ("CN", "Acme verifier"),
        ];
        assert_eq!(
            named,
            expected.map(|(name, value)| (name.to_owned(), value.to_owned()))
        );

        let bare = RequestedSubject {
            common_name: "Acme verifier",
            organization: None,
            organization_identifier: None,
            country: None,
        };
        let pem = request_certificate(&private_of(&key), &bare).expect("a request");
        let request = X509Req::from_pem(pem.as_bytes()).expect("PKCS#10");
        assert_eq!(request.subject_name().entries().count(), 1);
        let three_letters = RequestedSubject {
            country: Some("FRA"),
            ..bare
        };
        assert!(request_certificate(&private_of(&key), &three_letters).is_none());
    }

    const NOW: i64 = 1_790_000_000;
    const FROM: i64 = NOW - 3_600;
    const UNTIL: i64 = NOW + 30 * 86_400;

    /// `subject`'s certificate under `issuer`, an RSA key, valid between the
    /// two instants given.
    fn certified(
        subject: &PKey<Private>,
        subject_name: &str,
        issuer: &PKey<Private>,
        issuer_name: &str,
        authority: bool,
        (from, until): (i64, i64),
    ) -> Vec<u8> {
        let (subject_key, issuer_key) = (public_of(subject), private_of(issuer));
        let issuance = Issuance {
            subject_key: &subject_key,
            subject_name,
            issuer_key: &issuer_key,
            issuer_name,
            serial: &[7],
            not_before: from,
            not_after: until,
        };
        if authority {
            issue_authority_certificate(&issuance)
        } else {
            issue_certificate(&issuance)
        }
        .expect("a certificate")
    }

    fn pem_of(chain: &[&[u8]]) -> Vec<u8> {
        chain
            .iter()
            .flat_map(|der| {
                X509::from_der(der)
                    .and_then(|read| read.to_pem())
                    .expect("PEM")
            })
            .collect()
    }

    /// A root, an intermediate it certifies, and a P-256 key the intermediate
    /// certifies.
    struct Hierarchy {
        root_key: PKey<Private>,
        root: Vec<u8>,
        intermediate_key: PKey<Private>,
        intermediate: Vec<u8>,
        leaf_key: PKey<Private>,
        leaf: Vec<u8>,
    }

    fn hierarchy() -> Hierarchy {
        let (root_key, intermediate_key) = (rsa_key(2048), rsa_key(2048));
        let leaf_key = ec_key(Nid::X9_62_PRIME256V1);
        // The authorities outlive the leaf, so a chain's validity is read off
        // the leaf alone.
        let lasting = (FROM - 86_400, UNTIL + 86_400);
        let root = certified(&root_key, "Root", &root_key, "Root", true, lasting);
        let intermediate = certified(
            &intermediate_key,
            "Access CA",
            &root_key,
            "Root",
            true,
            lasting,
        );
        let leaf = certified(
            &leaf_key,
            "Acme verifier",
            &intermediate_key,
            "Access CA",
            false,
            (FROM, UNTIL),
        );
        Hierarchy {
            root_key,
            root,
            intermediate_key,
            intermediate,
            leaf_key,
            leaf,
        }
    }

    /// A chain is kept leaf first, without the self-signed anchor closing it,
    /// whether or not the anchor was pasted in.
    #[test]
    fn a_chain_is_taken_for_its_key_without_its_anchor() {
        let held = hierarchy();
        let key = public_of(&held.leaf_key);
        let expected = TakenChain {
            chain: vec![held.leaf.clone(), held.intermediate.clone()],
            not_before: FROM,
            not_after: UNTIL,
        };
        for pasted in [
            pem_of(&[&held.leaf, &held.intermediate, &held.root]),
            pem_of(&[&held.leaf, &held.intermediate]),
        ] {
            assert_eq!(
                take_certificate_chain(&pasted, &key, NOW).as_ref(),
                Ok(&expected)
            );
        }
        let under_root = certified(
            &held.leaf_key,
            "Acme verifier",
            &held.root_key,
            "Root",
            false,
            (FROM, UNTIL),
        );
        assert_eq!(
            take_certificate_chain(&pem_of(&[&under_root]), &key, NOW).map(|taken| taken.chain),
            Ok(vec![under_root.clone()])
        );
        assert_eq!(
            take_certificate_chain(&pem_of(&[&under_root, &held.root]), &key, NOW)
                .map(|taken| taken.chain),
            Ok(vec![under_root])
        );
    }

    #[test]
    fn a_chain_not_fit_for_the_key_is_refused_in_words() {
        let held = hierarchy();
        let key = public_of(&held.leaf_key);
        let take = |chain: &[&[u8]], at: i64| take_certificate_chain(&pem_of(chain), &key, at);
        assert_eq!(
            take_certificate_chain(b"no certificate", &key, NOW),
            Err(Untaken::Unreadable)
        );
        assert_eq!(
            take_certificate_chain(
                &pem_of(&[&held.leaf, &held.intermediate]),
                &public_of(&ec_key(Nid::X9_62_PRIME256V1)),
                NOW
            ),
            Err(Untaken::AnotherKey)
        );
        assert_eq!(
            take(&[&held.intermediate, &held.leaf], NOW),
            Err(Untaken::AnotherKey)
        );
        assert_eq!(
            take_certificate_chain(&pem_of(&[&held.root]), &public_of(&held.root_key), NOW),
            Err(Untaken::SelfSigned)
        );
        let for_authorities = certified(
            &held.leaf_key,
            "Acme verifier",
            &held.intermediate_key,
            "Access CA",
            true,
            (FROM, UNTIL),
        );
        assert_eq!(
            take(&[&for_authorities, &held.intermediate], NOW),
            Err(Untaken::NotForSigning)
        );
        for at in [FROM - 1, UNTIL] {
            assert_eq!(
                take(&[&held.leaf, &held.intermediate], at),
                Err(Untaken::OutOfValidity),
                "{at}"
            );
        }
        let lapsed = certified(
            &held.intermediate_key,
            "Access CA",
            &held.root_key,
            "Root",
            true,
            (FROM, NOW),
        );
        assert_eq!(
            take(&[&held.leaf, &lapsed], NOW),
            Err(Untaken::OutOfValidity)
        );
        let stranger_key = rsa_key(2048);
        let stranger = certified(
            &stranger_key,
            "Access CA",
            &stranger_key,
            "Access CA",
            true,
            (FROM, UNTIL),
        );
        assert_eq!(
            take(&[&held.leaf, &stranger], NOW),
            Err(Untaken::Unlinked),
            "named alike, signed by another key"
        );
        assert_eq!(
            take(&[&held.leaf, &held.root], NOW),
            Err(Untaken::Unlinked),
            "named otherwise and signed by another key"
        );
        let renamed = certified(
            &held.intermediate_key,
            "Other CA",
            &held.root_key,
            "Root",
            true,
            (FROM, UNTIL),
        );
        assert_eq!(
            take(&[&held.leaf, &renamed], NOW),
            Err(Untaken::Unlinked),
            "signed by the issuer's key, under another name than the issuer the leaf names"
        );
        let mut long: Vec<&[u8]> = vec![&held.leaf];
        long.extend(std::iter::repeat_n(held.intermediate.as_slice(), 9));
        assert_eq!(take(&long, NOW), Err(Untaken::TooLong));
    }

    fn certifying<'a>(
        subject_key: &'a PublicKey,
        subject_name: &'a str,
        issuer: Option<&'a [u8]>,
        issuer_key: &'a PrivateKey,
    ) -> Certifying<'a> {
        Certifying {
            subject_key,
            subject_name,
            issuer_certificate: issuer,
            issuer_key,
            serial: &[1],
            not_before: FROM,
            not_after: UNTIL,
            authority: true,
            revocation_list: None,
        }
    }

    /// A key certified as a hierarchy certifies one names its own key and its
    /// issuer's and says where its revocation is published; its chain holds
    /// under strict validation, a root closing it.
    #[test]
    fn a_key_certified_names_its_keys_and_its_revocation() {
        let (root_key, leaf_key) = (ec_key(Nid::X9_62_PRIME256V1), ec_key(Nid::X9_62_PRIME256V1));
        let (root_public, root_private) = (public_of(&root_key), private_of(&root_key));
        let root =
            certify_key(&certifying(&root_public, "Root", None, &root_private)).expect("a root");
        let leaf_public = public_of(&leaf_key);
        let leaf = certify_key(&Certifying {
            serial: &[0x01, 0x02],
            authority: false,
            revocation_list: Some("https://ca.example/root.crl"),
            ..certifying(&leaf_public, "Leaf", Some(&root), &root_private)
        })
        .expect("a leaf");
        let anchored = verify_chain(
            std::slice::from_ref(&leaf),
            std::slice::from_ref(&root),
            NOW,
        )
        .expect("anchored under strict validation");
        assert_eq!(anchored.leaf_key.der(), leaf_public.der());
        assert_eq!(
            read_chained_certificate(&leaf),
            Some(ChainedCertificate {
                serial: vec![0x01, 0x02],
                authority_key_identifier: subject_key_identifier(&root),
                revocation: RevocationPoints {
                    addresses: vec!["https://ca.example/root.crl".to_owned()],
                    unreadable: false,
                },
            })
        );
        assert_eq!(
            read_chained_certificate(&root).map(|read| read.revocation),
            Some(RevocationPoints::default())
        );
        assert_eq!(read_chained_certificate(b"no certificate"), None);
        assert_eq!(
            certify_key(&Certifying {
                serial: &[],
                ..certifying(&leaf_public, "Leaf", Some(&root), &root_private)
            }),
            None,
            "a serial of no bits"
        );
    }

    /// A certificate naming its revocation by `extension`, a raw CRL
    /// distribution points value, issued by itself.
    fn published_at(points: &[u8]) -> Vec<u8> {
        let key = ec_key(Nid::X9_62_PRIME256V1);
        let mut builder = X509Builder::new().expect("a builder");
        builder.set_version(2).expect("version 3");
        let mut name = X509NameBuilder::new().expect("a name");
        name.append_entry_by_text("CN", "Published")
            .expect("a name");
        let name = name.build();
        builder.set_subject_name(&name).expect("a subject");
        builder.set_issuer_name(&name).expect("an issuer");
        builder.set_pubkey(&key).expect("a key");
        builder
            .set_not_before(&Asn1Time::from_unix(FROM).expect("a time"))
            .expect("a start");
        builder
            .set_not_after(&Asn1Time::from_unix(UNTIL).expect("a time"))
            .expect("an end");
        let named = openssl::asn1::Asn1Object::from_str("2.5.29.31").expect("an OID");
        let contents = openssl::asn1::Asn1OctetString::new_from_bytes(points).expect("bytes");
        builder
            .append_extension(
                openssl::x509::X509Extension::new_from_der(&named, false, &contents)
                    .expect("an extension"),
            )
            .expect("appended");
        builder.sign(&key, MessageDigest::sha256()).expect("signed");
        builder.build().to_der().expect("DER")
    }

    /// A distribution point is read when one http(s) URI names its full list;
    /// one named otherwise, partitioned by reason or issued by another
    /// authority is unreadable, and said so beside those that are read.
    #[test]
    fn a_revocation_point_is_read_when_an_http_address_names_its_whole_list() {
        let point = |name: &[u8], rest: &[u8]| {
            let named = encode_der(0xa0, &encode_der(0xa0, name).expect("DER")).expect("DER");
            encode_der(0x30, &[named.as_slice(), rest].concat()).expect("DER")
        };
        let uri = |address: &str| encode_der(0x86, address.as_bytes()).expect("DER");
        let read = |points: &[Vec<u8>]| {
            read_chained_certificate(&published_at(
                &encode_der(0x30, &points.concat()).expect("DER"),
            ))
            .expect("a certificate")
            .revocation
        };
        let reasons = encode_der(0x81, &[0x07, 0x80]).expect("DER");
        let other_issuer = encode_der(0xa2, &uri("https://other.example")).expect("DER");
        let readable = point(&uri("HTTPS://ca.example/a.crl"), &[]);
        for (points, addresses, unreadable) in [
            (
                vec![readable.clone()],
                vec!["HTTPS://ca.example/a.crl"],
                false,
            ),
            (
                vec![
                    point(&uri("ldap://ca.example/cn=a"), &[]),
                    point(
                        &[uri("ldap://x").as_slice(), &uri("http://ca.example/b.crl")].concat(),
                        &[],
                    ),
                ],
                vec!["http://ca.example/b.crl"],
                true,
            ),
            (
                vec![point(&uri("https://ca.example/c.crl"), &reasons)],
                vec![],
                true,
            ),
            (
                vec![point(&uri("https://ca.example/d.crl"), &other_issuer)],
                vec![],
                true,
            ),
            (
                vec![readable, point(&uri("ftp://ca.example/e.crl"), &[])],
                vec!["HTTPS://ca.example/a.crl"],
                true,
            ),
        ] {
            assert_eq!(
                read(&points),
                RevocationPoints {
                    addresses: addresses
                        .iter()
                        .map(|address| (*address).to_owned())
                        .collect(),
                    unreadable,
                },
                "{addresses:?}"
            );
        }
        let common_name = encode_der(
            0x30,
            &[&[0x06, 0x03, 0x55, 0x04, 0x03][..], &[0x0c, 0x01, b'x']].concat(),
        )
        .expect("DER");
        let relative = encode_der(
            0x30,
            &encode_der(0xa0, &encode_der(0xa1, &common_name).expect("DER")).expect("DER"),
        )
        .expect("DER");
        assert_eq!(
            read(&[relative]),
            RevocationPoints {
                addresses: Vec::new(),
                unreadable: true,
            },
            "a name relative to the issuer"
        );
        assert_eq!(
            read(&[b"\x04\x00".to_vec()]),
            RevocationPoints {
                addresses: Vec::new(),
                unreadable: true,
            },
            "an extension stated but unparsed"
        );
        assert!(super::build_revocation_point("https://ca.example/f.crl").is_some());
    }

    /// The leaf of a chain signs: one issuing itself is refused even trusted
    /// as an anchor, and so is one for issuing certificates alone.
    #[test]
    fn a_chain_leaf_signs_under_an_authority() {
        let key = ec_key(Nid::X9_62_PRIME256V1);
        let (public, private) = (public_of(&key), private_of(&key));
        let alone = certify_key(&Certifying {
            authority: false,
            ..certifying(&public, "Alone", None, &private)
        })
        .expect("a self-signed leaf");
        assert_eq!(
            verify_chain(
                std::slice::from_ref(&alone),
                std::slice::from_ref(&alone),
                NOW
            )
            .unwrap_err(),
            Unanchored::SelfSigned
        );
        let root = certify_key(&certifying(&public, "Root", None, &private)).expect("a root");
        let other = ec_key(Nid::X9_62_PRIME256V1);
        let issuing = certify_key(&certifying(
            &public_of(&other),
            "Issuing",
            Some(&root),
            &private,
        ))
        .expect("an authority");
        assert_eq!(
            verify_chain(&[issuing], &[root], NOW).unwrap_err(),
            Unanchored::NotForSigning
        );
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
        /// Whether it says what its key is for.
        usage_stated: bool,
        /// A key usage stated a second time, which OpenSSL reads as malformed.
        usage_twice: bool,
        /// The size of its RSA key, when its key is not on P-256.
        rsa_bits: Option<u32>,
        /// Whether its issuer signs it over SHA-1.
        over_sha1: bool,
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
                usage_stated: true,
                usage_twice: false,
                rsa_bits: None,
                over_sha1: false,
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
        let key = match asked.rsa_bits {
            Some(bits) => {
                PKey::from_rsa(openssl::rsa::Rsa::generate(bits).expect("a key")).expect("a key")
            }
            None => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
                PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key")
            }
        };
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
        if asked.usage_stated {
            builder
                .append_extension(usage.build().expect("a usage"))
                .expect("a usage");
        }
        if asked.usage_twice {
            builder
                .append_extension(usage.build().expect("a usage"))
                .expect("a second usage");
        }
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
        let digest = if asked.over_sha1 {
            MessageDigest::sha1()
        } else {
            MessageDigest::sha256()
        };
        builder.sign(signer, digest).expect("signed");
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
        assert_eq!(
            anchored.path,
            [leaf.der(), intermediate.der(), root.der()],
            "the path verified is not the one issued"
        );
        let reordered = verify_chain(
            &[leaf.der(), other.der(), intermediate.der(), root.der()],
            &[root.der()],
            AT,
        )
        .expect("anchored");
        assert_eq!(
            reordered.path,
            [leaf.der(), intermediate.der(), root.der()],
            "a certificate presented beside the path was taken into it"
        );
    }

    /// Trusting an intermediate is what depositing it means: a chain ends
    /// there without climbing to the root that issued it.
    #[test]
    fn an_intermediate_can_be_the_anchor() {
        let (_, intermediate, leaf) = hierarchy();
        let anchored = verify_chain(&[leaf.der()], &[intermediate.der()], AT).expect("anchored");
        assert_eq!(anchored.anchor, 0);
        assert_eq!(anchored.path, [leaf.der(), intermediate.der()]);
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

    /// A leaf saying nothing of what its key is for may sign, as RFC 5280
    /// reads a certificate with no key usage; one whose usage cannot be read
    /// signs nothing.
    #[test]
    fn a_leaf_saying_nothing_of_its_key_usage_signs() {
        let (root, intermediate, _) = hierarchy();
        let silent = issue(Issuing {
            usage_stated: false,
            ..Issuing::leaf("Leaf", &intermediate)
        });
        assert!(verify_chain(&[silent.der(), intermediate.der()], &[root.der()], AT).is_ok());
        let malformed = issue(Issuing {
            usage_twice: true,
            ..Issuing::leaf("Leaf", &intermediate)
        });
        assert_eq!(
            verify_chain(&[malformed.der(), intermediate.der()], &[root.der()], AT).unwrap_err(),
            Unanchored::NotForSigning
        );
    }

    /// A chain is held to keys and signatures of 112 bits of security: an RSA
    /// key under 2048 bits, the leaf's or an authority's, and a certificate
    /// signed over SHA-1 anchor nothing. The anchor's own signature is not
    /// judged: depositing it is what trusts it.
    #[test]
    fn a_chain_is_held_to_keys_and_signatures_strong_enough() {
        let (root, intermediate, _) = hierarchy();
        let strong = issue(Issuing {
            rsa_bits: Some(2048),
            ..Issuing::leaf("Leaf", &intermediate)
        });
        assert!(verify_chain(&[strong.der(), intermediate.der()], &[root.der()], AT).is_ok());

        let weak_leaf = issue(Issuing {
            rsa_bits: Some(1024),
            ..Issuing::leaf("Leaf", &intermediate)
        });
        let weak_authority = issue(Issuing {
            rsa_bits: Some(1024),
            ..Issuing::authority("Weak authority", Some(&root))
        });
        let under_weak = issue(Issuing::leaf("Leaf", &weak_authority));
        let over_sha1 = issue(Issuing {
            over_sha1: true,
            ..Issuing::leaf("Leaf", &intermediate)
        });
        for (chain, what) in [
            (vec![weak_leaf.der(), intermediate.der()], "a leaf's key"),
            (
                vec![under_weak.der(), weak_authority.der()],
                "an authority's key",
            ),
            (
                vec![over_sha1.der(), intermediate.der()],
                "a signature over SHA-1",
            ),
        ] {
            assert_eq!(
                verify_chain(&chain, &[root.der()], AT).unwrap_err(),
                Unanchored::TooWeak,
                "{what}"
            );
        }

        let old_root = issue(Issuing {
            over_sha1: true,
            ..Issuing::authority("Old root", None)
        });
        let leaf = issue(Issuing::leaf("Leaf", &old_root));
        assert!(
            verify_chain(&[leaf.der()], &[old_root.der()], AT).is_ok(),
            "the anchor's own signature was judged"
        );
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

    /// An authority is told apart from a leaf and from bytes that are no
    /// certificate at all.
    #[test]
    fn an_authority_is_told_apart() {
        let (root, intermediate, leaf) = hierarchy();
        assert!(super::is_authority(&root.der()));
        assert!(super::is_authority(&intermediate.der()));
        assert!(!super::is_authority(&leaf.der()));
        assert!(!super::is_authority(b"not a certificate"));
    }

    /// An authority whose extensions OpenSSL finds malformed is none, whatever
    /// its basic constraints say.
    #[test]
    fn an_authority_with_malformed_extensions_is_none() {
        let malformed = issue(Issuing {
            usage_twice: true,
            ..Issuing::authority("Malformed", None)
        });
        assert!(!super::is_authority(&malformed.der()));
    }

    /// A PEM text gives back every certificate it carries, in order, and a
    /// text that carries none, or a broken one, gives nothing.
    #[test]
    fn a_pem_text_gives_back_what_it_carries() {
        let (root, intermediate, _) = hierarchy();
        let mut bundle = root.certificate.to_pem().expect("PEM");
        bundle.extend(intermediate.certificate.to_pem().expect("PEM"));
        assert_eq!(
            super::read_pem_certificates(&bundle),
            Some(vec![root.der(), intermediate.der()])
        );
        assert_eq!(super::read_pem_certificates(b"no certificate here"), None);
        let broken =
            b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
        assert_eq!(super::read_pem_certificates(broken), None);
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
