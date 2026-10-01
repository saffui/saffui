//! Certificate revocation lists (RFC 5280 §5): read under the authority whose
//! certificates they cover, and issued, for tests to revoke a certificate.

use std::cmp::Ordering;

use foreign_types::ForeignTypeRef;
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Crl, X509CrlBuilder, X509Extension, X509RevokedBuilder};

use crate::provider::PrivateKey;
use crate::x509::{encode_der, unix_seconds};

/// A revocation list read under its authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRevocations {
    /// The serial numbers revoked, each a magnitude in big-endian bytes.
    pub revoked: Vec<Vec<u8>>,
    /// When the list was issued, and when the next is due, in seconds since
    /// the epoch.
    pub this_update: i64,
    pub next_update: Option<i64>,
}

/// Why a revocation list was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnreadRevocations {
    #[error("the text is no certificate revocation list")]
    Unreadable,
    #[error("the list is issued under another name than its authority's")]
    AnotherAuthority,
    #[error("the list is not signed by its authority's key")]
    Unsigned,
    #[error("the authority's key is not for signing revocation lists")]
    NotForRevocations,
    #[error("the list says something critical this build does not read")]
    Critical,
}

/// Read the revocation list `served`, DER or PEM, as the one `authority`, a
/// DER certificate, issues for the certificates it issued: issued under its
/// name, signed by its key, which is for signing lists when its key usage
/// says what it is for, and with no critical extension, of the list or of an
/// entry. A delta list, a list partitioned by an issuing distribution point
/// and an entry another authority issued all mark themselves critical, and
/// are refused rather than read for less than they say.
pub fn read_revocation_list(
    served: &[u8],
    authority: &[u8],
) -> Result<ReadRevocations, UnreadRevocations> {
    let list = X509Crl::from_der(served)
        .or_else(|_| X509Crl::from_pem(served))
        .map_err(|_| UnreadRevocations::Unreadable)?;
    let authority = X509::from_der(authority).map_err(|_| UnreadRevocations::Unreadable)?;
    let named = list
        .issuer_name()
        .try_cmp(authority.subject_name())
        .map_err(|_| UnreadRevocations::Unreadable)?;
    if named != Ordering::Equal {
        return Err(UnreadRevocations::AnotherAuthority);
    }
    // SAFETY: the pointer is the live certificate parsed above; the call reads
    // and caches its extensions and keeps no reference to it. An authority
    // saying nothing of its key usage is read as fit for every usage, and one
    // whose extensions cannot be read as fit for none.
    let usage = unsafe { openssl_sys::X509_get_key_usage(authority.as_ptr()) };
    if usage & openssl_sys::X509v3_KU_CRL_SIGN == 0 {
        return Err(UnreadRevocations::NotForRevocations);
    }
    let key = authority
        .public_key()
        .map_err(|_| UnreadRevocations::Unreadable)?;
    if !list.verify(&key).unwrap_or(false) {
        return Err(UnreadRevocations::Unsigned);
    }
    if says_something_critical(&list) {
        return Err(UnreadRevocations::Critical);
    }
    let this_update = unix_seconds(list.last_update()).ok_or(UnreadRevocations::Unreadable)?;
    let next_update = list
        .next_update()
        .map(|time| unix_seconds(time).ok_or(UnreadRevocations::Unreadable))
        .transpose()?;
    let revoked = list
        .get_revoked()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    entry
                        .serial_number()
                        .to_bn()
                        .map(|serial| serial.to_vec())
                        .map_err(|_| UnreadRevocations::Unreadable)
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(ReadRevocations {
        revoked,
        this_update,
        next_update,
    })
}

/// Whether the list, or one of its entries, carries a critical extension.
fn says_something_critical(list: &X509Crl) -> bool {
    // SAFETY: every pointer is the live list parsed by the caller or an entry
    // of it; each call reads and keeps no reference.
    unsafe {
        let raw = list.as_ptr();
        let critical_in_list = (0..openssl_sys::X509_CRL_get_ext_count(raw)).any(|at| {
            openssl_sys::X509_EXTENSION_get_critical(openssl_sys::X509_CRL_get_ext(raw, at)) == 1
        });
        let critical_in_entry = list.get_revoked().is_some_and(|entries| {
            entries.iter().any(|entry| {
                let raw = entry.as_ptr();
                (0..openssl_sys::X509_REVOKED_get_ext_count(raw)).any(|at| {
                    openssl_sys::X509_EXTENSION_get_critical(openssl_sys::X509_REVOKED_get_ext(
                        raw, at,
                    )) == 1
                })
            })
        });
        critical_in_list || critical_in_entry
    }
}

/// What a revocation list an authority issues says.
#[derive(Debug, Clone, Copy)]
pub struct Revoking<'a> {
    /// The authority's certificate, DER, and its private key.
    pub issuer_certificate: &'a [u8],
    pub issuer_key: &'a PrivateKey,
    /// The serials revoked, each a magnitude in big-endian bytes.
    pub revoked: &'a [&'a [u8]],
    pub this_update: i64,
    pub next_update: i64,
}

/// A revocation list, DER, signed with SHA-256 under the authority's key, as
/// RFC 5280 §5 has a conforming authority issue one: naming the authority's
/// key, numbered, and saying when the next is due. For tests to revoke a
/// certificate with. Nothing when a key, the certificate or a serial does not
/// parse, the authority's certificate names no key of its own, or a time does
/// not fit.
pub fn issue_revocation_list(revoking: &Revoking<'_>) -> Option<Vec<u8>> {
    let issuer = X509::from_der(revoking.issuer_certificate).ok()?;
    let key = PKey::private_key_from_der(revoking.issuer_key.der()).ok()?;
    let issued = Asn1Time::from_unix(revoking.this_update).ok()?;
    let mut list = start_revocation_list(&issuer, &issued, revoking.next_update)?;
    for serial in revoking.revoked {
        let serial = BigNum::from_slice(serial).ok()?.to_asn1_integer().ok()?;
        let mut entry = X509RevokedBuilder::new().ok()?;
        entry.set_serial_number(&serial).ok()?;
        entry.set_revocation_date(&issued).ok()?;
        list.add_revoked(entry.build()).ok()?;
    }
    list.sort().ok()?;
    list.sign(&key, MessageDigest::sha256()).ok()?;
    list.build().ok()?.to_der().ok()
}

/// A list under `issuer`'s name and key identifier, numbered one, issued at
/// `issued` and due again at `next`: what OpenSSL's builder asks of every
/// list it builds.
fn start_revocation_list(issuer: &X509, issued: &Asn1Time, next: i64) -> Option<X509CrlBuilder> {
    let identifier = issuer.subject_key_id()?.as_slice();
    let next = Asn1Time::from_unix(next).ok()?;
    let mut list = X509CrlBuilder::new().ok()?;
    list.set_issuer_name(issuer.subject_name()).ok()?;
    list.set_last_update(issued).ok()?;
    list.set_next_update(&next).ok()?;
    let named = encode_der(0x30, &encode_der(0x80, identifier)?)?;
    list.append_extension(build_extension("2.5.29.35", &named)?)
        .ok()?;
    list.append_extension(build_extension("2.5.29.20", &encode_der(0x02, &[0x01])?)?)
        .ok()?;
    Some(list)
}

/// A non-critical extension of the given OID holding `value`, DER.
fn build_extension(oid: &str, value: &[u8]) -> Option<X509Extension> {
    let named = Asn1Object::from_str(oid).ok()?;
    let value = Asn1OctetString::new_from_bytes(value).ok()?;
    X509Extension::new_from_der(&named, false, &value).ok()
}

#[cfg(test)]
mod tests {
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Crl, X509CrlBuilder, X509Extension, X509Revoked};

    use super::*;
    use crate::provider::PublicKey;
    use crate::x509::{Certifying, certify_key, encode_der};

    const NOW: i64 = 1_790_000_000;

    struct Authority {
        key: PKey<Private>,
        certificate: Vec<u8>,
    }

    fn drawn_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key")
    }

    fn private_of(key: &PKey<Private>) -> PrivateKey {
        PrivateKey::from_der(key.private_key_to_der().expect("PKCS#8"))
    }

    /// A key certified as `name`, by itself when `issuer` is absent, for
    /// issuing when `authority` says so.
    fn certified(name: &str, issuer: Option<&Authority>, authority: bool) -> Authority {
        let key = drawn_key();
        let public = PublicKey::from_der(key.public_key_to_der().expect("SPKI"));
        let signer = private_of(issuer.map_or(&key, |issuer| &issuer.key));
        let certificate = certify_key(&Certifying {
            subject_key: &public,
            subject_name: name,
            issuer_certificate: issuer.map(|issuer| issuer.certificate.as_slice()),
            issuer_key: &signer,
            serial: &[0x0a, 0x0b],
            not_before: NOW - 3_600,
            not_after: NOW + 86_400,
            authority,
            revocation_list: None,
        })
        .expect("a certificate");
        Authority { key, certificate }
    }

    fn revoked_by(authority: &Authority, serials: &[&[u8]], next: i64) -> Vec<u8> {
        issue_revocation_list(&Revoking {
            issuer_certificate: &authority.certificate,
            issuer_key: &private_of(&authority.key),
            revoked: serials,
            this_update: NOW - 60,
            next_update: next,
        })
        .expect("a list")
    }

    /// A list is read under the authority that issued it, DER or PEM: what it
    /// revokes, when it was issued and when the next is due.
    #[test]
    fn a_list_is_read_under_its_authority() {
        let root = certified("Root", None, true);
        let list = revoked_by(&root, &[&[0x0a, 0x0b], &[0x01]], NOW + 3_600);
        let expected = ReadRevocations {
            revoked: vec![vec![0x01], vec![0x0a, 0x0b]],
            this_update: NOW - 60,
            next_update: Some(NOW + 3_600),
        };
        assert_eq!(
            read_revocation_list(&list, &root.certificate),
            Ok(expected.clone())
        );
        let pem = X509Crl::from_der(&list)
            .and_then(|read| read.to_pem())
            .expect("PEM");
        assert_eq!(read_revocation_list(&pem, &root.certificate), Ok(expected));
        let empty = revoked_by(&root, &[], NOW + 60);
        assert_eq!(
            read_revocation_list(&empty, &root.certificate),
            Ok(ReadRevocations {
                revoked: Vec::new(),
                this_update: NOW - 60,
                next_update: Some(NOW + 60),
            })
        );
    }

    /// An authority issuing itself that says nothing of what its key is for.
    fn certified_without_usage(name: &str) -> Authority {
        use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
        use openssl::x509::{X509Builder, X509NameBuilder};
        let key = drawn_key();
        let mut named = X509NameBuilder::new().expect("a name");
        named
            .append_entry_by_nid(Nid::COMMONNAME, name)
            .expect("a common name");
        let named = named.build();
        let serial = BigNum::from_u32(7)
            .and_then(|serial| serial.to_asn1_integer())
            .expect("a serial");
        let mut builder = X509Builder::new().expect("a builder");
        builder.set_version(2).expect("version 3");
        builder.set_serial_number(&serial).expect("the serial");
        builder.set_subject_name(&named).expect("a subject");
        builder.set_issuer_name(&named).expect("itself");
        builder.set_pubkey(&key).expect("the key");
        builder
            .set_not_before(&Asn1Time::from_unix(NOW - 3_600).expect("a start"))
            .expect("a start");
        builder
            .set_not_after(&Asn1Time::from_unix(NOW + 86_400).expect("an end"))
            .expect("an end");
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .expect("constraints"),
            )
            .expect("constraints");
        let identifier = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .expect("a key identifier");
        builder
            .append_extension(identifier)
            .expect("a key identifier");
        builder.sign(&key, MessageDigest::sha256()).expect("signed");
        Authority {
            key,
            certificate: builder.build().to_der().expect("DER"),
        }
    }

    /// An authority saying nothing of what its key is for signs its lists, as
    /// RFC 5280 reads a certificate with no key usage.
    #[test]
    fn an_authority_saying_nothing_of_its_key_usage_signs_its_lists() {
        let silent = certified_without_usage("Silent root");
        let list = revoked_by(&silent, &[&[0x01]], NOW + 60);
        assert_eq!(
            read_revocation_list(&list, &silent.certificate).map(|read| read.revoked),
            Ok(vec![vec![0x01]])
        );
    }

    /// A list built here, with what `change` adds before it is signed.
    fn signed_with(authority: &Authority, change: impl FnOnce(&mut X509CrlBuilder)) -> Vec<u8> {
        let issuer = openssl::x509::X509::from_der(&authority.certificate).expect("a certificate");
        let issued = Asn1Time::from_unix(NOW).expect("a time");
        let mut list = start_revocation_list(&issuer, &issued, NOW + 60).expect("a builder");
        change(&mut list);
        list.sign(&authority.key, MessageDigest::sha256())
            .expect("signed");
        list.build().expect("a list").to_der().expect("DER")
    }

    /// A list that is not its authority's, or says what this build does not
    /// read, is refused in words.
    #[test]
    fn a_list_not_fit_for_its_authority_is_refused_in_words() {
        let root = certified("Root", None, true);
        let list = revoked_by(&root, &[&[0x01]], NOW + 60);
        assert_eq!(
            read_revocation_list(b"no list", &root.certificate),
            Err(UnreadRevocations::Unreadable)
        );
        assert_eq!(
            read_revocation_list(&list, b"no certificate"),
            Err(UnreadRevocations::Unreadable)
        );
        let renamed = certified("Other root", None, true);
        assert_eq!(
            read_revocation_list(&list, &renamed.certificate),
            Err(UnreadRevocations::AnotherAuthority)
        );
        let impostor = certified("Root", None, true);
        assert_eq!(
            read_revocation_list(&list, &impostor.certificate),
            Err(UnreadRevocations::Unsigned)
        );
        let leaf = certified("Leaf", Some(&root), false);
        assert_eq!(
            read_revocation_list(&revoked_by(&leaf, &[&[0x01]], NOW + 60), &leaf.certificate),
            Err(UnreadRevocations::NotForRevocations)
        );

        let critical = signed_with(&root, |list| {
            let delta = Asn1Object::from_str("2.5.29.27").expect("an OID");
            let base = Asn1OctetString::new_from_bytes(&[0x02, 0x01, 0x07]).expect("bytes");
            list.append_extension(
                X509Extension::new_from_der(&delta, true, &base).expect("an extension"),
            )
            .expect("appended");
        });
        assert_eq!(
            read_revocation_list(&critical, &root.certificate),
            Err(UnreadRevocations::Critical)
        );
        let flagged = signed_with(&root, |list| {
            let reason = [
                encode_der(0x06, &[0x55, 0x1d, 0x15]).expect("DER"),
                encode_der(0x01, &[0xff]).expect("DER"),
                encode_der(0x04, &encode_der(0x0a, &[0x01]).expect("DER")).expect("DER"),
            ]
            .concat();
            let entry = [
                encode_der(0x02, &[0x01]).expect("DER"),
                encode_der(0x17, b"260921100000Z").expect("DER"),
                encode_der(0x30, &encode_der(0x30, &reason).expect("DER")).expect("DER"),
            ]
            .concat();
            let entry =
                X509Revoked::from_der(&encode_der(0x30, &entry).expect("DER")).expect("an entry");
            list.add_revoked(entry).expect("added");
        });
        assert_eq!(
            read_revocation_list(&flagged, &root.certificate),
            Err(UnreadRevocations::Critical),
            "an entry carrying a critical extension"
        );
        let plain = signed_with(&root, |_| {});
        assert!(read_revocation_list(&plain, &root.certificate).is_ok());
    }
}
