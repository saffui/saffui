use crate::provider::PublicKey;

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

#[cfg(test)]
mod tests {
    use super::public_key_of;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};

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
}
