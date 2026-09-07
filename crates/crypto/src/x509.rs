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
