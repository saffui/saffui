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
