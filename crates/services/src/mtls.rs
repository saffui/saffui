use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::{BASE64, BASE64URL_NOPAD};

/// Why a certificate a proxy forwarded could not be read.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum Unreadable {
    #[error("the header does not carry a certificate this build can read")]
    Malformed,
}

/// The RFC 8705 §3.1 thumbprint of the certificate a proxy forwarded.
///
/// Over the DER, which is what the certificate is: a thumbprint over the
/// text around it would change with the wrapping and name a different
/// certificate for the same key.
///
/// Two shapes are read, because the proxies in front write both. Caddy and
/// nginx write PEM, either as it stands or with its newlines percent encoded
/// to fit on a header line; some write the base64 body alone.
pub fn thumbprint(provider: &dyn CryptoProvider, carried: &str) -> Result<String, Unreadable> {
    let der = der_of(carried).ok_or(Unreadable::Malformed)?;
    provider
        .digest()
        .hash(HashAlg::Sha256, &der)
        .map(|held| BASE64URL_NOPAD.encode(&held))
        .map_err(|_| Unreadable::Malformed)
}

/// The URI subject-alternative-names of the forwarded certificate: the
/// identities a workload mesh stamps into its leaves.
pub fn san_uris(carried: &str) -> Result<Vec<String>, Unreadable> {
    let der = der_of(carried).ok_or(Unreadable::Malformed)?;
    crypto::x509::san_uris(&der).ok_or(Unreadable::Malformed)
}

fn der_of(carried: &str) -> Option<Vec<u8>> {
    // A header cannot hold a newline, so a proxy that forwards PEM either
    // escapes them or writes the body alone. Both arrive here as one line.
    let unescaped = carried.replace("%0A", "\n").replace("%0a", "\n");
    let body: String = unescaped
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(str::chars)
        .filter(|held| !held.is_whitespace())
        .collect();
    if body.is_empty() {
        return None;
    }
    BASE64.decode(body.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same certificate, written the three ways a proxy writes it, is the
    /// same certificate. A thumbprint that moved with the wrapping would bind
    /// a token to a shape rather than to a key.
    #[test]
    fn the_wrapping_does_not_change_what_is_named() {
        let der = [0x30_u8, 0x82, 0x01, 0x0a, 0x02, 0x01, 0x01];
        let body = BASE64.encode(&der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----");

        let bare = der_of(&body).expect("the body alone");
        let wrapped = der_of(&pem).expect("pem");
        let escaped = der_of(&pem.replace('\n', "%0A")).expect("pem with escaped newlines");

        assert_eq!(bare, der);
        assert_eq!(wrapped, der);
        assert_eq!(escaped, der);
    }

    #[test]
    fn a_header_carrying_nothing_names_nothing() {
        assert_eq!(der_of(""), None);
        assert_eq!(
            der_of("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
            None
        );
        assert_eq!(der_of("not base64 at all !!"), None);
    }
}
