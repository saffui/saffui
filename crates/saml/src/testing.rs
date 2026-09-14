use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, PublicKey};

pub fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
}

/// The key a base64 certificate fixture certifies.
pub fn key_certified_by(certificate: &str) -> PublicKey {
    let der = data_encoding::BASE64
        .decode(certificate.trim().as_bytes())
        .expect("base64");
    crypto::x509::public_key_of(&der).expect("a certificate")
}
