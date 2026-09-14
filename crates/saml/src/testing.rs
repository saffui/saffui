use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, PrivateKey, PublicKey};

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

/// The private key a base64 PKCS#8 fixture holds.
pub fn private_key_of(pkcs8: &str) -> PrivateKey {
    PrivateKey::from_der(
        data_encoding::BASE64
            .decode(pkcs8.trim().as_bytes())
            .expect("base64"),
    )
}
