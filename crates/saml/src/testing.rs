use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, PrivateKey, PublicKey};
use crypto::x509::{Issuance, issue_certificate};

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

/// A key the crypto crate draws for a test run, kept as its DER halves so a static
/// can hold it and every case of a module signs and verifies with the same one.
pub struct DrawnKey {
    private_der: Vec<u8>,
    public_der: Vec<u8>,
}

impl DrawnKey {
    pub fn draw_rsa() -> Self {
        Self::keep(&RsaKeyPair::generate(2048).expect("an RSA key"))
    }

    pub fn draw_ec() -> Self {
        Self::keep(&EcKeyPair::generate(EcCurve::P256).expect("an EC key"))
    }

    fn keep(pair: &impl KeyPair) -> Self {
        Self {
            private_der: pair.to_der_private_key(),
            public_der: pair.to_der_public_key(),
        }
    }

    pub fn to_private_key(&self) -> PrivateKey {
        PrivateKey::from_der(self.private_der.clone())
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from_der(self.public_der.clone())
    }

    /// A certificate for this key in base64, as metadata carries it, issued by the
    /// crypto crate under an RSA key drawn for the purpose.
    pub fn issue_certificate_in_base64(&self) -> String {
        let issuer = Self::draw_rsa();
        let der = issue_certificate(&Issuance {
            subject_key: &self.to_public_key(),
            subject_name: "idp.test",
            issuer_key: &issuer.to_private_key(),
            issuer_name: "idp.test",
            serial: &[1],
            not_before: 1_789_372_800,
            not_after: 2_104_992_000,
        })
        .expect("a certificate issued by the crypto crate");
        data_encoding::BASE64.encode(&der)
    }
}
