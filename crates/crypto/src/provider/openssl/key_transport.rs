use openssl::encrypt::Decrypter;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use secrecy::SecretBox;

use crate::provider::openssl::digest::message_digest;
use crate::provider::{CryptoError, HashAlg, KeyTransportProvider, PrivateKey, Result};

pub struct OpenSslKeyTransport;

impl KeyTransportProvider for OpenSslKeyTransport {
    fn unwrap_rsa_oaep(
        &self,
        key: &PrivateKey,
        oaep_digest: HashAlg,
        mgf1_digest: HashAlg,
        wrapped: &[u8],
    ) -> Result<SecretBox<Vec<u8>>> {
        let pkey = PKey::private_key_from_der(key.der()).map_err(|_| CryptoError::InvalidKey)?;
        if pkey.rsa().is_err() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let mut decrypter = Decrypter::new(&pkey).map_err(|_| CryptoError::InvalidKey)?;
        decrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .and_then(|_| decrypter.set_rsa_oaep_md(message_digest(oaep_digest)))
            .and_then(|_| decrypter.set_rsa_mgf1_md(message_digest(mgf1_digest)))
            .map_err(|_| CryptoError::OperationFailed)?;
        let length = decrypter
            .decrypt_len(wrapped)
            .map_err(|_| CryptoError::OperationFailed)?;
        let mut unwrapped = vec![0; length];
        let written = decrypter
            .decrypt(wrapped, &mut unwrapped)
            .map_err(|_| CryptoError::OperationFailed)?;
        unwrapped.truncate(written);
        Ok(SecretBox::new(Box::new(unwrapped)))
    }
}

#[cfg(test)]
mod tests {
    use super::OpenSslKeyTransport;
    use crate::provider::openssl::digest::message_digest;
    use crate::provider::{CryptoError, HashAlg, KeyTransportProvider, PrivateKey};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::encrypt::Encrypter;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::{Padding, Rsa};
    use secrecy::ExposeSecret;

    fn wrapped(pkey: &PKey<Private>, oaep: HashAlg, mgf1: HashAlg, key: &[u8]) -> Vec<u8> {
        let mut encrypter = Encrypter::new(pkey).expect("an encrypter");
        encrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .expect("OAEP");
        encrypter
            .set_rsa_oaep_md(message_digest(oaep))
            .expect("the OAEP digest");
        encrypter
            .set_rsa_mgf1_md(message_digest(mgf1))
            .expect("the MGF1 digest");
        let mut out = vec![0; encrypter.encrypt_len(key).expect("a length")];
        let written = encrypter.encrypt(key, &mut out).expect("wrapped");
        out.truncate(written);
        out
    }

    /// A key wrapped under a pairing of digests unwraps under that pairing and
    /// under no other, and a key that is not RSA is refused.
    #[test]
    fn a_wrapped_key_unwraps_only_under_its_own_digests() {
        let pkey = PKey::from_rsa(Rsa::generate(2048).expect("a key")).expect("a key");
        let private = PrivateKey::from_der(pkey.private_key_to_pkcs8().expect("PKCS#8"));
        let content_key = [0x5a_u8; 32];
        for (oaep, mgf1) in [
            (HashAlg::Sha1, HashAlg::Sha1),
            (HashAlg::Sha256, HashAlg::Sha1),
            (HashAlg::Sha256, HashAlg::Sha256),
        ] {
            let sealed = wrapped(&pkey, oaep, mgf1, &content_key);
            let opened = OpenSslKeyTransport
                .unwrap_rsa_oaep(&private, oaep, mgf1, &sealed)
                .expect("unwrapped");
            assert_eq!(opened.expose_secret().as_slice(), &content_key);
            let other = if mgf1 == HashAlg::Sha1 {
                HashAlg::Sha256
            } else {
                HashAlg::Sha1
            };
            assert!(
                OpenSslKeyTransport
                    .unwrap_rsa_oaep(&private, oaep, other, &sealed)
                    .is_err()
            );
        }

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        let ec = PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key");
        let ec_private = PrivateKey::from_der(ec.private_key_to_pkcs8().expect("PKCS#8"));
        assert!(matches!(
            OpenSslKeyTransport.unwrap_rsa_oaep(
                &ec_private,
                HashAlg::Sha1,
                HashAlg::Sha1,
                &[0; 256]
            ),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
    }
}
