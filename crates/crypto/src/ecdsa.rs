use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;

use crate::provider::{CryptoError, Result};

/// A raw `r‖s` ECDSA signature re-encoded as the DER the signer verifies.
///
/// A PKCS#11 token and an XML signature both write the two halves side by
/// side, equal and fixed by the curve. An empty or odd length is no signature
/// from any curve, and is refused rather than split.
pub fn der_from_raw_signature(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(CryptoError::OperationFailed);
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let signature = EcdsaSig::from_private_components(
        BigNum::from_slice(r).map_err(|_| CryptoError::OperationFailed)?,
        BigNum::from_slice(s).map_err(|_| CryptoError::OperationFailed)?,
    )
    .map_err(|_| CryptoError::OperationFailed)?;
    signature.to_der().map_err(|_| CryptoError::OperationFailed)
}

#[cfg(test)]
mod tests {
    use super::der_from_raw_signature;
    use crate::provider::openssl::signer::OpenSslSigner;
    use crate::provider::{PrivateKey, PublicKey, SignAlg, SignerProvider};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;

    /// A signature split into its two halves verifies once re-encoded, and a
    /// length no curve writes is refused.
    #[test]
    fn a_raw_signature_verifies_once_re_encoded() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256");
        let key = PKey::from_ec_key(EcKey::generate(&group).expect("a key")).expect("a key");
        let private = PrivateKey::from_der(key.private_key_to_pkcs8().expect("PKCS#8"));
        let public = PublicKey::from_der(key.public_key_to_der().expect("SPKI"));
        let signed = OpenSslSigner
            .sign(SignAlg::Es256, &private, b"message")
            .expect("a signature");
        let halves = EcdsaSig::from_der(&signed).expect("DER");
        let mut raw = halves.r().to_vec_padded(32).expect("r");
        raw.extend(halves.s().to_vec_padded(32).expect("s"));

        let re_encoded = der_from_raw_signature(&raw).expect("re-encoded");
        assert!(
            OpenSslSigner
                .verify(SignAlg::Es256, &public, b"message", &re_encoded)
                .expect("a verdict")
        );
        assert!(der_from_raw_signature(&raw[..63]).is_err());
        assert!(der_from_raw_signature(&[]).is_err());
    }
}
