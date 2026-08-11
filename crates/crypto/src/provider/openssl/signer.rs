//! Signatures over OpenSSL.

use openssl::pkey::{Id, PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer, Verifier};

use crate::provider::openssl::digest::message_digest;
use crate::provider::{
    CryptoError, HashAlg, PrivateKey, PublicKey, Result, SignAlg, SignerProvider,
};

pub struct OpenSslSigner;

/// RFC 7518 3.5: the PSS salt is as long as the digest.
fn configure_pss<F>(set: F, hash: HashAlg) -> Result<()>
where
    F: FnOnce(Padding, openssl::hash::MessageDigest, RsaPssSaltlen) -> Result<()>,
{
    set(
        Padding::PKCS1_PSS,
        message_digest(hash),
        RsaPssSaltlen::custom(hash.output_len() as i32),
    )
}

/// The algorithm names a key family as well as a digest, and OpenSSL will not
/// check that for us: `Signer::new` signs with whatever the key is, so asking
/// for RS256 over an EC key yields an ECDSA signature under an RSA name. That
/// verifies nowhere, and a reader trusting `alg` to say what it is holding has
/// been told something false. Refused here instead.
fn check_family(alg: SignAlg, id: Id) -> Result<()> {
    let ok = match alg {
        SignAlg::Rs256 | SignAlg::Rs384 | SignAlg::Rs512 => id == Id::RSA,
        SignAlg::Ps256 | SignAlg::Ps384 | SignAlg::Ps512 => id == Id::RSA || id == Id::RSA_PSS,
        SignAlg::Es256 | SignAlg::Es384 | SignAlg::Es512 => id == Id::EC,
        SignAlg::EdDsa => id == Id::ED25519 || id == Id::ED448,
    };

    if ok {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

fn private(alg: SignAlg, key: &PrivateKey) -> Result<PKey<Private>> {
    let pkey = PKey::private_key_from_der(key.der()).map_err(|_| CryptoError::InvalidKey)?;
    check_family(alg, pkey.id())?;
    Ok(pkey)
}

fn public(alg: SignAlg, key: &PublicKey) -> Result<PKey<Public>> {
    let pkey = PKey::public_key_from_der(key.der()).map_err(|_| CryptoError::InvalidKey)?;
    check_family(alg, pkey.id())?;
    Ok(pkey)
}

impl SignerProvider for OpenSslSigner {
    fn sign(&self, alg: SignAlg, key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>> {
        let pkey = private(alg, key)?;

        match alg.hash() {
            // EdDSA hashes internally and signs in one shot. Pre-hashing it
            // would sign the digest rather than the message.
            None => Signer::new_without_digest(&pkey)
                .map_err(|_| CryptoError::InvalidKey)?
                .sign_oneshot_to_vec(data)
                .map_err(|_| CryptoError::OperationFailed),
            Some(hash) => {
                let mut signer = Signer::new(message_digest(hash), &pkey)
                    .map_err(|_| CryptoError::InvalidKey)?;

                if alg.is_pss() {
                    configure_pss(
                        |padding, md, salt| {
                            signer
                                .set_rsa_padding(padding)
                                .and_then(|_| signer.set_rsa_mgf1_md(md))
                                .and_then(|_| signer.set_rsa_pss_saltlen(salt))
                                .map_err(|_| CryptoError::OperationFailed)
                        },
                        hash,
                    )?;
                }

                signer
                    .update(data)
                    .map_err(|_| CryptoError::OperationFailed)?;
                signer
                    .sign_to_vec()
                    .map_err(|_| CryptoError::OperationFailed)
            }
        }
    }

    fn verify(&self, alg: SignAlg, key: &PublicKey, data: &[u8], sig: &[u8]) -> Result<bool> {
        let pkey = public(alg, key)?;

        match alg.hash() {
            None => Verifier::new_without_digest(&pkey)
                .map_err(|_| CryptoError::InvalidKey)?
                .verify_oneshot(sig, data)
                .map_err(|_| CryptoError::OperationFailed),
            Some(hash) => {
                let mut verifier = Verifier::new(message_digest(hash), &pkey)
                    .map_err(|_| CryptoError::InvalidKey)?;

                if alg.is_pss() {
                    configure_pss(
                        |padding, md, salt| {
                            verifier
                                .set_rsa_padding(padding)
                                .and_then(|_| verifier.set_rsa_mgf1_md(md))
                                .and_then(|_| verifier.set_rsa_pss_saltlen(salt))
                                .map_err(|_| CryptoError::OperationFailed)
                        },
                        hash,
                    )?;
                }

                verifier
                    .update(data)
                    .map_err(|_| CryptoError::OperationFailed)?;
                verifier
                    .verify(sig)
                    .map_err(|_| CryptoError::OperationFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::rsa::Rsa;

    /// Keys cross the seam as DER, so the tests build them the way a caller
    /// would: whatever OpenSSL produced, written out as PKCS#8 and SPKI.
    fn keys_from(pkey: PKey<Private>) -> (PrivateKey, PublicKey) {
        (
            PrivateKey::from_der(pkey.private_key_to_pkcs8().unwrap()),
            PublicKey::from_der(pkey.public_key_to_der().unwrap()),
        )
    }

    fn rsa() -> (PrivateKey, PublicKey) {
        keys_from(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap())
    }

    fn ec(nid: Nid) -> (PrivateKey, PublicKey) {
        let group = EcGroup::from_curve_name(nid).unwrap();
        keys_from(PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap())
    }

    fn round_trip(alg: SignAlg, private: &PrivateKey, public: &PublicKey) {
        let data = b"the quick brown fox";
        let sig = OpenSslSigner.sign(alg, private, data).unwrap();

        assert!(
            OpenSslSigner.verify(alg, public, data, &sig).unwrap(),
            "{alg:?} did not verify its own signature"
        );

        // A signature only means something if a changed one fails.
        let mut moved = sig.clone();
        moved[0] ^= 1;
        assert!(
            !OpenSslSigner
                .verify(alg, public, data, &moved)
                .unwrap_or(false)
        );

        assert!(
            !OpenSslSigner
                .verify(alg, public, b"other message", &sig)
                .unwrap_or(false),
            "{alg:?} verified another message"
        );

        assert!(
            !OpenSslSigner
                .verify(alg, public, data, b"")
                .unwrap_or(false)
        );
    }

    /// PKCS#1 v1.5, one key for the three digests.
    #[test]
    fn rsassa_algorithms_round_trip() {
        let (private, public) = rsa();
        for alg in [SignAlg::Rs256, SignAlg::Rs384, SignAlg::Rs512] {
            round_trip(alg, &private, &public);
        }
    }

    /// PSS over the same key: the padding is chosen per signature, not per key.
    #[test]
    fn rsassa_pss_algorithms_round_trip() {
        let (private, public) = rsa();
        for alg in [SignAlg::Ps256, SignAlg::Ps384, SignAlg::Ps512] {
            round_trip(alg, &private, &public);
        }
    }

    #[test]
    fn ecdsa_algorithms_round_trip() {
        let cases = [
            (SignAlg::Es256, Nid::X9_62_PRIME256V1),
            (SignAlg::Es384, Nid::SECP384R1),
            (SignAlg::Es512, Nid::SECP521R1),
        ];
        for (alg, nid) in cases {
            let (private, public) = ec(nid);
            round_trip(alg, &private, &public);
        }
    }

    #[test]
    fn eddsa_round_trips() {
        let (private, public) = keys_from(PKey::generate_ed25519().unwrap());
        round_trip(SignAlg::EdDsa, &private, &public);
    }

    /// PSS and PKCS#1 v1.5 are different paddings over one key, and a
    /// signature made under one must not verify under the other.
    ///
    /// This is what `is_pss` decides, and getting it wrong produces signatures
    /// that verify nowhere while looking like a key problem.
    #[test]
    fn a_pss_signature_does_not_verify_as_pkcs1() {
        let (private, public) = rsa();
        let data = b"payload";

        let pss = OpenSslSigner.sign(SignAlg::Ps256, &private, data).unwrap();
        assert!(
            !OpenSslSigner
                .verify(SignAlg::Rs256, &public, data, &pss)
                .unwrap_or(false)
        );

        let pkcs1 = OpenSslSigner.sign(SignAlg::Rs256, &private, data).unwrap();
        assert!(
            !OpenSslSigner
                .verify(SignAlg::Ps256, &public, data, &pkcs1)
                .unwrap_or(false)
        );
    }

    /// A signature does not verify under another key of the same shape.
    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let (private, _) = ec(Nid::X9_62_PRIME256V1);
        let (_, other_public) = ec(Nid::X9_62_PRIME256V1);

        let sig = OpenSslSigner
            .sign(SignAlg::Es256, &private, b"payload")
            .unwrap();
        assert!(
            !OpenSslSigner
                .verify(SignAlg::Es256, &other_public, b"payload", &sig)
                .unwrap_or(false)
        );
    }

    /// Key material that is not a key is refused before anything is signed.
    #[test]
    fn input_that_is_not_a_key_is_refused() {
        let private = PrivateKey::from_der(b"garbage".to_vec());
        let public = PublicKey::from_der(b"garbage".to_vec());

        assert!(matches!(
            OpenSslSigner.sign(SignAlg::Rs256, &private, b"payload"),
            Err(CryptoError::InvalidKey)
        ));
        assert!(matches!(
            OpenSslSigner.verify(SignAlg::Rs256, &public, b"payload", b"sig"),
            Err(CryptoError::InvalidKey)
        ));
    }

    /// An EC key cannot sign as RSA, and the refusal is an error rather than a
    /// signature nobody can check.
    #[test]
    fn a_key_of_the_wrong_family_is_refused() {
        let (private, public) = ec(Nid::X9_62_PRIME256V1);

        assert!(
            OpenSslSigner
                .sign(SignAlg::Rs256, &private, b"payload")
                .is_err()
        );
        assert!(
            OpenSslSigner
                .sign(SignAlg::EdDsa, &private, b"payload")
                .is_err()
        );
        assert!(
            OpenSslSigner
                .verify(SignAlg::Rs256, &public, b"payload", b"sig")
                .is_err()
        );
    }
}
