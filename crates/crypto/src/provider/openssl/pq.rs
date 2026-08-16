//! Post-quantum algorithms over OpenSSL 3.5 or newer.
//!
//! The safe `openssl` crate has no bindings for these yet, so the key
//! generation goes through the raw FFI. Signing and verifying do not: OpenSSL
//! exposes ML-DSA through the ordinary `EVP_PKEY` signing path, and the crate's
//! digest-free variant of it is already safe.

use std::ffi::CString;
use std::ptr;

use foreign_types::ForeignType;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};

use crate::provider::{CryptoError, MlDsaAlg, PqSignatureProvider, PrivateKey, PublicKey, Result};

pub struct OpenSslPq;

impl MlDsaAlg {
    /// The name OpenSSL fetches the algorithm by.
    fn openssl_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }
}

/// Generate a key pair for an algorithm named at run time.
///
/// The only place in this crate that reaches past the safe API. It is here
/// because `EVP_PKEY_CTX_new_from_name` has no wrapper yet, and because a
/// fetch-by-name is how an algorithm the linked library may not have is asked
/// for: a libcrypto older than 3.5 returns null rather than failing to link.
pub(crate) fn generate_named(name: &str) -> Result<PKey<Private>> {
    let name = CString::new(name).map_err(|_| CryptoError::InvalidParams)?;

    // SAFETY: `name` is a valid NUL-terminated C string that outlives the call.
    // The context is freed on every path below, including the error ones. The
    // `EVP_PKEY` produced by a successful keygen is owned here and handed to
    // `PKey::from_ptr`, which takes that ownership; it is never freed twice
    // because the failure branches return before reaching it.
    unsafe {
        let ctx =
            openssl_sys::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), name.as_ptr(), ptr::null());
        if ctx.is_null() {
            // The algorithm is not in this libcrypto. Nothing to free.
            return Err(CryptoError::UnsupportedAlgorithm);
        }

        let generated = (|| {
            if openssl_sys::EVP_PKEY_keygen_init(ctx) <= 0 {
                return Err(CryptoError::UnsupportedAlgorithm);
            }

            let mut pkey = ptr::null_mut();
            if openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey) <= 0 || pkey.is_null() {
                return Err(CryptoError::OperationFailed);
            }

            Ok(PKey::from_ptr(pkey))
        })();

        openssl_sys::EVP_PKEY_CTX_free(ctx);
        generated
    }
}

impl PqSignatureProvider for OpenSslPq {
    fn generate(&self, alg: MlDsaAlg) -> Result<(PrivateKey, PublicKey)> {
        let pkey = generate_named(alg.openssl_name())?;

        let private = pkey
            .private_key_to_pkcs8()
            .map_err(|_| CryptoError::OperationFailed)?;
        let public = pkey
            .public_key_to_der()
            .map_err(|_| CryptoError::OperationFailed)?;

        Ok((PrivateKey::from_der(private), PublicKey::from_der(public)))
    }

    fn sign(&self, key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
        let pkey: PKey<Private> =
            PKey::private_key_from_pkcs8(key.der()).map_err(|_| CryptoError::InvalidKey)?;

        let mut signer =
            Signer::new_without_digest(&pkey).map_err(|_| CryptoError::UnsupportedAlgorithm)?;
        signer
            .sign_oneshot_to_vec(message)
            .map_err(|_| CryptoError::OperationFailed)
    }

    fn verify(&self, key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pkey: PKey<Public> =
            PKey::public_key_from_der(key.der()).map_err(|_| CryptoError::InvalidKey)?;

        let mut verifier =
            Verifier::new_without_digest(&pkey).map_err(|_| CryptoError::UnsupportedAlgorithm)?;

        // OpenSSL already answers `false` for a signature that is malformed,
        // truncated or simply wrong, so an error here is not "invalid" but
        // "could not check". Those are different answers and only one of them
        // is safe to report as a failed verification, so the error propagates.
        verifier
            .verify_oneshot(signature, message)
            .map_err(|_| CryptoError::OperationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::{CryptoConfig, CryptoProvider, SignAlg, SignerProvider};

    const ALGORITHMS: [MlDsaAlg; 3] = [MlDsaAlg::MlDsa44, MlDsaAlg::MlDsa65, MlDsaAlg::MlDsa87];

    /// Every parameter set signs its own message and refuses anything else.
    ///
    /// No published vector is used, and cannot be: ML-DSA is randomised, so two
    /// signatures over one message differ and no fixed answer exists to compare
    /// against. What is checked instead is that a signature verifies where it
    /// should and nowhere else — including under another parameter set, which
    /// is the substitution a round trip alone would not see.
    #[test]
    fn every_parameter_set_signs_and_verifies() {
        for alg in ALGORITHMS {
            let (private, public) = OpenSslPq.generate(alg).unwrap();
            let signature = OpenSslPq.sign(&private, b"the quick brown fox").unwrap();

            assert!(
                OpenSslPq
                    .verify(&public, b"the quick brown fox", &signature)
                    .unwrap(),
                "{alg:?} did not verify its own signature"
            );
            assert!(
                !OpenSslPq
                    .verify(&public, b"the quick brown fix", &signature)
                    .unwrap(),
                "{alg:?} verified another message"
            );

            let (_, other) = OpenSslPq.generate(alg).unwrap();
            assert!(
                !OpenSslPq
                    .verify(&other, b"the quick brown fox", &signature)
                    .unwrap(),
                "{alg:?} verified under another key"
            );
        }
    }

    /// A signature does not carry across parameter sets.
    #[test]
    fn a_signature_does_not_verify_under_another_parameter_set() {
        for alg in ALGORITHMS {
            let (private, _) = OpenSslPq.generate(alg).unwrap();
            let signature = OpenSslPq.sign(&private, b"payload").unwrap();

            for other in ALGORITHMS {
                if other == alg {
                    continue;
                }
                let (_, public) = OpenSslPq.generate(other).unwrap();
                assert!(
                    !OpenSslPq.verify(&public, b"payload", &signature).unwrap(),
                    "a {alg:?} signature verified as {other:?}"
                );
            }
        }
    }

    /// The three sets differ in strength, and the signature sizes say so.
    ///
    /// FIPS 204 fixes them: 2420, 3309 and 4627 bytes. A generate that quietly
    /// produced the same parameter set three times would pass every test above.
    #[test]
    fn each_parameter_set_has_the_size_the_standard_gives_it() {
        let expected = [
            (MlDsaAlg::MlDsa44, 2420usize),
            (MlDsaAlg::MlDsa65, 3309),
            (MlDsaAlg::MlDsa87, 4627),
        ];

        for (alg, size) in expected {
            let (private, _) = OpenSslPq.generate(alg).unwrap();
            assert_eq!(
                OpenSslPq.sign(&private, b"payload").unwrap().len(),
                size,
                "{alg:?}"
            );
        }
    }

    /// Two keys of one parameter set are different keys.
    #[test]
    fn generation_draws_a_fresh_key_each_time() {
        let (first_private, first_public) = OpenSslPq.generate(MlDsaAlg::MlDsa44).unwrap();
        let (second_private, second_public) = OpenSslPq.generate(MlDsaAlg::MlDsa44).unwrap();

        assert_ne!(first_private.der(), second_private.der());
        assert_ne!(first_public.der(), second_public.der());
    }

    /// A malformed signature verifies as false rather than raising.
    ///
    /// OpenSSL answers these itself, so the error path below it is not reached
    /// by any of them — which is why it reports "could not check" rather than
    /// folding into "did not verify". The two are different answers.
    #[test]
    fn a_malformed_signature_is_a_no_rather_than_an_error() {
        let (private, public) = OpenSslPq.generate(MlDsaAlg::MlDsa44).unwrap();
        let signature = OpenSslPq.sign(&private, b"payload").unwrap();

        for broken in [
            Vec::new(),
            vec![0u8; 8],
            signature[..signature.len() - 1].to_vec(),
            {
                let mut moved = signature.clone();
                moved[0] ^= 1;
                moved
            },
        ] {
            assert!(
                !OpenSslPq.verify(&public, b"payload", &broken).unwrap(),
                "a {}-byte signature was not simply refused",
                broken.len()
            );
        }
    }

    /// Key material that is not an ML-DSA key is refused.
    #[test]
    fn a_key_that_is_not_ml_dsa_is_refused() {
        for junk in [&b""[..], b"not a key", &[0x30, 0x82, 0x01, 0x00]] {
            assert!(
                OpenSslPq
                    .sign(&PrivateKey::from_der(junk.to_vec()), b"x")
                    .is_err()
            );
            assert!(
                OpenSslPq
                    .verify(&PublicKey::from_der(junk.to_vec()), b"x", b"sig")
                    .is_err()
            );
        }
    }

    /// The classical signer does not accept a post-quantum key, and this one
    /// does not accept a classical key.
    ///
    /// The two live behind separate traits precisely so a caller cannot reach
    /// for the wrong one; this is the assertion that the separation holds at
    /// run time as well as in the type system.
    #[test]
    fn the_two_signature_paths_do_not_accept_each_others_keys() {
        let (pq_private, pq_public) = OpenSslPq.generate(MlDsaAlg::MlDsa44).unwrap();

        assert!(
            crate::provider::openssl::signer::OpenSslSigner
                .sign(SignAlg::Es256, &pq_private, b"payload")
                .is_err(),
            "the classical signer accepted an ML-DSA key"
        );
        assert!(
            crate::provider::openssl::signer::OpenSslSigner
                .verify(SignAlg::EdDsa, &pq_public, b"payload", b"sig")
                .is_err()
        );
    }

    /// The provider reaches it, like every other capability.
    #[test]
    fn the_provider_exposes_it() {
        let provider =
            crate::provider::openssl::OpenSslProvider::new(&CryptoConfig::default()).unwrap();
        let provider: &dyn CryptoProvider = &provider;

        let (private, public) = provider.pq_signature().generate(MlDsaAlg::MlDsa65).unwrap();
        let signature = provider.pq_signature().sign(&private, b"payload").unwrap();

        assert!(
            provider
                .pq_signature()
                .verify(&public, b"payload", &signature)
                .unwrap()
        );
    }
}
