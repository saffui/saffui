use std::ffi::CString;
use std::ptr;

use foreign_types::ForeignType;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};

use secrecy::SecretBox;

use crate::provider::{
    CryptoError, Encapsulation, MlDsaAlg, MlKemAlg, PqKemProvider, PqSignatureProvider, PrivateKey,
    PublicKey, Result,
};

pub struct OpenSslMlDsa;

pub struct OpenSslMlKem;

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

impl MlKemAlg {
    fn openssl_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
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

impl PqSignatureProvider for OpenSslMlDsa {
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

/// Run `operation` against a context bound to `pkey`, freeing the context
/// whichever way the operation goes.
///
/// The free lives here rather than in each caller so there is one place to get
/// it right instead of three. `EVP_PKEY_CTX_new` is used over
/// `EVP_PKEY_CTX_new_from_pkey` because the safe crate already binds it: a
/// hand-written `extern` declaration whose signature is subtly wrong is
/// undefined behaviour, and the two do the same job for a key that already
/// carries its own provider.
///
/// # Safety
///
/// `pkey` must be a valid, non-null `EVP_PKEY` that outlives the call. The
/// context handed to `operation` is valid only for its duration and must not
/// escape it.
unsafe fn with_key_context<T>(
    pkey: *mut openssl_sys::EVP_PKEY,
    operation: impl FnOnce(*mut openssl_sys::EVP_PKEY_CTX) -> Result<T>,
) -> Result<T> {
    // SAFETY: the caller guarantees `pkey`. A null context means the algorithm
    // is not available in this libcrypto, and there is nothing to free.
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if ctx.is_null() {
            return Err(CryptoError::UnsupportedAlgorithm);
        }

        let outcome = operation(ctx);
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        outcome
    }
}

impl PqKemProvider for OpenSslMlKem {
    fn generate(&self, alg: MlKemAlg) -> Result<(PrivateKey, PublicKey)> {
        let pkey = generate_named(alg.openssl_name())?;

        let private = pkey
            .private_key_to_pkcs8()
            .map_err(|_| CryptoError::OperationFailed)?;
        let public = pkey
            .public_key_to_der()
            .map_err(|_| CryptoError::OperationFailed)?;

        Ok((PrivateKey::from_der(private), PublicKey::from_der(public)))
    }

    fn encapsulate(&self, key: &PublicKey) -> Result<Encapsulation> {
        let pkey: PKey<Public> =
            PKey::public_key_from_der(key.der()).map_err(|_| CryptoError::InvalidKey)?;

        // SAFETY: `pkey` is live for the whole call and the context does not
        // escape the closure. Both output buffers are sized by the first call
        // and only then written by the second, which is the length-then-fill
        // contract these functions document.
        unsafe {
            with_key_context(pkey.as_ptr(), |ctx| {
                if openssl_sys::EVP_PKEY_encapsulate_init(ctx, ptr::null()) <= 0 {
                    return Err(CryptoError::UnsupportedAlgorithm);
                }

                let (mut ciphertext_len, mut secret_len) = (0usize, 0usize);
                if openssl_sys::EVP_PKEY_encapsulate(
                    ctx,
                    ptr::null_mut(),
                    &mut ciphertext_len,
                    ptr::null_mut(),
                    &mut secret_len,
                ) <= 0
                {
                    return Err(CryptoError::OperationFailed);
                }

                let mut ciphertext = vec![0u8; ciphertext_len];
                let mut secret = vec![0u8; secret_len];
                if openssl_sys::EVP_PKEY_encapsulate(
                    ctx,
                    ciphertext.as_mut_ptr(),
                    &mut ciphertext_len,
                    secret.as_mut_ptr(),
                    &mut secret_len,
                ) <= 0
                {
                    return Err(CryptoError::OperationFailed);
                }

                ciphertext.truncate(ciphertext_len);
                secret.truncate(secret_len);

                Ok(Encapsulation {
                    ciphertext,
                    shared_secret: SecretBox::new(Box::new(secret)),
                })
            })
        }
    }

    fn decapsulate(&self, key: &PrivateKey, ciphertext: &[u8]) -> Result<SecretBox<Vec<u8>>> {
        let pkey: PKey<Private> =
            PKey::private_key_from_pkcs8(key.der()).map_err(|_| CryptoError::InvalidKey)?;

        // SAFETY: as above. `ciphertext` is only read, and its length is passed
        // alongside it rather than inferred.
        unsafe {
            with_key_context(pkey.as_ptr(), |ctx| {
                if openssl_sys::EVP_PKEY_decapsulate_init(ctx, ptr::null()) <= 0 {
                    return Err(CryptoError::UnsupportedAlgorithm);
                }

                let mut secret_len = 0usize;
                if openssl_sys::EVP_PKEY_decapsulate(
                    ctx,
                    ptr::null_mut(),
                    &mut secret_len,
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                ) <= 0
                {
                    return Err(CryptoError::OperationFailed);
                }

                let mut secret = vec![0u8; secret_len];
                if openssl_sys::EVP_PKEY_decapsulate(
                    ctx,
                    secret.as_mut_ptr(),
                    &mut secret_len,
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                ) <= 0
                {
                    return Err(CryptoError::OperationFailed);
                }

                secret.truncate(secret_len);
                Ok(SecretBox::new(Box::new(secret)))
            })
        }
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
            let (private, public) = OpenSslMlDsa.generate(alg).unwrap();
            let signature = OpenSslMlDsa.sign(&private, b"the quick brown fox").unwrap();

            assert!(
                OpenSslMlDsa
                    .verify(&public, b"the quick brown fox", &signature)
                    .unwrap(),
                "{alg:?} did not verify its own signature"
            );
            assert!(
                !OpenSslMlDsa
                    .verify(&public, b"the quick brown fix", &signature)
                    .unwrap(),
                "{alg:?} verified another message"
            );

            let (_, other) = OpenSslMlDsa.generate(alg).unwrap();
            assert!(
                !OpenSslMlDsa
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
            let (private, _) = OpenSslMlDsa.generate(alg).unwrap();
            let signature = OpenSslMlDsa.sign(&private, b"payload").unwrap();

            for other in ALGORITHMS {
                if other == alg {
                    continue;
                }
                let (_, public) = OpenSslMlDsa.generate(other).unwrap();
                assert!(
                    !OpenSslMlDsa
                        .verify(&public, b"payload", &signature)
                        .unwrap(),
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
            let (private, _) = OpenSslMlDsa.generate(alg).unwrap();
            assert_eq!(
                OpenSslMlDsa.sign(&private, b"payload").unwrap().len(),
                size,
                "{alg:?}"
            );
        }
    }

    /// Two keys of one parameter set are different keys.
    #[test]
    fn generation_draws_a_fresh_key_each_time() {
        let (first_private, first_public) = OpenSslMlDsa.generate(MlDsaAlg::MlDsa44).unwrap();
        let (second_private, second_public) = OpenSslMlDsa.generate(MlDsaAlg::MlDsa44).unwrap();

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
        let (private, public) = OpenSslMlDsa.generate(MlDsaAlg::MlDsa44).unwrap();
        let signature = OpenSslMlDsa.sign(&private, b"payload").unwrap();

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
                !OpenSslMlDsa.verify(&public, b"payload", &broken).unwrap(),
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
                OpenSslMlDsa
                    .sign(&PrivateKey::from_der(junk.to_vec()), b"x")
                    .is_err()
            );
            assert!(
                OpenSslMlDsa
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
        let (pq_private, pq_public) = OpenSslMlDsa.generate(MlDsaAlg::MlDsa44).unwrap();

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

    use secrecy::ExposeSecret;

    const KEMS: [MlKemAlg; 3] = [MlKemAlg::MlKem512, MlKemAlg::MlKem768, MlKemAlg::MlKem1024];

    /// What one side encapsulates, the other side decapsulates to the same
    /// secret. That is the whole of what a KEM promises.
    #[test]
    fn both_sides_reach_the_same_secret() {
        for alg in KEMS {
            let (private, public) = OpenSslMlKem.generate(alg).unwrap();
            let sent = OpenSslMlKem.encapsulate(&public).unwrap();
            let received = OpenSslMlKem
                .decapsulate(&private, &sent.ciphertext)
                .unwrap();

            assert_eq!(
                received.expose_secret(),
                sent.shared_secret.expose_secret(),
                "{alg:?}"
            );
            assert!(!received.expose_secret().iter().all(|b| *b == 0), "{alg:?}");
        }
    }

    /// Each encapsulation draws a new secret, so one public key serves many
    /// exchanges without any of them sharing a key.
    #[test]
    fn every_encapsulation_draws_a_new_secret() {
        let (private, public) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();

        let first = OpenSslMlKem.encapsulate(&public).unwrap();
        let second = OpenSslMlKem.encapsulate(&public).unwrap();

        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(
            first.shared_secret.expose_secret(),
            second.shared_secret.expose_secret()
        );

        // And each ciphertext still opens to its own secret.
        for sent in [first, second] {
            assert_eq!(
                OpenSslMlKem
                    .decapsulate(&private, &sent.ciphertext)
                    .unwrap()
                    .expose_secret(),
                sent.shared_secret.expose_secret()
            );
        }
    }

    /// The sizes FIPS 203 fixes for each parameter set.
    ///
    /// A KEM round trip agrees with itself under any parameter set, so nothing
    /// above would notice a generate that produced ML-KEM-512 three times. The
    /// ciphertext sizes differ and the shared secret is 32 bytes throughout.
    #[test]
    fn each_parameter_set_has_the_sizes_the_standard_gives_it() {
        for (alg, ciphertext_len) in [
            (MlKemAlg::MlKem512, 768usize),
            (MlKemAlg::MlKem768, 1088),
            (MlKemAlg::MlKem1024, 1568),
        ] {
            let (_, public) = OpenSslMlKem.generate(alg).unwrap();
            let sent = OpenSslMlKem.encapsulate(&public).unwrap();

            assert_eq!(sent.ciphertext.len(), ciphertext_len, "{alg:?}");
            assert_eq!(sent.shared_secret.expose_secret().len(), 32, "{alg:?}");
        }
    }

    /// Another key does not open it, and neither does another parameter set.
    #[test]
    fn another_key_reaches_a_different_secret_or_none() {
        let (_, public) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();
        let sent = OpenSslMlKem.encapsulate(&public).unwrap();

        // ML-KEM decapsulation is designed not to fail on a wrong ciphertext:
        // it returns an unrelated secret rather than an error, which is what
        // stops a decapsulation oracle. So the assertion is that the secret
        // differs, not that the call fails.
        let (other_private, _) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();
        if let Ok(wrong) = OpenSslMlKem.decapsulate(&other_private, &sent.ciphertext) {
            assert_ne!(
                wrong.expose_secret(),
                sent.shared_secret.expose_secret(),
                "another private key recovered the secret"
            );
        }

        // A different parameter set cannot even take the ciphertext.
        let (small, _) = OpenSslMlKem.generate(MlKemAlg::MlKem512).unwrap();
        assert!(OpenSslMlKem.decapsulate(&small, &sent.ciphertext).is_err());
    }

    /// A ciphertext that moved gives a different secret, never the original.
    #[test]
    fn a_ciphertext_that_moved_does_not_recover_the_secret() {
        let (private, public) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();
        let sent = OpenSslMlKem.encapsulate(&public).unwrap();

        for position in [
            0usize,
            1,
            sent.ciphertext.len() / 2,
            sent.ciphertext.len() - 1,
        ] {
            let mut moved = sent.ciphertext.clone();
            moved[position] ^= 1;

            if let Ok(recovered) = OpenSslMlKem.decapsulate(&private, &moved) {
                assert_ne!(
                    recovered.expose_secret(),
                    sent.shared_secret.expose_secret(),
                    "byte {position} could change freely"
                );
            }
        }
    }

    /// A ciphertext of the wrong length is refused rather than indexed into.
    #[test]
    fn a_ciphertext_of_the_wrong_length_is_refused() {
        let (private, public) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();
        let sent = OpenSslMlKem.encapsulate(&public).unwrap();

        for broken in [
            Vec::new(),
            vec![0u8; 8],
            sent.ciphertext[..sent.ciphertext.len() - 1].to_vec(),
            [sent.ciphertext.clone(), vec![0]].concat(),
        ] {
            assert!(
                OpenSslMlKem.decapsulate(&private, &broken).is_err(),
                "a {}-byte ciphertext was accepted",
                broken.len()
            );
        }
    }

    /// The KEM does not take signature keys, nor the signer KEM keys.
    #[test]
    fn the_two_post_quantum_paths_do_not_share_keys() {
        let (kem_private, kem_public) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();
        let (dsa_private, dsa_public) = OpenSslMlDsa.generate(MlDsaAlg::MlDsa44).unwrap();

        assert!(OpenSslMlKem.encapsulate(&dsa_public).is_err());
        assert!(
            OpenSslMlKem
                .decapsulate(&dsa_private, b"ciphertext")
                .is_err()
        );
        assert!(OpenSslMlDsa.sign(&kem_private, b"payload").is_err());
        assert!(
            OpenSslMlDsa
                .verify(&kem_public, b"payload", b"sig")
                .is_err()
        );
    }

    /// The secret does not reach a log through a formatter.
    #[test]
    fn an_encapsulation_does_not_render_its_secret() {
        let (_, public) = OpenSslMlKem.generate(MlKemAlg::MlKem768).unwrap();
        let sent = OpenSslMlKem.encapsulate(&public).unwrap();

        let rendered = format!("{sent:?}");
        let secret: String = sent
            .shared_secret
            .expose_secret()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        assert!(rendered.contains("ciphertext_len"));
        assert!(!rendered.contains(&secret));
    }

    /// The provider reaches the KEM too.
    #[test]
    fn the_provider_exposes_the_kem() {
        let provider =
            crate::provider::openssl::OpenSslProvider::new(&CryptoConfig::default()).unwrap();
        let provider: &dyn CryptoProvider = &provider;

        let (private, public) = provider.pq_kem().generate(MlKemAlg::MlKem768).unwrap();
        let sent = provider.pq_kem().encapsulate(&public).unwrap();

        assert_eq!(
            provider
                .pq_kem()
                .decapsulate(&private, &sent.ciphertext)
                .unwrap()
                .expose_secret(),
            sent.shared_secret.expose_secret()
        );
    }
}
