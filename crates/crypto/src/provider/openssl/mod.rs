//! The OpenSSL backend.
//!
//! One file per trait the seam declares, so a change to how HMAC is computed
//! cannot reach the code that signs. `digest` is the exception: three of them
//! need the same hash-to-digest mapping, and one copy cannot drift.

pub mod aead;
pub mod digest;
pub mod hashing;
pub mod hmac;
pub mod kdf;
pub mod key_store;
pub mod legacy_digest;
pub mod password;
pub mod rand;
pub mod signer;

use crate::provider::{
    AeadProvider, CryptoConfig, CryptoError, CryptoProvider, DigestProvider, HmacProvider,
    KdfProvider, KeyStoreProvider, LegacyDigestProvider, PasswordProvider, RandProvider, Result,
    SignerProvider,
};

use aead::OpenSslAead;
use hashing::OpenSslDigest;
use hmac::OpenSslHmac;
use kdf::OpenSslKdf;
use key_store::SoftwareKeyStore;
use legacy_digest::OpenSslLegacyDigest;
use password::OpenSslPassword;
use rand::OpenSslRand;
use signer::OpenSslSigner;

/// The backend behind the seam: every sub-provider, assembled once.
///
/// The composition root builds one of these and shares it; nothing else in the
/// workspace needs to name a sub-module again.
pub struct OpenSslProvider {
    fips: bool,
    // The loaded FIPS and base providers, held for the provider's lifetime.
    // Dropping the handles unloads them, which is why they are kept and named.
    _fips_providers: Vec<openssl::provider::Provider>,
    hmac: OpenSslHmac,
    aead: OpenSslAead,
    signer: OpenSslSigner,
    kdf: OpenSslKdf,
    rand: OpenSslRand,
    password: OpenSslPassword,
    key_store: SoftwareKeyStore,
    legacy_digest: OpenSslLegacyDigest,
    digest: OpenSslDigest,
}

impl OpenSslProvider {
    /// Build a provider from configuration.
    ///
    /// With `fips_required` set, OpenSSL's FIPS provider is loaded (with
    /// `base` beside it for the non-cryptographic algorithms) and a failure to
    /// load is fatal. The one outcome this constructor must not have is a
    /// working non-FIPS provider handed to a config that demanded FIPS:
    /// `is_fips_enabled` feeds compliance claims downstream, and nothing there
    /// asks twice.
    pub fn new(config: &CryptoConfig) -> Result<Self> {
        let fips_providers = if config.fips_required {
            match Self::load_fips() {
                Ok(providers) => providers,
                Err(error) => {
                    // A failed explicit load is not free: it has already
                    // switched the process-global context off implicit
                    // activation, so every later fetch in this process would
                    // fail — including a fallback non-FIPS provider built
                    // after catching this error. Restore the default provider
                    // before reporting, and leak the handle deliberately: its
                    // drop would unload again, and process-lifetime is exactly
                    // how long the implicit default would have lived.
                    if let Ok(default) = openssl::provider::Provider::load(None, "default") {
                        std::mem::forget(default);
                    }
                    return Err(error);
                }
            }
        } else {
            Vec::new()
        };

        Ok(Self {
            fips: config.fips_required,
            _fips_providers: fips_providers,
            hmac: OpenSslHmac,
            aead: OpenSslAead,
            signer: OpenSslSigner,
            kdf: OpenSslKdf,
            rand: OpenSslRand,
            password: OpenSslPassword,
            key_store: SoftwareKeyStore::new(),
            legacy_digest: OpenSslLegacyDigest,
            digest: OpenSslDigest,
        })
    }

    fn load_fips() -> Result<Vec<openssl::provider::Provider>> {
        let fips = openssl::provider::Provider::load(None, "fips")
            .map_err(|_| CryptoError::FipsUnavailable)?;
        let base = openssl::provider::Provider::load(None, "base")
            .map_err(|_| CryptoError::FipsUnavailable)?;
        Ok(vec![fips, base])
    }
}

impl CryptoProvider for OpenSslProvider {
    fn name(&self) -> &str {
        "openssl"
    }

    fn version(&self) -> &str {
        "3.x"
    }

    fn is_fips_enabled(&self) -> bool {
        self.fips
    }

    fn hmac(&self) -> &dyn HmacProvider {
        &self.hmac
    }
    fn aead(&self) -> &dyn AeadProvider {
        &self.aead
    }
    fn signer(&self) -> &dyn SignerProvider {
        &self.signer
    }
    fn kdf(&self) -> &dyn KdfProvider {
        &self.kdf
    }
    fn rand(&self) -> &dyn RandProvider {
        &self.rand
    }
    fn password(&self) -> &dyn PasswordProvider {
        &self.password
    }
    fn key_store(&self) -> &dyn KeyStoreProvider {
        &self.key_store
    }
    fn legacy_digest(&self) -> &dyn LegacyDigestProvider {
        &self.legacy_digest
    }
    fn digest(&self) -> &dyn DigestProvider {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::{ExposeSecret, SecretBox};

    use crate::provider::{AeadAlg, HashAlg, HmacAlg};

    /// One operation through every accessor, behind the trait object.
    ///
    /// The slices tested each sub-provider on its own type. This is the only
    /// test that exercises them the way callers will — through `&dyn
    /// CryptoProvider` — so a wiring mistake in an accessor shows here and
    /// nowhere else.
    #[test]
    fn every_accessor_reaches_a_working_provider() {
        let provider = OpenSslProvider::new(&CryptoConfig::default()).unwrap();
        let provider: &dyn CryptoProvider = &provider;

        assert_eq!(provider.name(), "openssl");
        assert!(!provider.is_fips_enabled());

        let key = SecretBox::new(Box::new(vec![0x5a; 32]));
        let tag = provider.hmac().hmac(HmacAlg::Hs256, &key, b"data").unwrap();
        assert!(
            provider
                .hmac()
                .verify(HmacAlg::Hs256, &key, b"data", &tag)
                .unwrap()
        );

        let nonce = [0x2b; 12];
        let sealed = provider
            .aead()
            .encrypt(AeadAlg::A256Gcm, &key, &nonce, b"", b"plain")
            .unwrap();
        assert_eq!(
            provider
                .aead()
                .decrypt(AeadAlg::A256Gcm, &key, &nonce, b"", &sealed)
                .unwrap(),
            b"plain"
        );

        let okm = provider
            .kdf()
            .hkdf(HashAlg::Sha256, &key, None, b"info", 32)
            .unwrap();
        assert_eq!(okm.expose_secret().len(), 32);

        let mut buf = [0u8; 16];
        provider.rand().fill(&mut buf).unwrap();

        assert_eq!(
            provider
                .legacy_digest()
                .digest(crate::provider::LegacyDigest::Sha256, b"")
                .unwrap()
                .len(),
            32
        );

        let password = SecretBox::new(Box::new("secret".to_string()));
        let stored = provider
            .password()
            .hash(&password, crate::provider::Argon2Params::default())
            .unwrap();
        assert!(provider.password().verify(&password, &stored).unwrap());
    }

    /// A config that demands FIPS either gets it or fails with
    /// `FipsUnavailable`. There is no third answer.
    ///
    /// Which branch runs depends on the host's libcrypto, so the test asserts
    /// the dichotomy rather than one outcome. The forbidden third answer is a
    /// provider that works while reporting FIPS it does not have — that is the
    /// silent fallback `is_fips_enabled` exists to preclude, and the reason a
    /// load failure is fatal in `new`.
    #[test]
    fn a_fips_requirement_is_met_or_fatal() {
        let config = CryptoConfig {
            fips_required: true,
        };

        match OpenSslProvider::new(&config) {
            Ok(provider) => assert!(
                provider.is_fips_enabled(),
                "built for FIPS but does not report it"
            ),
            Err(error) => assert!(
                matches!(error, CryptoError::FipsUnavailable),
                "a FIPS-required config must fail with FipsUnavailable, got {error:?}"
            ),
        }
    }

    /// A failed FIPS attempt must not take the rest of the process with it.
    ///
    /// On OpenSSL 3, an explicit provider load switches the global context off
    /// implicit activation even when the load fails. Without the recovery in
    /// `new`, the sequence "require FIPS, catch the error, fall back to a
    /// non-FIPS provider" leaves a process where every fetch fails — the
    /// fallback works on a fresh process and dies on this one, which is the
    /// worst kind of conditional.
    ///
    /// On a host that has the FIPS module the first construction succeeds and
    /// the sequence is trivially fine, so the test is meaningful exactly where
    /// the failure path runs.
    #[test]
    fn a_failed_fips_attempt_leaves_the_process_usable() {
        let fips = OpenSslProvider::new(&CryptoConfig {
            fips_required: true,
        });

        let fallback = OpenSslProvider::new(&CryptoConfig::default())
            .expect("a default provider after a FIPS attempt");

        let key = SecretBox::new(Box::new(vec![0x5a; 32]));
        let tag = fallback
            .hmac()
            .hmac(HmacAlg::Hs256, &key, b"data")
            .expect("crypto still works after a FIPS attempt");
        assert!(
            fallback
                .hmac()
                .verify(HmacAlg::Hs256, &key, b"data", &tag)
                .unwrap()
        );

        drop(fips);
    }
}
