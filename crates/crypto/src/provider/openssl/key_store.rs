//! The software key store: private keys held in process memory.
//!
//! This is the store a deployment gets when no hardware one is configured.
//! Keys never leave the process, are addressed by an opaque id, and are used
//! for signing through the same code path as caller-supplied keys.

use std::collections::HashMap;
use std::sync::Mutex;

use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use zeroize::Zeroizing;

use crate::provider::openssl::rand::OpenSslRand;
use crate::provider::openssl::signer::OpenSslSigner;
use crate::provider::{
    Attestation, CryptoError, KeyGenSpec, KeyHandle, KeyStoreProvider, PrivateKey, RandProvider,
    Result, SignAlg, SignerProvider,
};

pub struct SoftwareKeyStore {
    // PKCS#8 DER, the form the seam carries, so signing goes through exactly
    // the code a caller-supplied key would. The buffers are scrubbed when the
    // store drops them.
    keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl SoftwareKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    fn generate_der(alg: SignAlg) -> Result<Zeroizing<Vec<u8>>> {
        let pkey = match alg {
            SignAlg::Rs256
            | SignAlg::Rs384
            | SignAlg::Rs512
            | SignAlg::Ps256
            | SignAlg::Ps384
            | SignAlg::Ps512 => {
                let rsa = Rsa::generate(2048).map_err(|_| CryptoError::OperationFailed)?;
                PKey::from_rsa(rsa).map_err(|_| CryptoError::OperationFailed)?
            }
            SignAlg::Es256 | SignAlg::Es384 | SignAlg::Es512 => {
                let nid = match alg {
                    SignAlg::Es256 => Nid::X9_62_PRIME256V1,
                    SignAlg::Es384 => Nid::SECP384R1,
                    _ => Nid::SECP521R1,
                };
                let group =
                    EcGroup::from_curve_name(nid).map_err(|_| CryptoError::OperationFailed)?;
                let ec = EcKey::generate(&group).map_err(|_| CryptoError::OperationFailed)?;
                PKey::from_ec_key(ec).map_err(|_| CryptoError::OperationFailed)?
            }
            SignAlg::EdDsa => PKey::generate_ed25519().map_err(|_| CryptoError::OperationFailed)?,
        };

        pkey.private_key_to_pkcs8()
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::OperationFailed)
    }
}

impl Default for SoftwareKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl KeyStoreProvider for SoftwareKeyStore {
    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let keys = self.keys.lock().map_err(|_| CryptoError::KeyStore)?;
        Ok(keys
            .keys()
            .map(|id| KeyHandle::Software { id: id.clone() })
            .collect())
    }

    async fn create_key(&self, spec: KeyGenSpec) -> Result<KeyHandle> {
        let der = Self::generate_der(spec.alg)?;

        // The id is random rather than derived from the label: labels are
        // caller-chosen and repeat, and a repeated id would overwrite a key.
        let mut raw = [0u8; 16];
        OpenSslRand.fill(&mut raw)?;
        let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();

        self.keys
            .lock()
            .map_err(|_| CryptoError::KeyStore)?
            .insert(id.clone(), der);
        Ok(KeyHandle::Software { id })
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        let KeyHandle::Software { id } = handle;
        // Deleting a key that is not there is an error, not a no-op. The
        // caller's mental model is "that key is now gone because I removed
        // it"; on a missing id the truthful answer is that nothing was
        // removed, and revocation flows in particular should hear it.
        self.keys
            .lock()
            .map_err(|_| CryptoError::KeyStore)?
            .remove(id)
            .map(|_| ())
            .ok_or(CryptoError::KeyStore)
    }

    async fn sign_with_key(
        &self,
        handle: &KeyHandle,
        alg: SignAlg,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let KeyHandle::Software { id } = handle;
        let der = {
            let keys = self.keys.lock().map_err(|_| CryptoError::KeyStore)?;
            keys.get(id).cloned().ok_or(CryptoError::KeyStore)?
        };
        // Through the signer, not around it: the family check and the PSS
        // parameters apply to a stored key exactly as to a supplied one.
        OpenSslSigner.sign(alg, &PrivateKey::from_der(der.to_vec()), data)
    }

    fn supports_attestation(&self) -> bool {
        false
    }

    async fn attest(&self, _handle: &KeyHandle) -> Result<Attestation> {
        // `supports_attestation` already says no; answering anyway would hand
        // back something that looks like a proof of residency and is not.
        Err(CryptoError::AttestationUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::pkey::PKey;

    use crate::provider::PublicKey;

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        // The store's futures never park, so a poll loop with a no-op waker is
        // enough and avoids pulling a runtime into the crate for one test
        // module.
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    fn spec(alg: SignAlg) -> KeyGenSpec {
        KeyGenSpec {
            alg,
            label: "test-key".to_string(),
            extractable: false,
        }
    }

    /// A key is created, listed, signs, and is gone after deletion.
    ///
    /// The signature is checked against the store's own signing path, so the
    /// stored key is shown to be a working key rather than an entry.
    #[test]
    fn a_key_lives_from_creation_to_deletion() {
        let store = SoftwareKeyStore::new();

        let handle = block_on(store.create_key(spec(SignAlg::Es256))).unwrap();
        assert_eq!(block_on(store.list_keys()).unwrap().len(), 1);

        let sig = block_on(store.sign_with_key(&handle, SignAlg::Es256, b"payload")).unwrap();
        assert!(!sig.is_empty());

        block_on(store.delete_key(&handle)).unwrap();
        assert!(block_on(store.list_keys()).unwrap().is_empty());
        assert!(matches!(
            block_on(store.sign_with_key(&handle, SignAlg::Es256, b"payload")),
            Err(CryptoError::KeyStore)
        ));
    }

    /// Every algorithm the spec can name produces a key that signs under it.
    #[test]
    fn every_algorithm_generates_a_working_key() {
        let store = SoftwareKeyStore::new();
        let algs = [
            SignAlg::Rs256,
            SignAlg::Ps256,
            SignAlg::Es256,
            SignAlg::Es384,
            SignAlg::Es512,
            SignAlg::EdDsa,
        ];

        for alg in algs {
            let handle = block_on(store.create_key(spec(alg))).unwrap();
            let sig = block_on(store.sign_with_key(&handle, alg, b"payload")).unwrap();
            assert!(!sig.is_empty(), "{alg:?}");
        }

        assert_eq!(block_on(store.list_keys()).unwrap().len(), algs.len());
    }

    /// A stored key signs through the same checks as a supplied one, so a
    /// mismatched algorithm is refused rather than obeyed.
    #[test]
    fn a_stored_key_cannot_sign_under_another_family() {
        let store = SoftwareKeyStore::new();
        let handle = block_on(store.create_key(spec(SignAlg::Es256))).unwrap();

        assert!(
            block_on(store.sign_with_key(&handle, SignAlg::Rs256, b"payload")).is_err(),
            "an EC key signed as RSA"
        );
    }

    /// What the store signs, the public half verifies. The private key stays
    /// inside; this is the shape of every real use of the store.
    #[test]
    fn a_signature_from_the_store_verifies_outside_it() {
        let store = SoftwareKeyStore::new();
        let handle = block_on(store.create_key(spec(SignAlg::EdDsa))).unwrap();

        // Reach into the map for the public half only — the test stands in for
        // the export path a real deployment would have.
        let KeyHandle::Software { id } = &handle;
        let public = {
            let keys = store.keys.lock().unwrap();
            let pkey = PKey::private_key_from_pkcs8(keys.get(id).unwrap()).unwrap();
            PublicKey::from_der(pkey.public_key_to_der().unwrap())
        };

        let sig = block_on(store.sign_with_key(&handle, SignAlg::EdDsa, b"payload")).unwrap();
        assert!(
            OpenSslSigner
                .verify(SignAlg::EdDsa, &public, b"payload", &sig)
                .unwrap()
        );
    }

    /// Two keys never share an id, and deleting one leaves the other.
    #[test]
    fn keys_are_independent() {
        let store = SoftwareKeyStore::new();
        let first = block_on(store.create_key(spec(SignAlg::Es256))).unwrap();
        let second = block_on(store.create_key(spec(SignAlg::Es256))).unwrap();

        let KeyHandle::Software { id: first_id } = &first;
        let KeyHandle::Software { id: second_id } = &second;
        assert_ne!(first_id, second_id);

        block_on(store.delete_key(&first)).unwrap();
        assert!(block_on(store.sign_with_key(&second, SignAlg::Es256, b"payload")).is_ok());
    }

    /// Deleting what is not there says so.
    #[test]
    fn deleting_a_missing_key_is_an_error() {
        let store = SoftwareKeyStore::new();
        let ghost = KeyHandle::Software {
            id: "not-a-key".to_string(),
        };
        assert!(matches!(
            block_on(store.delete_key(&ghost)),
            Err(CryptoError::KeyStore)
        ));
    }

    /// No attestation, and no answer that could be mistaken for one.
    #[test]
    fn attestation_is_declined_consistently() {
        let store = SoftwareKeyStore::new();
        let handle = KeyHandle::Software {
            id: "any".to_string(),
        };

        assert!(!store.supports_attestation());
        assert!(matches!(
            block_on(store.attest(&handle)),
            Err(CryptoError::AttestationUnsupported)
        ));
    }
}
