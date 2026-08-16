//! A key store inside a PKCS#11 token.
//!
//! What this buys over the software store is one property: the private key is
//! created inside the device and never leaves it, so a memory dump of this
//! process yields nothing that can sign.
//!
//! The `cryptoki` calls block. They run inline in the async trait methods, so a
//! caller on an async runtime should reach this store through a blocking pool
//! rather than from a reactor thread.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use secrecy::ExposeSecret;

use crate::provider::openssl::hashing::OpenSslDigest;
use crate::provider::{
    Attestation, CryptoError, DigestProvider, HashAlg, KeyGenSpec, KeyHandle, KeyStoreProvider,
    Pkcs11Config, Result, SignAlg,
};

/// A key store bound to one token slot.
pub struct Pkcs11KeyStore {
    pkcs11: Pkcs11,
    slot: Slot,
    pin: AuthPin,
}

impl Pkcs11KeyStore {
    /// Load the module, initialise the library and resolve the slot.
    pub fn new(config: &Pkcs11Config) -> Result<Self> {
        let pkcs11 = Pkcs11::new(&config.module).map_err(|_| CryptoError::KeyStore)?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|_| CryptoError::KeyStore)?;

        let slot = match config.slot {
            Some(id) => Slot::try_from(id).map_err(|_| CryptoError::InvalidParams)?,
            // The first slot holding a token. Right for a host with one, and
            // the reason the field exists for every other host.
            None => pkcs11
                .get_slots_with_token()
                .map_err(|_| CryptoError::KeyStore)?
                .into_iter()
                .next()
                .ok_or(CryptoError::KeyStore)?,
        };

        Ok(Self {
            pkcs11,
            slot,
            pin: AuthPin::from(config.pin.expose_secret().as_str()),
        })
    }

    /// A read-write session, logged in.
    fn session(&self) -> Result<Session> {
        let session = self
            .pkcs11
            .open_rw_session(self.slot)
            .map_err(|_| CryptoError::KeyStore)?;
        session
            .login(UserType::User, Some(&self.pin))
            .map_err(|_| CryptoError::KeyStore)?;

        Ok(session)
    }

    /// The label inside a handle this store issued.
    ///
    /// A software handle is refused rather than looked up: the two name
    /// different things, and searching for one as the other reports "no such
    /// key" for a key that exists somewhere else.
    fn token_label(handle: &KeyHandle) -> Result<&str> {
        match handle {
            KeyHandle::Token { label } => Ok(label),
            KeyHandle::Software { .. } => Err(CryptoError::KeyStore),
        }
    }

    fn find(session: &Session, class: ObjectClass, label: &str) -> Result<Option<ObjectHandle>> {
        Ok(session
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(|_| CryptoError::KeyStore)?
            .into_iter()
            .next())
    }
}

/// The DER of a named curve OID, which is what `CKA_EC_PARAMS` carries.
///
/// Written out rather than derived: these three are the only curves the seam
/// names, and a wrong OID here would create a key on a different curve than the
/// caller asked for.
fn ec_params(alg: SignAlg) -> Result<Vec<u8>> {
    match alg {
        // 1.2.840.10045.3.1.7
        SignAlg::Es256 => Ok(vec![
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]),
        // 1.3.132.0.34
        SignAlg::Es384 => Ok(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        // 1.3.132.0.35
        SignAlg::Es512 => Ok(vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn pss(hash: MechanismType, salt_len: u64) -> PkcsPssParams {
    PkcsPssParams {
        hash_alg: hash,
        mgf: match hash {
            MechanismType::SHA256 => PkcsMgfType::MGF1_SHA256,
            MechanismType::SHA384 => PkcsMgfType::MGF1_SHA384,
            _ => PkcsMgfType::MGF1_SHA512,
        },
        s_len: salt_len.into(),
    }
}

/// Re-encode a raw `r‖s` ECDSA signature as the DER the rest of this crate
/// speaks.
///
/// The halves are equal and fixed by the curve, so the split is the midpoint —
/// and an odd length is not a signature from any curve, rather than something
/// to round.
fn der_from_raw_ecdsa(raw: &[u8]) -> Result<Vec<u8>> {
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;

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

/// The mechanism that signs under an algorithm, and the digest to apply first.
///
/// ECDSA uses the bare `CKM_ECDSA`, which signs a digest already computed —
/// so the hash is taken here and handed over. The combined hash-and-sign
/// mechanisms would be tidier and are not portable: SoftHSM 2.6 implements the
/// bare one only, and a store that needs the token to hash cannot be moved
/// between tokens.
///
/// RSA keeps its combined mechanisms, where the alternative is assembling a
/// DigestInfo by hand for every digest.
fn sign_mechanism(alg: SignAlg) -> Result<(Mechanism<'static>, Option<HashAlg>)> {
    match alg {
        SignAlg::Es256 => Ok((Mechanism::Ecdsa, Some(HashAlg::Sha256))),
        SignAlg::Es384 => Ok((Mechanism::Ecdsa, Some(HashAlg::Sha384))),
        SignAlg::Es512 => Ok((Mechanism::Ecdsa, Some(HashAlg::Sha512))),
        SignAlg::Rs256 => Ok((Mechanism::Sha256RsaPkcs, None)),
        SignAlg::Rs384 => Ok((Mechanism::Sha384RsaPkcs, None)),
        SignAlg::Rs512 => Ok((Mechanism::Sha512RsaPkcs, None)),

        // RFC 7518 3.5 fixes the salt at the digest length, which is also what
        // the software signer uses. A token asked for a different one produces
        // signatures the rest of this crate will not verify.
        SignAlg::Ps256 => Ok((
            Mechanism::Sha256RsaPkcsPss(pss(MechanismType::SHA256, 32)),
            None,
        )),
        SignAlg::Ps384 => Ok((
            Mechanism::Sha384RsaPkcsPss(pss(MechanismType::SHA384, 48)),
            None,
        )),
        SignAlg::Ps512 => Ok((
            Mechanism::Sha512RsaPkcsPss(pss(MechanismType::SHA512, 64)),
            None,
        )),

        // Edwards curves are a token capability rather than a given, and the
        // seam has no way to ask. Refused rather than attempted.
        SignAlg::EdDsa => Err(CryptoError::UnsupportedAlgorithm),
    }
}

#[async_trait::async_trait]
impl KeyStoreProvider for Pkcs11KeyStore {
    async fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let session = self.session()?;
        let handles = session
            .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
            .map_err(|_| CryptoError::KeyStore)?;

        let mut keys = Vec::with_capacity(handles.len());
        for handle in handles {
            // A key with no readable label cannot be addressed later, so it is
            // skipped rather than listed under a name that would not find it.
            if let Ok(attributes) = session.get_attributes(handle, &[AttributeType::Label])
                && let Some(cryptoki::object::Attribute::Label(label)) = attributes.first()
                && let Ok(label) = String::from_utf8(label.clone())
            {
                keys.push(KeyHandle::Token { label });
            }
        }

        Ok(keys)
    }

    async fn create_key(&self, spec: KeyGenSpec) -> Result<KeyHandle> {
        let session = self.session()?;
        let label = spec.label.as_bytes().to_vec();

        // A label already in use would give two keys one name, and every later
        // lookup would return whichever the token happens to find first.
        if Self::find(&session, ObjectClass::PRIVATE_KEY, &spec.label)?.is_some() {
            return Err(CryptoError::KeyStore);
        }

        let private = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sign(true),
            Attribute::Label(label.clone()),
            // The point of the store. A token free to refuse extraction is a
            // token whose keys cannot be copied out.
            Attribute::Extractable(spec.extractable),
            Attribute::Sensitive(!spec.extractable),
        ];
        let public = |mut extra: Vec<Attribute>| {
            let mut attributes = vec![
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::Label(label.clone()),
            ];
            attributes.append(&mut extra);
            attributes
        };

        let (mechanism, public) = match spec.alg {
            SignAlg::Es256 | SignAlg::Es384 | SignAlg::Es512 => (
                Mechanism::EccKeyPairGen,
                public(vec![Attribute::EcParams(ec_params(spec.alg)?)]),
            ),
            SignAlg::Rs256
            | SignAlg::Rs384
            | SignAlg::Rs512
            | SignAlg::Ps256
            | SignAlg::Ps384
            | SignAlg::Ps512 => (
                Mechanism::RsaPkcsKeyPairGen,
                public(vec![
                    Attribute::ModulusBits(2048.into()),
                    Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                ]),
            ),
            SignAlg::EdDsa => return Err(CryptoError::UnsupportedAlgorithm),
        };

        session
            .generate_key_pair(&mechanism, &public, &private)
            .map_err(|_| CryptoError::KeyStore)?;

        Ok(KeyHandle::Token { label: spec.label })
    }

    async fn delete_key(&self, handle: &KeyHandle) -> Result<()> {
        let label = Self::token_label(handle)?;
        let session = self.session()?;

        // Both halves go, and the private one first: a public key left behind
        // is a verifier that will never match anything, while a private key
        // left behind still signs.
        let private =
            Self::find(&session, ObjectClass::PRIVATE_KEY, label)?.ok_or(CryptoError::KeyStore)?;
        session
            .destroy_object(private)
            .map_err(|_| CryptoError::KeyStore)?;

        if let Some(public) = Self::find(&session, ObjectClass::PUBLIC_KEY, label)? {
            session
                .destroy_object(public)
                .map_err(|_| CryptoError::KeyStore)?;
        }

        Ok(())
    }

    async fn sign_with_key(
        &self,
        handle: &KeyHandle,
        alg: SignAlg,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let label = Self::token_label(handle)?;
        let session = self.session()?;

        let key =
            Self::find(&session, ObjectClass::PRIVATE_KEY, label)?.ok_or(CryptoError::KeyStore)?;

        let (mechanism, digest) = sign_mechanism(alg)?;

        // Hashed here when the mechanism expects a digest rather than a
        // message. Which of the two it is comes from the table above, so the
        // two cannot disagree.
        let signed = match digest {
            Some(hash) => std::borrow::Cow::Owned(OpenSslDigest.hash(hash, data)?),
            None => std::borrow::Cow::Borrowed(data),
        };

        let signature = session
            .sign(&mechanism, key, &signed)
            .map_err(|_| CryptoError::OperationFailed)?;

        // PKCS#11 returns ECDSA as the raw r‖s pair; the software store returns
        // DER, because that is what OpenSSL produces. One trait promising one
        // thing has to mean one encoding, or moving a deployment from software
        // to a token changes the bytes every verifier downstream reads.
        if matches!(alg, SignAlg::Es256 | SignAlg::Es384 | SignAlg::Es512) {
            return der_from_raw_ecdsa(&signature);
        }

        Ok(signature)
    }

    fn supports_attestation(&self) -> bool {
        // Key attestation is a vendor extension, and there is no portable way
        // to ask for one. Saying no is the only answer this store can defend.
        false
    }

    async fn attest(&self, _handle: &KeyHandle) -> Result<Attestation> {
        Err(CryptoError::AttestationUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::SecretBox;

    use cryptoki::object::KeyType;

    use crate::provider::{CryptoConfig, CryptoProvider, PublicKey, SignerProvider};

    /// Where the module and PIN come from.
    ///
    /// A missing variable panics naming what is missing rather than returning
    /// quietly. A test that runs under `--ignored` and passes without reaching
    /// a token proves nothing about the private-key path, which is the one
    /// place a green result must mean something.
    fn config() -> Pkcs11Config {
        let module = std::env::var("SAFFUI_TEST_PKCS11_MODULE").unwrap_or_else(|_| {
            panic!(
                "these tests need a PKCS#11 module: set SAFFUI_TEST_PKCS11_MODULE \
                 (and SAFFUI_TEST_PKCS11_PIN, default 1234)"
            )
        });

        Pkcs11Config {
            module,
            slot: None,
            pin: SecretBox::new(Box::new(
                std::env::var("SAFFUI_TEST_PKCS11_PIN").unwrap_or_else(|_| "1234".into()),
            )),
        }
    }

    fn store() -> Pkcs11KeyStore {
        Pkcs11KeyStore::new(&config()).expect("the token is reachable")
    }

    /// A label nothing else in the suite uses, so tests do not collide on a
    /// token they share.
    fn label(what: &str) -> String {
        format!("saffui-test-{what}")
    }

    fn spec(alg: SignAlg, label: &str) -> KeyGenSpec {
        KeyGenSpec {
            alg,
            label: label.to_string(),
            extractable: false,
        }
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);

        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut context = Context::from_waker(&waker);
        let mut fut = pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut context) {
                return out;
            }
        }
    }

    /// Remove a label from a previous run, so a failure does not poison the
    /// next one.
    fn clear(store: &Pkcs11KeyStore, label: &str) {
        let _ = block_on(store.delete_key(&KeyHandle::Token {
            label: label.to_string(),
        }));
    }

    /// A key is created in the token, signs there, and is gone after deletion.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn a_key_lives_and_signs_inside_the_token() {
        let store = store();
        let label = label("lifecycle");
        clear(&store, &label);

        let handle = block_on(store.create_key(spec(SignAlg::Es256, &label))).unwrap();
        assert_eq!(
            handle,
            KeyHandle::Token {
                label: label.clone()
            }
        );

        assert!(
            block_on(store.list_keys()).unwrap().contains(&handle),
            "the key was created and is not listed"
        );

        let signature = block_on(store.sign_with_key(&handle, SignAlg::Es256, b"payload")).unwrap();
        assert!(!signature.is_empty());

        block_on(store.delete_key(&handle)).unwrap();
        assert!(!block_on(store.list_keys()).unwrap().contains(&handle));
        assert!(block_on(store.sign_with_key(&handle, SignAlg::Es256, b"payload")).is_err());
        assert!(block_on(store.delete_key(&handle)).is_err());
    }

    /// The signature the token produces verifies outside it.
    ///
    /// This is the assertion that matters: a token that signed with the wrong
    /// mechanism, or hashed twice, produces something the rest of the world
    /// rejects — and every test that only looked at the store would pass.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn what_the_token_signs_verifies_against_openssl() {
        let store = store();

        for (alg, name) in [
            (SignAlg::Es256, "es256"),
            (SignAlg::Es384, "es384"),
            (SignAlg::Rs256, "rs256"),
            (SignAlg::Ps256, "ps256"),
        ] {
            let label = label(name);
            clear(&store, &label);

            let handle = block_on(store.create_key(spec(alg, &label))).unwrap();
            let signature = block_on(store.sign_with_key(&handle, alg, b"payload")).unwrap();

            let public = public_key_der(&store, &label);
            assert!(
                crate::provider::openssl::signer::OpenSslSigner
                    .verify(
                        alg,
                        &PublicKey::from_der(public.clone()),
                        b"payload",
                        &signature
                    )
                    .unwrap_or(false),
                "{name} did not verify outside the token"
            );

            // And it verifies nothing else, so the assertion above is about
            // this signature rather than about a verifier that says yes.
            assert!(
                !crate::provider::openssl::signer::OpenSslSigner
                    .verify(
                        alg,
                        &PublicKey::from_der(public),
                        b"other payload",
                        &signature
                    )
                    .unwrap_or(false),
                "{name} verified a message it did not sign"
            );

            clear(&store, &label);
        }
    }

    /// The public half can be read out; the private half cannot.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn the_private_half_does_not_leave() {
        let store = store();
        let label = label("sensitive");
        clear(&store, &label);

        let handle = block_on(store.create_key(spec(SignAlg::Es256, &label))).unwrap();
        let session = store.session().unwrap();
        let private = Pkcs11KeyStore::find(&session, ObjectClass::PRIVATE_KEY, &label)
            .unwrap()
            .expect("the key was created");

        // Read back what create_key asked the token for. Probing whether the
        // value comes out would be indirect: a token may withhold it for its
        // own reasons, and the test would pass without the flags ever being
        // set. These two are the flags, so they are what is asserted.
        let flags = session
            .get_attributes(
                private,
                &[AttributeType::Sensitive, AttributeType::Extractable],
            )
            .expect("the token reports its own flags");

        let mut sensitive = None;
        let mut extractable = None;
        for flag in flags {
            match flag {
                Attribute::Sensitive(value) => sensitive = Some(value),
                Attribute::Extractable(value) => extractable = Some(value),
                _ => {}
            }
        }

        assert_eq!(sensitive, Some(true), "the key is not sensitive");
        assert_eq!(extractable, Some(false), "the key can be extracted");

        // And the value itself does not come out.
        assert!(
            session
                .get_attributes(private, &[AttributeType::Value])
                .is_err_and(|_| true)
                || session
                    .get_attributes(private, &[AttributeType::Value])
                    .is_ok_and(|attributes| attributes.is_empty()),
            "the token handed back the private key"
        );

        clear(&store, &label);
        let _ = handle;
    }

    /// A handle from the software store is refused rather than looked up.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn a_handle_from_another_store_is_refused() {
        let store = store();
        let foreign = KeyHandle::Software {
            id: "not-a-token-label".to_string(),
        };

        assert!(block_on(store.sign_with_key(&foreign, SignAlg::Es256, b"x")).is_err());
        assert!(block_on(store.delete_key(&foreign)).is_err());
    }

    /// One label names one key. A second create under it is refused rather
    /// than adding a twin nothing can tell apart.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn a_label_is_not_reused() {
        let store = store();
        let label = label("duplicate");
        clear(&store, &label);

        let handle = block_on(store.create_key(spec(SignAlg::Es256, &label))).unwrap();
        assert!(block_on(store.create_key(spec(SignAlg::Es256, &label))).is_err());

        block_on(store.delete_key(&handle)).unwrap();
    }

    /// Attestation is declined, and declined consistently.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn attestation_is_declined() {
        let store = store();
        let handle = KeyHandle::Token {
            label: label("any"),
        };

        assert!(!store.supports_attestation());
        assert!(matches!(
            block_on(store.attest(&handle)),
            Err(CryptoError::AttestationUnsupported)
        ));
    }

    /// The provider builds on the token when configured, and on the software
    /// store when not.
    #[test]
    #[ignore = "needs a PKCS#11 token (SAFFUI_TEST_PKCS11_MODULE)"]
    fn the_provider_uses_the_token_only_when_told_to() {
        let label = label("provider");

        let with_token = crate::provider::openssl::OpenSslProvider::new(&CryptoConfig {
            fips_required: false,
            pkcs11: Some(config()),
        })
        .unwrap();
        let with_token: &dyn CryptoProvider = &with_token;

        let handle = block_on(
            with_token
                .key_store()
                .create_key(spec(SignAlg::Es256, &label)),
        )
        .unwrap();
        assert!(matches!(handle, KeyHandle::Token { .. }));
        block_on(with_token.key_store().delete_key(&handle)).unwrap();

        let without =
            crate::provider::openssl::OpenSslProvider::new(&CryptoConfig::default()).unwrap();
        let without: &dyn CryptoProvider = &without;
        let software = block_on(
            without
                .key_store()
                .create_key(spec(SignAlg::Es256, "in-memory")),
        )
        .unwrap();
        assert!(matches!(software, KeyHandle::Software { .. }));
    }

    /// The public key, read off the token for a verification outside it.
    fn public_key_der(store: &Pkcs11KeyStore, label: &str) -> Vec<u8> {
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey, EcPoint};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;

        let session = store.session().unwrap();
        let public = Pkcs11KeyStore::find(&session, ObjectClass::PUBLIC_KEY, label)
            .unwrap()
            .expect("the public half exists");

        let attributes = session
            .get_attributes(public, &[AttributeType::KeyType])
            .unwrap();
        let key_type = match attributes.first() {
            Some(Attribute::KeyType(t)) => *t,
            other => panic!("no key type: {other:?}"),
        };

        if key_type == KeyType::RSA {
            let parts = session
                .get_attributes(
                    public,
                    &[AttributeType::Modulus, AttributeType::PublicExponent],
                )
                .unwrap();
            let (mut modulus, mut exponent) = (Vec::new(), Vec::new());
            for part in parts {
                match part {
                    Attribute::Modulus(value) => modulus = value,
                    Attribute::PublicExponent(value) => exponent = value,
                    _ => {}
                }
            }
            let rsa = Rsa::from_public_components(
                BigNum::from_slice(&modulus).unwrap(),
                BigNum::from_slice(&exponent).unwrap(),
            )
            .unwrap();
            return PKey::from_rsa(rsa).unwrap().public_key_to_der().unwrap();
        }

        let parts = session
            .get_attributes(public, &[AttributeType::EcParams, AttributeType::EcPoint])
            .unwrap();
        let (mut params, mut point) = (Vec::new(), Vec::new());
        for part in parts {
            match part {
                Attribute::EcParams(value) => params = value,
                Attribute::EcPoint(value) => point = value,
                _ => {}
            }
        }

        // CKA_EC_POINT is the point wrapped in a DER OCTET STRING; the group is
        // read from the curve OID in CKA_EC_PARAMS.
        let nid = match params.as_slice() {
            [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Nid::X9_62_PRIME256V1,
            [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] => Nid::SECP384R1,
            other => panic!("unexpected curve: {other:?}"),
        };
        let group = EcGroup::from_curve_name(nid).unwrap();
        let mut context = openssl::bn::BigNumContext::new().unwrap();
        let raw = &point[2..];
        let point = EcPoint::from_bytes(&group, raw, &mut context).unwrap();
        let key = EcKey::from_public_key(&group, &point).unwrap();

        PKey::from_ec_key(key).unwrap().public_key_to_der().unwrap()
    }
}
