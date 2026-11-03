use data_encoding::BASE64URL_NOPAD;
use saffui_core::ports::crypto::{CryptoFailure, SealPlace, Sealer, WrappedDataKey};
use saffui_core::secret::Secret;
use secrecy::ExposeSecret;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::SharedProvider;
use crate::envelope::{Envelope, RealmDek, SecretScope};

/// What a wrapped data key is bound to, beside its tenant, its realm and its
/// generation.
const DATA_KEY_PURPOSE: &str = "realm-data-key";

/// The envelope of this crate, behind the sealing port of the core: the root
/// key wraps one data key per realm and generation, and a data key seals the
/// values of its realm, each bound to its place.
pub struct EnvelopeSealer {
    envelope: Envelope,
}

impl EnvelopeSealer {
    /// # Errors
    ///
    /// Fails when the envelope refuses the root key.
    pub fn new(provider: SharedProvider, root_key: &Secret) -> Result<Self, CryptoFailure> {
        // The envelope takes its key as text: the bytes are written in base64url.
        let written = Zeroizing::new(BASE64URL_NOPAD.encode(root_key.expose()));
        let envelope = Envelope::new(provider, &written).map_err(|_| CryptoFailure)?;
        Ok(Self { envelope })
    }

    fn unwrap_data_key(
        &self,
        tenant: Uuid,
        realm: Uuid,
        data_key: &WrappedDataKey,
    ) -> Result<RealmDek, CryptoFailure> {
        let (tenant, realm) = (tenant.to_string(), realm.to_string());
        let generation = data_key.generation.to_string();
        let scope = SecretScope {
            tenant: &tenant,
            realm_id: &realm,
            purpose: DATA_KEY_PURPOSE,
            id: &generation,
        };
        self.envelope
            .unwrap_dek(&scope, data_key.generation, &data_key.wrapped)
            .map_err(|_| CryptoFailure)
    }
}

impl Sealer for EnvelopeSealer {
    fn make_data_key(
        &self,
        tenant: Uuid,
        realm: Uuid,
        generation: u32,
    ) -> Result<WrappedDataKey, CryptoFailure> {
        let (tenant, realm) = (tenant.to_string(), realm.to_string());
        let written_generation = generation.to_string();
        let scope = SecretScope {
            tenant: &tenant,
            realm_id: &realm,
            purpose: DATA_KEY_PURPOSE,
            id: &written_generation,
        };
        let data_key = self
            .envelope
            .generate_dek(generation)
            .map_err(|_| CryptoFailure)?;
        let wrapped = self
            .envelope
            .wrap_dek(&scope, &data_key)
            .map_err(|_| CryptoFailure)?;
        Ok(WrappedDataKey {
            generation,
            wrapped,
        })
    }

    fn seal(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        plaintext: &Secret,
    ) -> Result<Vec<u8>, CryptoFailure> {
        let key = self.unwrap_data_key(place.tenant, place.realm, data_key)?;
        let (tenant, realm, row) = (
            place.tenant.to_string(),
            place.realm.to_string(),
            place.row.to_string(),
        );
        let scope = SecretScope {
            tenant: &tenant,
            realm_id: &realm,
            purpose: place.purpose,
            id: &row,
        };
        self.envelope
            .seal(&key, &scope, plaintext.expose())
            .map_err(|_| CryptoFailure)
    }

    fn open(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        sealed: &[u8],
    ) -> Result<Secret, CryptoFailure> {
        let key = self.unwrap_data_key(place.tenant, place.realm, data_key)?;
        let (tenant, realm, row) = (
            place.tenant.to_string(),
            place.realm.to_string(),
            place.row.to_string(),
        );
        let scope = SecretScope {
            tenant: &tenant,
            realm_id: &realm,
            purpose: place.purpose,
            id: &row,
        };
        let opened = self
            .envelope
            .open(&key, &scope, sealed)
            .map_err(|_| CryptoFailure)?;
        Ok(Secret::new(opened.expose_secret().clone()))
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::{SealPlace, Sealer};
    use saffui_core::secret::Secret;
    use uuid::Uuid;

    use super::EnvelopeSealer;
    use crate::adapters::open_provider;

    fn open_sealer(root_key: u8) -> EnvelopeSealer {
        let provider = open_provider().expect("a provider");
        EnvelopeSealer::new(provider, &Secret::new(vec![root_key; 32])).expect("a sealer")
    }

    fn name_place(tenant: u128, realm: u128, row: u128) -> SealPlace {
        SealPlace {
            tenant: Uuid::from_u128(tenant),
            realm: Uuid::from_u128(realm),
            purpose: "signing-key",
            row: Uuid::from_u128(row),
        }
    }

    #[test]
    fn a_value_opens_where_it_was_sealed_and_is_not_kept_in_the_clear() {
        let sealer = open_sealer(1);
        let place = name_place(1, 2, 3);
        let data_key = sealer
            .make_data_key(place.tenant, place.realm, 1)
            .expect("a data key");
        let secret = Secret::new(b"a private key".to_vec());

        let stored = sealer
            .seal(&data_key, &place, &secret)
            .expect("a sealed value");
        let again = sealer
            .seal(&data_key, &place, &secret)
            .expect("a sealed value");

        assert_ne!(stored, again, "two seals of one value never look alike");
        assert!(!stored.windows(13).any(|window| window == b"a private key"));
        assert_eq!(
            sealer
                .open(&data_key, &place, &stored)
                .expect("the value")
                .expose(),
            b"a private key"
        );
    }

    #[test]
    fn a_value_opens_in_no_other_place_and_under_no_other_key() {
        let sealer = open_sealer(1);
        let place = name_place(1, 2, 3);
        let data_key = sealer
            .make_data_key(place.tenant, place.realm, 1)
            .expect("a data key");
        let stored = sealer
            .seal(&data_key, &place, &Secret::new(b"a private key".to_vec()))
            .expect("a sealed value");

        let other_row = name_place(1, 2, 4);
        let other_purpose = SealPlace {
            purpose: "client-secret",
            ..place
        };
        let other_realm = name_place(1, 9, 3);
        let other_tenant = name_place(9, 2, 3);
        for elsewhere in [other_row, other_purpose, other_realm, other_tenant] {
            assert!(
                sealer.open(&data_key, &elsewhere, &stored).is_err(),
                "{elsewhere:?}"
            );
        }

        let key_of_another_realm = sealer
            .make_data_key(place.tenant, Uuid::from_u128(9), 1)
            .expect("a data key");
        assert!(sealer.open(&key_of_another_realm, &place, &stored).is_err());
        let under_another_root = open_sealer(2);
        assert!(under_another_root.open(&data_key, &place, &stored).is_err());

        let mut altered = stored.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert!(sealer.open(&data_key, &place, &altered).is_err());
    }

    #[test]
    fn a_root_key_too_short_to_be_one_is_refused() {
        let provider = open_provider().expect("a provider");

        assert!(EnvelopeSealer::new(provider, &Secret::new(vec![1; 4])).is_err());
    }
}
