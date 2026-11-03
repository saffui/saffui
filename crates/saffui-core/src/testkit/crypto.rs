//! Doubles of the cryptographic ports. They hide nothing and prove nothing:
//! they keep the shape of the real ones so that the heart can be tested
//! without a cryptographic library.

use uuid::Uuid;

use crate::ports::crypto::{CryptoFailure, SealPlace, Sealer, WrappedDataKey};
use crate::secret::Secret;

/// A sealer that writes the place in clear in front of the value, and opens
/// only where the place matches: a moved value fails as it would for real.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransparentSealer;

fn write_place(data_key: &WrappedDataKey, place: &SealPlace) -> Vec<u8> {
    let mut written = data_key.wrapped.clone();
    written.extend_from_slice(place.tenant.as_bytes());
    written.extend_from_slice(place.realm.as_bytes());
    written.extend_from_slice(place.purpose.as_bytes());
    written.extend_from_slice(place.row.as_bytes());
    written.push(b'|');
    written
}

impl Sealer for TransparentSealer {
    fn make_data_key(
        &self,
        tenant: Uuid,
        realm: Uuid,
        generation: u32,
    ) -> Result<WrappedDataKey, CryptoFailure> {
        let mut wrapped = b"data-key:".to_vec();
        wrapped.extend_from_slice(tenant.as_bytes());
        wrapped.extend_from_slice(realm.as_bytes());
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
        let mut sealed = write_place(data_key, place);
        sealed.extend_from_slice(plaintext.expose());
        Ok(sealed)
    }

    fn open(
        &self,
        data_key: &WrappedDataKey,
        place: &SealPlace,
        sealed: &[u8],
    ) -> Result<Secret, CryptoFailure> {
        sealed
            .strip_prefix(write_place(data_key, place).as_slice())
            .map(|plaintext| Secret::new(plaintext.to_vec()))
            .ok_or(CryptoFailure)
    }
}
