//! The sealer of a process that holds no root key, such as a command that
//! seals and opens nothing: it refuses every call.

use saffui_core::ports::crypto::{CryptoFailure, SealPlace, Sealer, WrappedDataKey};
use saffui_core::secret::Secret;
use uuid::Uuid;

pub struct RefusingSealer;

impl Sealer for RefusingSealer {
    fn make_data_key(&self, _: Uuid, _: Uuid, _: u32) -> Result<WrappedDataKey, CryptoFailure> {
        Err(CryptoFailure)
    }

    fn seal(
        &self,
        _: &WrappedDataKey,
        _: &SealPlace,
        _: &Secret,
    ) -> Result<Vec<u8>, CryptoFailure> {
        Err(CryptoFailure)
    }

    fn open(&self, _: &WrappedDataKey, _: &SealPlace, _: &[u8]) -> Result<Secret, CryptoFailure> {
        Err(CryptoFailure)
    }

    fn digest_typed_name(&self, _: Uuid, _: Uuid, _: &[u8]) -> Result<Vec<u8>, CryptoFailure> {
        Err(CryptoFailure)
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::{SealPlace, Sealer, WrappedDataKey};
    use saffui_core::secret::Secret;
    use uuid::Uuid;

    use super::RefusingSealer;

    #[test]
    fn a_process_without_a_root_key_makes_seals_opens_and_digests_nothing() {
        let sealer = RefusingSealer;
        let data_key = WrappedDataKey {
            generation: 1,
            wrapped: vec![7; 40],
        };
        let place = SealPlace {
            tenant: Uuid::from_u128(1),
            realm: Uuid::from_u128(2),
            purpose: "signing-key",
            row: Uuid::from_u128(3),
        };

        assert!(sealer.make_data_key(place.tenant, place.realm, 1).is_err());
        assert!(
            sealer
                .seal(&data_key, &place, &Secret::new(vec![1, 2, 3]))
                .is_err()
        );
        assert!(sealer.open(&data_key, &place, &[1, 2, 3]).is_err());
        assert!(
            sealer
                .digest_typed_name(place.tenant, place.realm, b"ada")
                .is_err()
        );
    }
}
