use crate::ports::crypto::{CryptoFailure, Digester};
use crate::secret::Secret;

/// A digest that is not one: 32 bytes that depend on every byte of the
/// input, with no claim past that. It lets the heart be tested without a
/// cryptographic library. Nothing it gives protects anything.
#[derive(Clone, Copy, Debug, Default)]
pub struct WeakDigester;

fn mix(seed: u64, data: &[u8]) -> u64 {
    // FNV-1a, then one round of avalanche.
    let mut state = seed ^ 0xcbf2_9ce4_8422_2325;
    for byte in data {
        state = (state ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    state ^= state >> 32;
    state.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

impl Digester for WeakDigester {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut digest = [0_u8; 32];
        for (seed, chunk) in (1_u64..).zip(digest.chunks_mut(8)) {
            chunk.copy_from_slice(&mix(seed, data).to_be_bytes());
        }
        digest
    }

    /// The digest of the length of the key, the key, then the data: two keys
    /// give two tags, and nothing more is claimed.
    fn hmac_sha256(&self, key: &Secret, data: &[u8]) -> Result<[u8; 32], CryptoFailure> {
        let length = u64::try_from(key.expose().len()).map_err(|_| CryptoFailure)?;
        let mut keyed = length.to_be_bytes().to_vec();
        keyed.extend_from_slice(key.expose());
        keyed.extend_from_slice(data);
        Ok(self.sha256(&keyed))
    }

    fn equal_in_constant_time(&self, left: &[u8], right: &[u8]) -> bool {
        left == right
    }
}
