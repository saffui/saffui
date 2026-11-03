use crate::ports::crypto::Digester;

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

    fn equal_in_constant_time(&self, left: &[u8], right: &[u8]) -> bool {
        left == right
    }
}
