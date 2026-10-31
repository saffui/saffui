use std::sync::atomic::{AtomicU64, Ordering};

use crate::ports::random::{Random, RandomUnavailable};

/// A source that repeats itself from one run to the next and never within
/// one. Nothing it gives is secret: it only exists so that a test can be read.
#[derive(Default)]
pub struct CountingRandom {
    drawn: AtomicU64,
}

impl Random for CountingRandom {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), RandomUnavailable> {
        for chunk in buffer.chunks_mut(8) {
            // SplitMix64: a counter spread over all 64 bits.
            let mut word = self
                .drawn
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            word ^= word >> 31;
            chunk.copy_from_slice(&word.to_be_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
