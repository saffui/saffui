use crate::provider::{CryptoError, RandProvider, Result};

pub struct OpenSslRand;

impl RandProvider for OpenSslRand {
    fn fill(&self, buf: &mut [u8]) -> Result<()> {
        // `rand_bytes` draws from the seeded CSPRNG and reports failure rather
        // than returning weak output, which is the property worth preserving:
        // the error is passed on, never swallowed into a partly-filled buffer.
        openssl::rand::rand_bytes(buf).map_err(|_| CryptoError::OperationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a test can honestly assert about a generator is narrow: that it
    /// writes, that it does not repeat itself, and that its output is not
    /// visibly degenerate. None of this measures randomness — a broken
    /// generator can pass all three — so these are smoke tests placed where a
    /// stuck or unseeded one would show, and nowhere else.
    #[test]
    fn a_draw_is_not_left_as_it_was_found() {
        let mut buf = [0u8; 32];
        OpenSslRand.fill(&mut buf).unwrap();

        // Thirty-two zero bytes has probability 2^-256, so this fails only if
        // nothing was written.
        assert_ne!(buf, [0u8; 32]);

        let mut marked = [0xAAu8; 32];
        OpenSslRand.fill(&mut marked).unwrap();
        assert_ne!(marked, [0xAAu8; 32]);
    }

    /// Two draws differ. A generator returning the same block twice is the
    /// failure this catches, and it is the one that matters for nonces.
    #[test]
    fn two_draws_differ() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        OpenSslRand.fill(&mut first).unwrap();
        OpenSslRand.fill(&mut second).unwrap();

        assert_ne!(first, second);
    }

    /// The last byte of the slice is written, at every length.
    ///
    /// A fill that stops short leaves the tail at whatever the caller had
    /// there, which for a freshly allocated buffer is zeros — and a nonce or a
    /// key with a zero tail is the kind of thing that survives review.
    ///
    /// Drawn repeatedly rather than once: a single one-byte draw is legitimately
    /// zero one time in 256, which would make this fail on its own about that
    /// often. Eight draws bring that to one in 2^64, and a fill that never
    /// touches the last byte still fails every time.
    #[test]
    fn the_last_byte_of_the_slice_is_written() {
        for len in [1usize, 7, 16, 31, 64, 4096] {
            let wrote_tail = (0..8).any(|_| {
                let mut buf = vec![0u8; len];
                OpenSslRand.fill(&mut buf).unwrap();
                buf[len - 1] != 0
            });

            assert!(
                wrote_tail,
                "the last byte of a {len}-byte draw was left at zero eight times over"
            );
        }
    }

    /// Over a large draw, essentially every byte value appears.
    ///
    /// A uniform draw of 4096 bytes misses a given value with probability
    /// (255/256)^4096, about 1 in ten million, so 200 distinct values is a
    /// threshold that cannot flake and that a stuck or short-period generator
    /// cannot reach.
    #[test]
    fn a_large_draw_is_not_visibly_degenerate() {
        let mut buf = vec![0u8; 4096];
        OpenSslRand.fill(&mut buf).unwrap();

        let mut seen = [false; 256];
        for byte in &buf {
            seen[*byte as usize] = true;
        }
        let distinct = seen.iter().filter(|s| **s).count();

        assert!(
            distinct > 200,
            "only {distinct} distinct byte values in 4096"
        );
    }

    /// An empty slice is not an error. A caller asking for nothing gets
    /// nothing, rather than a failure it has to special-case.
    #[test]
    fn an_empty_slice_is_accepted() {
        assert!(OpenSslRand.fill(&mut []).is_ok());
    }
}
