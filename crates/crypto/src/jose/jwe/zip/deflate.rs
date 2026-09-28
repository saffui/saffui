// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::fmt::Display;
use std::io::{self, Read, Write};
use std::ops::Deref;

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

use crate::jose::jwe::JweCompression;

/// Most bytes a payload may inflate to. Whoever produces a JWE chooses its
/// payload, and deflate reaches about a thousand to one, so without a ceiling
/// a few hundred kilobytes of ciphertext ask the recipient for hundreds of
/// megabytes once decrypted.
const MAX_INFLATED_LEN: u64 = 256 * 1024;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DeflateJweCompression {
    /// Compression with the DEFLATE [RFC1951] algorithm
    Def,
}

impl JweCompression for DeflateJweCompression {
    fn name(&self) -> &str {
        match self {
            Self::Def => "DEF",
        }
    }

    fn compress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(message)?;
        let vec = encoder.finish()?;
        Ok(vec)
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        read_at_most(DeflateDecoder::new(data), MAX_INFLATED_LEN)
    }

    fn box_clone(&self) -> Box<dyn JweCompression> {
        Box::new(*self)
    }
}

/// Read `inflated` to its end, or refuse it once it goes past `most` bytes.
///
/// One byte past `most` is read and nothing after it, so a payload that goes
/// beyond is refused before it costs more, and refused whole rather than
/// handed back cut short.
fn read_at_most(inflated: impl Read, most: u64) -> Result<Vec<u8>, io::Error> {
    let mut vec = Vec::new();
    inflated.take(most + 1).read_to_end(&mut vec)?;
    if vec.len() as u64 > most {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "The decompressed payload exceeds {} bytes. This is a possible DoS attack.",
                most
            ),
        ));
    }
    Ok(vec)
}

impl Display for DeflateJweCompression {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for DeflateJweCompression {
    type Target = dyn JweCompression;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::DeflateJweCompression::Def;
    use super::*;

    /// A payload inflates up to the ceiling, and one byte past it is refused.
    ///
    /// Upstream read the inflated stream to its end. The byte past the ceiling
    /// is the case that tells a refusal from a payload cut short: handing back
    /// the first 256 KiB of a longer plaintext would be worse than failing.
    #[test]
    fn a_payload_inflates_up_to_the_ceiling_and_not_past_it() -> Result<(), io::Error> {
        let at = vec![b'a'; MAX_INFLATED_LEN as usize];
        assert_eq!(Def.decompress(&Def.compress(&at)?)?, at);

        let past = vec![b'a'; MAX_INFLATED_LEN as usize + 1];
        let refused = Def
            .decompress(&Def.compress(&past)?)
            .expect_err("a payload past the ceiling inflated");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        Ok(())
    }

    /// A source that never ends, counting what is read from it, and failing
    /// well past what a bounded read would ever ask for.
    struct Endless {
        given: u64,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.given > 1024 * 1024 {
                return Err(io::Error::other("read on past the ceiling"));
            }
            buf.fill(0);
            self.given += buf.len() as u64;
            Ok(buf.len())
        }
    }

    /// Reading stops one byte past the ceiling, however much is left: the
    /// refusal comes before the allocation it guards against, not after it.
    #[test]
    fn reading_stops_one_byte_past_the_ceiling() {
        let mut source = Endless { given: 0 };
        let refused = read_at_most(&mut source, 1024).expect_err("an endless source was read");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        assert_eq!(source.given, 1025);
    }
}
