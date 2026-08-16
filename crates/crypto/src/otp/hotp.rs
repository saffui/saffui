//! HOTP: HMAC-based one-time passwords (RFC 4226).

use secrecy::SecretBox;

use crate::provider::{CryptoError, HashAlg, HmacProvider, Result};

/// RFC 4226 §5.3 defines a code of six, seven or eight digits.
const DIGITS: std::ops::RangeInclusive<u32> = 6..=8;

/// Compute an HOTP value: `Truncate(HMAC(secret, counter))` reduced to `digits`
/// decimal digits.
///
/// The HMAC goes through the provider rather than around it, so a deployment
/// that swaps the backend gets one-time passwords from the same place as
/// everything else.
///
/// A `digits` outside the range is refused rather than adjusted. Nothing good
/// follows from guessing: zero digits reduces every code to `0`, and a caller
/// asking for ten is asking for something the spec does not define and `u32`
/// cannot hold.
pub fn hotp(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    counter: u64,
    digits: u32,
    hash: HashAlg,
) -> Result<u32> {
    if !DIGITS.contains(&digits) {
        return Err(CryptoError::InvalidParams);
    }

    let tag = hmac.hmac_with_hash(hash, secret, &counter.to_be_bytes())?;

    // Dynamic truncation (RFC 4226 §5.3): the low nibble of the last byte gives
    // the offset of the four-byte window to read, and the top bit of that window
    // is masked off so the value cannot depend on signed interpretation.
    //
    // The offset reaches 15, so the window needs 19 bytes; every hash the seam
    // names produces at least 20. Read through `get` all the same, because the
    // alternative to an error here is a panic in a shorter one added later.
    let offset = (tag[tag.len() - 1] & 0x0f) as usize;
    let window: [u8; 4] = tag
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(CryptoError::OperationFailed)?;

    let binary = u32::from_be_bytes([window[0] & 0x7f, window[1], window[2], window[3]]);
    Ok(binary % 10u32.pow(digits))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::openssl::hmac::OpenSslHmac;

    /// The shared secret RFC 4226 Appendix D uses: ASCII "12345678901234567890".
    fn secret() -> SecretBox<Vec<u8>> {
        SecretBox::new(Box::new(b"12345678901234567890".to_vec()))
    }

    /// RFC 4226 Appendix D, counters 0 through 9.
    ///
    /// A known answer, and the only thing that makes this function useful: an
    /// implementation that truncates from the wrong offset agrees with itself
    /// and with no authenticator anyone owns.
    #[test]
    fn rfc4226_appendix_d() {
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];

        for (counter, want) in expected.into_iter().enumerate() {
            assert_eq!(
                hotp(&OpenSslHmac, &secret(), counter as u64, 6, HashAlg::Sha1).unwrap(),
                want,
                "counter {counter}"
            );
        }
    }

    /// The code has the width it was asked for, and widening it keeps the
    /// digits already there — truncation takes the low end of one number.
    #[test]
    fn the_code_has_the_requested_width() {
        let six = hotp(&OpenSslHmac, &secret(), 0, 6, HashAlg::Sha1).unwrap();
        let seven = hotp(&OpenSslHmac, &secret(), 0, 7, HashAlg::Sha1).unwrap();
        let eight = hotp(&OpenSslHmac, &secret(), 0, 8, HashAlg::Sha1).unwrap();

        assert!(six < 1_000_000);
        assert!(seven < 10_000_000);
        assert!(eight < 100_000_000);

        assert_eq!(seven % 1_000_000, six);
        assert_eq!(eight % 10_000_000, seven);
    }

    /// A width the spec does not define is refused, not adjusted.
    #[test]
    fn a_width_outside_the_specification_is_refused() {
        for digits in [0, 1, 5, 9, 10, u32::MAX] {
            assert!(
                matches!(
                    hotp(&OpenSslHmac, &secret(), 0, digits, HashAlg::Sha1),
                    Err(CryptoError::InvalidParams)
                ),
                "{digits} digits was accepted"
            );
        }
    }

    /// The counter and the hash both reach the code.
    ///
    /// Without this, dropping the counter from the HMAC input or ignoring the
    /// requested hash would leave every test above passing.
    #[test]
    fn the_counter_and_the_hash_both_change_the_code() {
        let first = hotp(&OpenSslHmac, &secret(), 0, 8, HashAlg::Sha1).unwrap();
        let second = hotp(&OpenSslHmac, &secret(), 1, 8, HashAlg::Sha1).unwrap();
        assert_ne!(first, second);

        let sha256 = hotp(&OpenSslHmac, &secret(), 0, 8, HashAlg::Sha256).unwrap();
        assert_ne!(first, sha256);
    }
}
