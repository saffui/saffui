//! TOTP: time-based one-time passwords (RFC 6238), over [`super::hotp`].

use data_encoding::BASE32_NOPAD;
use secrecy::{ExposeSecret, SecretBox};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::hotp::hotp;
use crate::provider::{CryptoError, HashAlg, HmacProvider, Result};

/// What a TOTP configuration is: how long a step lasts, how wide a code is, and
/// which hash it is built on.
///
/// Grouped rather than passed alongside the secret and the time because the
/// three are numbers a caller can transpose in silence — a period and a window
/// swapped still compile and still produce codes, just not the right ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpParams {
    pub period: u64,
    pub digits: u32,
    pub hash: HashAlg,
}

impl TotpParams {
    /// The common configuration: thirty-second steps, six digits, SHA-1 — what
    /// authenticator apps assume when a URI omits them.
    pub fn new(hash: HashAlg) -> Self {
        Self {
            period: 30,
            digits: 6,
            hash,
        }
    }

    /// A zero period is refused rather than adjusted, for the reason a zero
    /// width is: quietly making it one turns a caller's uninitialised field
    /// into a working configuration that rotates every second.
    ///
    /// The width is left to [`hotp`], which owns that range.
    fn check(&self) -> Result<()> {
        if self.period == 0 {
            return Err(CryptoError::InvalidParams);
        }
        Ok(())
    }
}

/// The code at an absolute Unix time (RFC 6238 §4): the counter is
/// `floor(unix_seconds / period)`.
pub fn totp_at(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    unix_seconds: u64,
    params: TotpParams,
) -> Result<u32> {
    params.check()?;

    hotp(
        hmac,
        secret,
        unix_seconds / params.period,
        params.digits,
        params.hash,
    )
}

/// The code for the current wall-clock time.
pub fn totp_now(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    params: TotpParams,
) -> Result<u32> {
    totp_at(hmac, secret, unix_now(), params)
}

/// Verify `code` at an absolute Unix time, accepting any step within `±window`
/// to absorb clock skew and the time a person spends typing.
pub fn totp_verify_at(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    code: u32,
    unix_seconds: u64,
    params: TotpParams,
    window: u32,
) -> Result<bool> {
    Ok(scan(hmac, secret, code, unix_seconds, params, window)?.is_some())
}

/// Verify `code` against the current wall-clock time.
pub fn totp_verify(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    code: u32,
    params: TotpParams,
    window: u32,
) -> Result<bool> {
    totp_verify_at(hmac, secret, code, unix_now(), params, window)
}

/// Verify `code` and report *which* step matched, so the caller can store it
/// and refuse a replay.
///
/// RFC 6238 §5.2 requires a code accepted within a step to be refused when
/// presented again; without the step there is nothing to compare against, and
/// an intercepted code stays usable for the whole window.
pub fn totp_verify_step_at(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    code: u32,
    unix_seconds: u64,
    params: TotpParams,
    window: u32,
) -> Result<Option<u64>> {
    scan(hmac, secret, code, unix_seconds, params, window)
}

/// [`totp_verify_step_at`] against the current wall-clock time.
pub fn totp_verify_step(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    code: u32,
    params: TotpParams,
    window: u32,
) -> Result<Option<u64>> {
    totp_verify_step_at(hmac, secret, code, unix_now(), params, window)
}

/// Walk the window once and return the matching step.
///
/// Every candidate is computed and none of them short-circuits: returning as
/// soon as a step matches would time the answer, telling anyone who can measure
/// it how far off the accepted code was. The match is accumulated with `subtle`
/// rather than a branch, and the step is moved into place by a conditional
/// select, so the loop does the same work whichever step matches, or none.
fn scan(
    hmac: &dyn HmacProvider,
    secret: &SecretBox<Vec<u8>>,
    code: u32,
    unix_seconds: u64,
    params: TotpParams,
    window: u32,
) -> Result<Option<u64>> {
    params.check()?;

    let center = unix_seconds / params.period;
    let mut hit = Choice::from(0u8);
    let mut step = 0u64;

    for delta in -i64::from(window)..=i64::from(window) {
        // A step before the epoch, or past the end of `u64`, is not a step. The
        // bound depends on the clock and the window, both public.
        let Some(counter) = center.checked_add_signed(delta) else {
            continue;
        };

        let candidate = hotp(hmac, secret, counter, params.digits, params.hash)?;
        let eq = candidate.ct_eq(&code);
        step = u64::conditional_select(&step, &counter, eq);
        hit |= eq;
    }

    Ok(bool::from(hit).then_some(step))
}

/// Render a code with the leading zeros the numeric form drops.
///
/// RFC 6238's own second vector is `07081804`: as a number it is 7081804,
/// seven digits, and no authenticator will match it.
pub fn format_code(code: u32, digits: u32) -> String {
    format!("{code:0width$}", width = digits as usize)
}

/// Build the `otpauth://totp/...` URI an authenticator app enrols from.
///
/// The hash is restricted to the three names apps actually implement. Emitting
/// `SHA3-256` produces a URI that scans, enrols, and then generates codes that
/// never match — a failure that surfaces at the user's next login rather than
/// at enrolment, which is the wrong end.
pub fn totp_provisioning_uri(
    secret: &SecretBox<Vec<u8>>,
    issuer: &str,
    account: &str,
    params: TotpParams,
) -> Result<String> {
    params.check()?;

    // Advertising a width the generator refuses would enrol an account that
    // cannot produce a code this crate accepts.
    if !(6..=8).contains(&params.digits) {
        return Err(CryptoError::InvalidParams);
    }

    let alg = match params.hash {
        HashAlg::Sha1 => "SHA1",
        HashAlg::Sha256 => "SHA256",
        HashAlg::Sha512 => "SHA512",
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };

    let issuer_encoded = percent_encode(issuer);
    let secret_b32 = BASE32_NOPAD.encode(secret.expose_secret());

    Ok(format!(
        "otpauth://totp/{issuer_encoded}:{account}\
         ?secret={secret_b32}&issuer={issuer_encoded}&algorithm={alg}\
         &digits={digits}&period={period}",
        account = percent_encode(account),
        digits = params.digits,
        period = params.period,
    ))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Percent-encoding for a URI component (RFC 3986 §2.3): unreserved characters
/// pass, everything else is escaped.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::provider::openssl::hmac::OpenSslHmac;

    /// RFC 6238 Appendix B seeds each hash with a secret as long as its digest,
    /// cycling "1234567890".
    fn seed(len: usize) -> SecretBox<Vec<u8>> {
        let ascii = b"1234567890";
        SecretBox::new(Box::new(
            (0..len)
                .map(|i| ascii[i % ascii.len()])
                .collect::<Vec<u8>>(),
        ))
    }

    /// Appendix B uses thirty-second steps and eight digits throughout.
    fn params(hash: HashAlg) -> TotpParams {
        TotpParams {
            period: 30,
            digits: 8,
            hash,
        }
    }

    fn code_at(secret: &SecretBox<Vec<u8>>, time: u64) -> u32 {
        totp_at(&OpenSslHmac, secret, time, params(HashAlg::Sha1)).unwrap()
    }

    fn verify(secret: &SecretBox<Vec<u8>>, code: u32, now: u64, window: u32) -> bool {
        totp_verify_at(
            &OpenSslHmac,
            secret,
            code,
            now,
            params(HashAlg::Sha1),
            window,
        )
        .unwrap()
    }

    /// The whole of RFC 6238 Appendix B: six times against three hashes.
    ///
    /// The times are the point. 59 sits in the first step, 1111111109 and
    /// 1111111111 straddle a step boundary two seconds apart, and 20000000000
    /// is past what a 32-bit counter holds — an implementation that truncates
    /// the counter passes the first five and fails the last.
    #[test]
    fn rfc6238_appendix_b() {
        let times = [
            59u64,
            1111111109,
            1111111111,
            1234567890,
            2000000000,
            20000000000,
        ];

        let cases = [
            (
                HashAlg::Sha1,
                20usize,
                [94287082u32, 7081804, 14050471, 89005924, 69279037, 65353130],
            ),
            (
                HashAlg::Sha256,
                32,
                [46119246, 68084774, 67062674, 91819424, 90698825, 77737706],
            ),
            (
                HashAlg::Sha512,
                64,
                [90693936, 25091201, 99943326, 93441116, 38618901, 47863826],
            ),
        ];

        for (hash, len, expected) in cases {
            let secret = seed(len);
            for (time, want) in times.into_iter().zip(expected) {
                assert_eq!(
                    totp_at(&OpenSslHmac, &secret, time, params(hash)).unwrap(),
                    want,
                    "{hash:?} at {time}"
                );
            }
        }
    }

    /// The window accepts exactly the steps it names, on both sides.
    #[test]
    fn the_window_accepts_exactly_its_steps() {
        let secret = seed(20);
        let now = 1111111109u64;

        assert!(
            verify(&secret, code_at(&secret, now), now, 0),
            "the current step must always pass"
        );

        for steps in 1u32..=2 {
            let offset = u64::from(steps) * 30;

            let past = code_at(&secret, now - offset);
            assert!(
                !verify(&secret, past, now, steps - 1),
                "{steps} back leaked"
            );
            assert!(
                verify(&secret, past, now, steps),
                "{steps} back was refused"
            );

            let future = code_at(&secret, now + offset);
            assert!(
                !verify(&secret, future, now, steps - 1),
                "{steps} ahead leaked"
            );
            assert!(
                verify(&secret, future, now, steps),
                "{steps} ahead was refused"
            );
        }
    }

    /// A code belonging to no step in the window is refused however wide it is.
    #[test]
    fn a_code_that_belongs_to_no_step_is_refused() {
        let secret = seed(20);
        let now = 1111111109u64;
        let good = code_at(&secret, now);

        for wrong in [good.wrapping_add(1), good.wrapping_sub(1), 0, 99_999_999] {
            if wrong == good {
                continue;
            }
            assert!(!verify(&secret, wrong, now, 10), "{wrong} was accepted");
        }
    }

    /// The step that matched is reported, which is what a replay check stores.
    #[test]
    fn the_matching_step_is_reported() {
        let secret = seed(20);
        let now = 1111111109u64;

        for offset in [-1i64, 0, 1] {
            let time = now.checked_add_signed(offset * 30).unwrap();
            let step = totp_verify_step_at(
                &OpenSslHmac,
                &secret,
                code_at(&secret, time),
                now,
                params(HashAlg::Sha1),
                1,
            )
            .unwrap();

            assert_eq!(step, Some(time / 30), "offset {offset}");
        }

        assert_eq!(
            totp_verify_step_at(&OpenSslHmac, &secret, 1, now, params(HashAlg::Sha1), 1).unwrap(),
            None
        );
    }

    /// A zero period is refused everywhere it can be passed.
    #[test]
    fn a_zero_period_is_refused() {
        let secret = seed(20);
        let broken = TotpParams {
            period: 0,
            digits: 8,
            hash: HashAlg::Sha1,
        };

        assert!(totp_at(&OpenSslHmac, &secret, 59, broken).is_err());
        assert!(totp_now(&OpenSslHmac, &secret, broken).is_err());
        assert!(totp_verify_at(&OpenSslHmac, &secret, 1, 59, broken, 1).is_err());
        assert!(totp_verify(&OpenSslHmac, &secret, 1, broken, 1).is_err());
        assert!(totp_verify_step_at(&OpenSslHmac, &secret, 1, 59, broken, 1).is_err());
        assert!(totp_verify_step(&OpenSslHmac, &secret, 1, broken, 1).is_err());
        assert!(totp_provisioning_uri(&secret, "i", "a", broken).is_err());
    }

    /// The wall-clock forms agree with the absolute ones.
    ///
    /// The clock can cross a step between the two reads, so the current and the
    /// next step are both accepted — which is exactly why the verifying form
    /// takes a window at all.
    #[test]
    fn the_wall_clock_forms_track_the_absolute_ones() {
        let secret = seed(20);
        let config = params(HashAlg::Sha1);

        let now = totp_now(&OpenSslHmac, &secret, config).unwrap();
        assert!(
            totp_verify(&OpenSslHmac, &secret, now, config, 1).unwrap(),
            "a code from `totp_now` did not verify against the clock"
        );

        let step = totp_verify_step(&OpenSslHmac, &secret, now, config, 1)
            .unwrap()
            .expect("the code came from this clock");
        assert_eq!(
            totp_at(&OpenSslHmac, &secret, step * 30, config).unwrap(),
            now
        );
    }

    /// The numeric form drops leading zeros; the rendered one does not.
    #[test]
    fn a_code_is_rendered_with_its_leading_zeros() {
        let secret = seed(20);

        assert_eq!(code_at(&secret, 1111111109), 7081804);
        assert_eq!(format_code(7081804, 8), "07081804");
        assert_eq!(format_code(0, 6), "000000");
    }

    /// The URI carries what an app needs, with the label and issuer escaped.
    #[test]
    fn the_provisioning_uri_is_escaped_and_complete() {
        let secret = seed(20);
        let uri = totp_provisioning_uri(
            &secret,
            "Acme Co",
            "a b@example.com",
            TotpParams::new(HashAlg::Sha1),
        )
        .unwrap();

        assert!(uri.starts_with("otpauth://totp/Acme%20Co:a%20b%40example.com?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Acme%20Co"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    /// A hash no authenticator implements is refused at enrolment.
    ///
    /// The alternative is a QR code that scans cleanly and produces codes that
    /// never match, discovered at the user's next login.
    #[test]
    fn the_uri_refuses_a_hash_no_app_implements() {
        let secret = seed(20);

        for hash in [
            HashAlg::Sha384,
            HashAlg::Sha3_256,
            HashAlg::Sha3_384,
            HashAlg::Sha3_512,
        ] {
            assert!(
                matches!(
                    totp_provisioning_uri(&secret, "i", "a", TotpParams::new(hash)),
                    Err(CryptoError::UnsupportedAlgorithm)
                ),
                "{hash:?} was advertised"
            );
        }

        for hash in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha512] {
            assert!(totp_provisioning_uri(&secret, "i", "a", TotpParams::new(hash)).is_ok());
        }
    }

    /// The URI cannot advertise a width the generator refuses.
    #[test]
    fn the_uri_refuses_a_width_the_generator_refuses() {
        let secret = seed(20);

        for digits in [0u32, 5, 9, 10] {
            let config = TotpParams {
                period: 30,
                digits,
                hash: HashAlg::Sha1,
            };
            assert!(
                totp_provisioning_uri(&secret, "i", "a", config).is_err(),
                "{digits} digits was advertised"
            );
            assert!(totp_at(&OpenSslHmac, &secret, 59, config).is_err());
        }
    }

    /// The period reaches the counter, so two periods disagree at one time.
    #[test]
    fn the_period_changes_the_code() {
        let secret = seed(20);
        let sixty = TotpParams {
            period: 60,
            digits: 8,
            hash: HashAlg::Sha1,
        };

        assert_ne!(
            code_at(&secret, 1111111109),
            totp_at(&OpenSslHmac, &secret, 1111111109, sixty).unwrap()
        );
    }
}
