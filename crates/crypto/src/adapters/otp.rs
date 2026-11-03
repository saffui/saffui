use saffui_core::ports::crypto::{CryptoFailure, OneTimeCodes, TotpEnrollmentText};
use saffui_core::secret::Secret;
use secrecy::SecretBox;

use super::SharedProvider;
use crate::otp::totp::{TotpParams, totp_provisioning_uri, totp_verify_step_at};
use crate::provider::HashAlg;

/// How many bytes a shared secret is: the size of the digest it keys.
const SECRET_BYTES: usize = 20;
/// How many steps on each side of the present one a code may be the code
/// of: the time a person takes to type it, and a clock that is a little off.
const WINDOW: u32 = 1;

/// The one-time codes of this crate, behind the port of the core: thirty
/// second steps, six digits and SHA-1, which is what every authenticator
/// application assumes.
pub struct ProviderOneTimeCodes {
    provider: SharedProvider,
}

impl ProviderOneTimeCodes {
    #[must_use]
    pub fn new(provider: SharedProvider) -> Self {
        Self { provider }
    }
}

fn describe_codes() -> TotpParams {
    TotpParams::new(HashAlg::Sha1)
}

fn carry(secret: &Secret) -> SecretBox<Vec<u8>> {
    SecretBox::new(Box::new(secret.expose().to_vec()))
}

/// Reads six digits. Anything else is the code of no step, and is never
/// handed to the comparison.
fn read_code(code: &str) -> Option<u32> {
    (code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| code.parse().ok())
        .flatten()
}

impl OneTimeCodes for ProviderOneTimeCodes {
    fn make_totp_secret(&self) -> Result<Secret, CryptoFailure> {
        let mut secret = vec![0_u8; SECRET_BYTES];
        self.provider
            .rand()
            .fill(&mut secret)
            .map_err(|_| CryptoFailure)?;
        Ok(Secret::new(secret))
    }

    fn find_totp_step(
        &self,
        secret: &Secret,
        code: &str,
        unix_seconds: u64,
    ) -> Result<Option<u64>, CryptoFailure> {
        let Some(code) = read_code(code) else {
            return Ok(None);
        };
        totp_verify_step_at(
            self.provider.hmac(),
            &carry(secret),
            code,
            unix_seconds,
            describe_codes(),
            WINDOW,
        )
        .map_err(|_| CryptoFailure)
    }

    fn write_totp_enrollment(
        &self,
        issuer: &str,
        account: &str,
        secret: &Secret,
    ) -> Result<TotpEnrollmentText, CryptoFailure> {
        let uri = totp_provisioning_uri(&carry(secret), issuer, account, describe_codes())
            .map_err(|_| CryptoFailure)?;
        Ok(TotpEnrollmentText {
            uri,
            typed_secret: data_encoding::BASE32_NOPAD.encode(secret.expose()),
        })
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::OneTimeCodes;
    use saffui_core::secret::Secret;

    use super::ProviderOneTimeCodes;
    use crate::adapters::open_provider;

    /// The secret of the test vectors of RFC 6238, appendix B, for SHA-1.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn open_codes() -> ProviderOneTimeCodes {
        ProviderOneTimeCodes::new(open_provider().expect("a provider"))
    }

    #[test]
    fn the_codes_of_the_rfc_are_found_at_their_time_and_one_step_around_it() {
        let codes = open_codes();
        let secret = Secret::new(RFC_SECRET.to_vec());

        // At 59 s the eight digits of the RFC are 94287082: six are 287082,
        // the code of step 1.
        assert_eq!(codes.find_totp_step(&secret, "287082", 59), Ok(Some(1)));
        assert_eq!(codes.find_totp_step(&secret, "287082", 30), Ok(Some(1)));
        assert_eq!(
            codes.find_totp_step(&secret, "287082", 89),
            Ok(Some(1)),
            "a code typed a little late is still the code of its step"
        );
        assert_eq!(
            codes.find_totp_step(&secret, "287082", 120),
            Ok(None),
            "two steps later it is the code of none"
        );
        // At 1111111109 s the RFC gives 07081804: the leading zero counts.
        assert_eq!(
            codes.find_totp_step(&secret, "081804", 1_111_111_109),
            Ok(Some(37_037_036))
        );
    }

    #[test]
    fn what_is_not_six_digits_is_the_code_of_no_step() {
        let codes = open_codes();
        let secret = Secret::new(RFC_SECRET.to_vec());

        for typed in [
            "",
            "28708",
            "2870822",
            "28708a",
            " 287082",
            "+87082",
            "２８７０８２",
        ] {
            assert_eq!(
                codes.find_totp_step(&secret, typed, 59),
                Ok(None),
                "{typed:?}"
            );
        }
        assert_eq!(
            codes.find_totp_step(&Secret::new(b"another secret of 20".to_vec()), "287082", 59),
            Ok(None)
        );
    }

    #[test]
    fn a_secret_is_twenty_fresh_bytes_and_is_written_for_an_application_to_enroll() {
        let codes = open_codes();

        let secret = codes.make_totp_secret().expect("a secret");
        let other = codes.make_totp_secret().expect("another secret");
        let written = codes
            .write_totp_enrollment("https://id.example.org/realms/acme", "ada", &secret)
            .expect("an enrollment");

        assert_eq!(secret.expose().len(), 20);
        assert_ne!(secret.expose(), other.expose());
        assert_eq!(written.typed_secret.len(), 32, "20 bytes in base32");
        assert!(
            written.uri.starts_with("otpauth://totp/"),
            "{}",
            written.uri
        );
        assert!(
            written
                .uri
                .contains(&format!("secret={}", written.typed_secret)),
            "{}",
            written.uri
        );
        assert!(written.uri.contains("algorithm=SHA1&digits=6&period=30"));
        assert!(written.uri.contains(":ada?"), "{}", written.uri);
    }
}
