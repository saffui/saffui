//! Password storage over Argon2id, with bcrypt kept for reading.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretBox};

use crate::provider::openssl::rand::OpenSslRand;
use crate::provider::{Argon2Params, CryptoError, PasswordProvider, RandProvider, Result};

/// Bounds on the Argon2 cost parameters, applied when minting and when reading.
///
/// On the reading side the parameters come out of a stored PHC string, which
/// arrives from a database and may have been imported from another system.
/// That makes them untrusted input to a memory allocator: a record carrying
/// `m=4194304` makes every login attempt reserve 4 GiB.
///
/// The floor matters as much as the ceiling. A record stored with `m=8,t=1`
/// verifies quite happily, so anyone able to seed a weak record gets a
/// credential cheap enough to forge.
const MAX_M_COST: u32 = 1024 * 1024; // 1 GiB, in KiB
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;
const MIN_M_COST: u32 = 8 * 1024; // 8 MiB, in KiB
const MIN_T_COST: u32 = 1;

/// One window for both directions.
///
/// It has to be one. Enforcing it on verification alone lets a caller mint a
/// hash this crate then refuses — for the right password, at every future
/// login, indistinguishable from a wrong one. Refusing to mint is the safe
/// asymmetry: a rejected hash is a visible error while the password is being
/// set, an unverifiable one is a silent error discovered much later.
fn within_bounds(m_cost: u32, t_cost: u32, p_cost: u32) -> bool {
    (MIN_M_COST..=MAX_M_COST).contains(&m_cost)
        && (MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        && p_cost <= MAX_P_COST
}

pub struct OpenSslPassword;

impl PasswordProvider for OpenSslPassword {
    fn hash(&self, password: &SecretBox<String>, params: Argon2Params) -> Result<String> {
        if !within_bounds(params.m_cost, params.t_cost, params.p_cost) {
            return Err(CryptoError::InvalidParams);
        }

        let configured = Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(params.output_len),
        )
        .map_err(|_| CryptoError::InvalidParams)?;

        // A fresh salt per hash, from the provider's own generator rather than
        // a second one: two sources of randomness is two things to get right.
        let mut salt_bytes = [0u8; 16];
        OpenSslRand.fill(&mut salt_bytes)?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| CryptoError::OperationFailed)?;

        Argon2::new(Algorithm::Argon2id, Version::V0x13, configured)
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| CryptoError::OperationFailed)
    }

    fn verify(&self, password: &SecretBox<String>, encoded: &str) -> Result<bool> {
        let parsed = PasswordHash::new(encoded).map_err(|_| CryptoError::InvalidParams)?;

        // Bounded before any work is done, because the cost in the record is
        // what decides how much work there is.
        let params = Params::try_from(&parsed).map_err(|_| CryptoError::InvalidParams)?;
        if !within_bounds(params.m_cost(), params.t_cost(), params.p_cost()) {
            return Err(CryptoError::InvalidParams);
        }

        // The variant is checked because callers read this method's name as a
        // promise. Left alone it also accepts `$argon2i$` and `$argon2d$`,
        // which trade away side-channel and GPU resistance respectively.
        if parsed.algorithm.as_str() != "argon2id" {
            return Err(CryptoError::InvalidParams);
        }

        Ok(Argon2::default()
            .verify_password(password.expose_secret().as_bytes(), &parsed)
            .is_ok())
    }

    fn verify_bcrypt(&self, password: &SecretBox<String>, hash: &str) -> Result<bool> {
        bcrypt::verify(password.expose_secret(), hash).map_err(|_| CryptoError::InvalidParams)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(text: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(text.to_string()))
    }

    /// A hash verifies against the password it was made from and nothing else.
    #[test]
    fn a_hash_verifies_its_own_password_only() {
        let stored = OpenSslPassword
            .hash(&password("correct horse"), Argon2Params::default())
            .unwrap();

        assert!(
            OpenSslPassword
                .verify(&password("correct horse"), &stored)
                .unwrap()
        );
        assert!(
            !OpenSslPassword
                .verify(&password("correct horsE"), &stored)
                .unwrap()
        );
        assert!(!OpenSslPassword.verify(&password(""), &stored).unwrap());
    }

    /// The salt is drawn per hash, so the same password stored twice gives two
    /// different records that both verify.
    ///
    /// Without it, equal passwords are visible as equal hashes across the whole
    /// table, and one cracked record breaks every account that shared it.
    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let first = OpenSslPassword
            .hash(&password("correct horse"), Argon2Params::default())
            .unwrap();
        let second = OpenSslPassword
            .hash(&password("correct horse"), Argon2Params::default())
            .unwrap();

        assert_ne!(first, second);
        assert!(
            OpenSslPassword
                .verify(&password("correct horse"), &first)
                .unwrap()
        );
        assert!(
            OpenSslPassword
                .verify(&password("correct horse"), &second)
                .unwrap()
        );
    }

    /// The stored form carries its own parameters, so raising the cost later
    /// does not invalidate what is already stored.
    #[test]
    fn a_record_is_read_with_the_cost_it_was_written_with() {
        let cheap = Argon2Params {
            m_cost: MIN_M_COST,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        };
        let stored = OpenSslPassword.hash(&password("secret"), cheap).unwrap();

        assert!(stored.starts_with("$argon2id$"));
        assert!(stored.contains(&format!("m={}", MIN_M_COST)));
        assert!(
            OpenSslPassword
                .verify(&password("secret"), &stored)
                .unwrap()
        );
    }

    /// The window is refused in both directions, and by the same rule.
    ///
    /// Minting outside it is the case worth having: a hash this crate would
    /// then refuse to read is a lockout for the correct password, and nothing
    /// at the login path can tell that from a wrong one.
    #[test]
    fn costs_outside_the_window_are_refused_when_minting() {
        let cases = [
            ("memory below the floor", MIN_M_COST - 1, 2, 1),
            ("memory above the ceiling", MAX_M_COST + 1, 2, 1),
            ("no passes", 19 * 1024, 0, 1),
            ("too many passes", 19 * 1024, MAX_T_COST + 1, 1),
            ("too many lanes", 19 * 1024, 2, MAX_P_COST + 1),
        ];

        for (what, m_cost, t_cost, p_cost) in cases {
            let params = Argon2Params {
                m_cost,
                t_cost,
                p_cost,
                output_len: 32,
            };
            assert!(
                matches!(
                    OpenSslPassword.hash(&password("secret"), params),
                    Err(CryptoError::InvalidParams)
                ),
                "{what} was accepted"
            );
        }
    }

    /// A stored record asking for more than the ceiling is refused before the
    /// memory is reserved. That record is what an attacker seeds to turn every
    /// login attempt into a gigabyte allocation.
    #[test]
    fn a_record_outside_the_window_is_refused_when_reading() {
        let too_much = "$argon2id$v=19$m=4194304,t=2,p=1\
                        $c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        assert!(matches!(
            OpenSslPassword.verify(&password("secret"), too_much),
            Err(CryptoError::InvalidParams)
        ));

        let too_little = "$argon2id$v=19$m=8,t=1,p=1\
                          $c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        assert!(matches!(
            OpenSslPassword.verify(&password("secret"), too_little),
            Err(CryptoError::InvalidParams)
        ));
    }

    /// Only Argon2id is read. The other two variants parse and would verify,
    /// and neither is what this method's name promises.
    #[test]
    fn the_other_argon2_variants_are_refused() {
        for variant in ["argon2i", "argon2d"] {
            let record = format!(
                "${variant}$v=19$m=19456,t=2,p=1\
                 $c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
            );
            assert!(
                matches!(
                    OpenSslPassword.verify(&password("secret"), &record),
                    Err(CryptoError::InvalidParams)
                ),
                "{variant} was accepted"
            );
        }
    }

    /// Something that is not a PHC string is refused rather than treated as a
    /// mismatch, so a corrupt record is distinguishable from a wrong password.
    #[test]
    fn a_record_that_is_not_a_phc_string_is_refused() {
        for record in [
            "",
            "not a hash",
            "$argon2id$",
            "$unknown$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA",
        ] {
            assert!(
                OpenSslPassword.verify(&password("secret"), record).is_err(),
                "{record:?} was read as a hash"
            );
        }
    }

    /// bcrypt is read, never written. The vector is the one from the crate's
    /// own documentation, so this checks interoperation rather than a round
    /// trip with ourselves.
    #[test]
    fn bcrypt_records_are_still_readable() {
        let stored = bcrypt::hash("correct horse", 4).unwrap();

        assert!(
            OpenSslPassword
                .verify_bcrypt(&password("correct horse"), &stored)
                .unwrap()
        );
        assert!(
            !OpenSslPassword
                .verify_bcrypt(&password("wrong horse"), &stored)
                .unwrap()
        );
        assert!(
            OpenSslPassword
                .verify_bcrypt(&password("correct horse"), "not a bcrypt hash")
                .is_err()
        );
    }
}
