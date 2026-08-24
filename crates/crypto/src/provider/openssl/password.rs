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
/// Ceiling on the bcrypt cost read out of a stored record.
///
/// `bcrypt::verify` honours the record's cost verbatim, and the format allows
/// up to 31 — a cost-31 record measures around a hundred hours on a developer
/// machine, so one imported or seeded row pins a worker for as long as it is
/// allowed to run. The work doubles per unit, so the ceiling is what bounds a
/// login attempt, not the caller's patience.
///
/// There is deliberately no floor, unlike Argon2 above. This crate never mints
/// bcrypt, so a cheap record is one an older system already issued; refusing it
/// locks that account out without making anything harder for an attacker who
/// could write to the table in the first place.
const MAX_BCRYPT_COST: u32 = 14;

/// The cost is the two digits after the version tag: `$2b$12$<22 salt><31 hash>`.
///
/// Read here rather than left to the bcrypt crate, because the crate's own
/// parse happens inside the call that then spends the work.
fn bcrypt_cost(hash: &str) -> Option<u32> {
    hash.strip_prefix("$2")?
        .strip_prefix(['a', 'b', 'x', 'y'])?
        .strip_prefix('$')?
        .split_at_checked(2)
        .and_then(|(cost, _)| cost.parse().ok())
}

fn within_bounds(m_cost: u32, t_cost: u32, p_cost: u32) -> bool {
    (MIN_M_COST..=MAX_M_COST).contains(&m_cost)
        && (MIN_T_COST..=MAX_T_COST).contains(&t_cost)
        && p_cost <= MAX_P_COST
}

/// The body behind both verifying entry points, differing only in which
/// variants they will read.
///
/// One function so the cost bounds cannot be enforced on one path and forgotten
/// on the other. The legacy path is the one that reads the least trustworthy
/// records, so it is the one that can least afford to skip them.
fn verify_argon2(password: &SecretBox<String>, encoded: &str, accepted: &[&str]) -> Result<bool> {
    let parsed = PasswordHash::new(encoded).map_err(|_| CryptoError::InvalidParams)?;

    // Bounded before any work is done, because the cost in the record is what
    // decides how much work there is.
    let params = Params::try_from(&parsed).map_err(|_| CryptoError::InvalidParams)?;
    if !within_bounds(params.m_cost(), params.t_cost(), params.p_cost()) {
        return Err(CryptoError::InvalidParams);
    }

    if !accepted.contains(&parsed.algorithm.as_str()) {
        return Err(CryptoError::InvalidParams);
    }

    Ok(Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed)
        .is_ok())
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
        // The variant is checked because callers read this method's name as a
        // promise. Left alone it also accepts `$argon2i$` and `$argon2d$`,
        // which trade away side-channel and GPU resistance respectively.
        verify_argon2(password, encoded, &["argon2id"])
    }

    fn verify_legacy_argon2(&self, password: &SecretBox<String>, encoded: &str) -> Result<bool> {
        verify_argon2(password, encoded, &["argon2id", "argon2i", "argon2d"])
    }

    fn verify_bcrypt(&self, password: &SecretBox<String>, hash: &str) -> Result<bool> {
        // Bounded before the call, because the call is the work.
        let cost = bcrypt_cost(hash).ok_or(CryptoError::InvalidParams)?;
        if cost > MAX_BCRYPT_COST {
            return Err(CryptoError::InvalidParams);
        }

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

    /// The legacy path reads the sibling variants, and the ordinary one still
    /// does not.
    ///
    /// A credential imported as argon2i has to verify once or its account can
    /// never move: the rehash needs the plaintext, and the plaintext only
    /// exists during a login that succeeds.
    #[test]
    fn the_legacy_path_reads_the_sibling_variants() {
        // Minted here rather than pasted, so the test cannot pass against a
        // vector that was wrong to begin with.
        let params = Params::new(MIN_M_COST, 2, 1, Some(32)).unwrap();
        let salt = SaltString::encode_b64(&[0x2b; 16]).unwrap();

        for (variant, algorithm) in [
            (Algorithm::Argon2i, "argon2i"),
            (Algorithm::Argon2d, "argon2d"),
        ] {
            let encoded = Argon2::new(variant, Version::V0x13, params.clone())
                .hash_password(b"correct horse", &salt)
                .unwrap()
                .to_string();
            assert!(encoded.starts_with(&format!("${algorithm}$")));

            assert!(
                OpenSslPassword
                    .verify_legacy_argon2(&password("correct horse"), &encoded)
                    .unwrap(),
                "{algorithm} did not verify on the legacy path"
            );
            assert!(
                !OpenSslPassword
                    .verify_legacy_argon2(&password("wrong horse"), &encoded)
                    .unwrap(),
                "{algorithm} accepted the wrong password"
            );
            assert!(
                matches!(
                    OpenSslPassword.verify(&password("correct horse"), &encoded),
                    Err(CryptoError::InvalidParams)
                ),
                "{algorithm} was read by the ordinary path"
            );
        }
    }

    /// The legacy path is bounded exactly like the ordinary one.
    ///
    /// It reads the least trustworthy records in the crate, so it is the one
    /// that can least afford to skip the cost check.
    #[test]
    fn the_legacy_path_bounds_the_cost_too() {
        for record in [
            "$argon2i$v=19$m=4194304,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2d$v=19$m=8,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2id$v=19$m=4194304,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        ] {
            assert!(
                matches!(
                    OpenSslPassword.verify_legacy_argon2(&password("secret"), record),
                    Err(CryptoError::InvalidParams)
                ),
                "{record} was accepted"
            );
        }

        // And nothing outside the Argon2 family gets in through it.
        assert!(
            OpenSslPassword
                .verify_legacy_argon2(&password("secret"), "not a hash")
                .is_err()
        );
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

    /// A record naming a cost beyond the ceiling is refused, and refused
    /// without doing the work.
    ///
    /// The elapsed-time assertion is the point of the test. Returning an error
    /// after grinding through 2^31 rounds would satisfy a plain `is_err`, and
    /// that is exactly the outcome — a pinned worker per attempt — the ceiling
    /// exists to prevent.
    #[test]
    fn a_record_above_the_cost_ceiling_is_refused_without_doing_the_work() {
        // A genuine record, so salt and digest are well-formed; only the two
        // cost digits move.
        let genuine = bcrypt::hash("correct horse", 4).unwrap();
        let body = &genuine["$2b$04$".len()..];

        for cost in [MAX_BCRYPT_COST + 1, 20, 31] {
            let record = format!("$2b${cost:02}${body}");
            let started = std::time::Instant::now();
            let outcome = OpenSslPassword.verify_bcrypt(&password("correct horse"), &record);
            let elapsed = started.elapsed();

            assert!(
                matches!(outcome, Err(CryptoError::InvalidParams)),
                "cost {cost} was accepted"
            );
            assert!(
                elapsed < std::time::Duration::from_millis(100),
                "cost {cost} was refused only after {elapsed:?} of work"
            );
        }
    }

    /// Records at or below the ceiling still read, so bounding the cost did not
    /// lock out the imports this method exists for.
    #[test]
    fn records_within_the_ceiling_still_verify() {
        for cost in [4u32, 6, 10] {
            let record = bcrypt::hash("correct horse", cost).unwrap();
            assert!(
                OpenSslPassword
                    .verify_bcrypt(&password("correct horse"), &record)
                    .unwrap(),
                "cost {cost} did not verify"
            );
        }
    }

    /// Every version tag the format defines is read, and anything else is not.
    #[test]
    fn the_cost_is_read_from_each_version_tag() {
        for version in ["2a", "2b", "2x", "2y"] {
            let record =
                format!("${version}$12$c29tZXNhbHQyMmNoYXJhY3Rlcn.abcdefghijklmnopqrstuvwxyz012");
            assert_eq!(bcrypt_cost(&record), Some(12), "{version} was not read");
        }

        for record in ["", "$2z$12$x", "$2b$$x", "$2b$xx$x", "not a hash"] {
            assert_eq!(bcrypt_cost(record), None, "{record:?} was read as a record");
        }
    }
}
