use std::sync::RwLock;

use data_encoding::HEXLOWER;
use secrecy::SecretBox;

use crate::password::legacy::{LegacyHash, RehashUrgency};
use crate::provider::{Argon2Params, CryptoProvider, Result};

/// What a login learned: whether the password matched, and what to do about how
/// it was stored.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VerifyPlan {
    pub valid: bool,
    pub rehash: RehashUrgency,
}

/// Verify a password and say what should happen to the stored hash.
///
/// A wrong password plans nothing. Rehashing on a failure is meaningless — the
/// plaintext to rehash is the wrong one — and it would hand anyone who can
/// reach the login a way to overwrite somebody else's credential.
pub fn verify_and_plan(
    provider: &dyn CryptoProvider,
    password: &SecretBox<String>,
    stored: &LegacyHash,
) -> Result<VerifyPlan> {
    plan(stored.verify(provider, password)?, stored.rehash_urgency())
}

/// The same, reading the cost out of an Argon2id string so a hash that has
/// fallen behind the policy is scheduled for an upgrade.
pub fn verify_and_plan_with_policy(
    provider: &dyn CryptoProvider,
    password: &SecretBox<String>,
    stored: &LegacyHash,
    policy: Argon2Params,
) -> Result<VerifyPlan> {
    plan(
        stored.verify(provider, password)?,
        stored.rehash_urgency_for_policy(policy),
    )
}

fn plan(valid: bool, urgency: RehashUrgency) -> Result<VerifyPlan> {
    Ok(VerifyPlan {
        valid,
        rehash: if valid { urgency } else { RehashUrgency::None },
    })
}

/// The decoy, with the cost it was built for.
///
/// Kept with its parameters rather than alone. A decoy built under one cost and
/// reused under another burns the wrong amount of time, and the cost rising is
/// exactly what the rest of this module exists to make routine.
static DECOY: RwLock<Option<(Argon2Params, String)>> = RwLock::new(None);

/// Spend what a real verification would spend, on the path where no credential
/// was found.
///
/// The error a caller returns for an unknown account is already identical to
/// the one for a wrong password. The time is not: an unknown account answers in
/// microseconds while a wrong password pays a full Argon2id derivation, and
/// that gap is a remote account-enumeration oracle. This closes it.
///
/// Returns nothing on purpose. Its predecessor returned the verification
/// result, which is `false` for any input anyone could submit — and an
/// invitation to write `if dummy_verify(..)` around a function whose whole job
/// is to waste time.
///
/// The decoy hashes a fresh random secret, so no submitted password matches it.
/// That matters more than it looks: a decoy anyone could reproduce would let an
/// attacker submit its password and learn from the answer that the account does
/// not exist, which is the same oracle read from the other end.
pub fn burn_verification_time(
    provider: &dyn CryptoProvider,
    password: &SecretBox<String>,
    policy: Argon2Params,
) {
    let Some(decoy) = decoy_for(provider, policy) else {
        // The generator failed. Nothing is cached, because a predictable decoy
        // is worse than an unequalised one, and this call simply does not
        // manage to hide the timing.
        return;
    };

    let _ = provider.password().verify_legacy_argon2(password, &decoy);
}

fn decoy_for(provider: &dyn CryptoProvider, policy: Argon2Params) -> Option<String> {
    if let Ok(cached) = DECOY.read()
        && let Some((params, decoy)) = cached.as_ref()
        && *params == policy
    {
        return Some(decoy.clone());
    }

    let mut filler = [0u8; 32];
    provider.rand().fill(&mut filler).ok()?;
    let filler = SecretBox::new(Box::new(HEXLOWER.encode(&filler)));
    let encoded = provider.password().hash(&filler, policy).ok()?;

    // Two threads racing here both computed a valid decoy; whichever writes
    // last wins and the other is simply dropped.
    if let Ok(mut cached) = DECOY.write() {
        *cached = Some((policy, encoded.clone()));
    }

    Some(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;

    use crate::provider::CryptoConfig;
    use crate::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig::default()).unwrap()
    }

    fn secret(text: &str) -> SecretBox<String> {
        SecretBox::new(Box::new(text.to_string()))
    }

    fn argon2id_at(p: &OpenSslProvider, policy: Argon2Params) -> LegacyHash {
        LegacyHash::Argon2id {
            encoded: p.password().hash(&secret("correct horse"), policy).unwrap(),
        }
    }

    /// A password that matched decides what happens next; one that did not
    /// decides nothing.
    #[test]
    fn only_a_successful_login_plans_anything() {
        let p = provider();
        let weak = LegacyHash::Md5 {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
        };
        let stored = argon2id_at(&p, Argon2Params::default());

        assert_eq!(
            verify_and_plan(&p, &secret("password"), &weak).unwrap(),
            VerifyPlan {
                valid: true,
                rehash: RehashUrgency::Immediate
            }
        );
        assert_eq!(
            verify_and_plan(&p, &secret("correct horse"), &stored).unwrap(),
            VerifyPlan {
                valid: true,
                rehash: RehashUrgency::None
            },
            "a hash already at the target plans nothing"
        );

        // A wrong password against the weakest format there is still plans
        // nothing: rehashing would need the right plaintext, and would let
        // anyone who can reach the login overwrite the credential.
        assert_eq!(
            verify_and_plan(&p, &secret("wrong"), &weak).unwrap(),
            VerifyPlan {
                valid: false,
                rehash: RehashUrgency::None
            }
        );
    }

    /// A hash that has fallen behind the policy is scheduled, and only the
    /// policy-aware form can see it.
    #[test]
    fn a_hash_behind_the_policy_is_scheduled() {
        let p = provider();
        let cheap = Argon2Params {
            m_cost: 8 * 1024,
            ..Argon2Params::default()
        };
        let stored = argon2id_at(&p, cheap);
        let password = secret("correct horse");

        assert_eq!(
            verify_and_plan(&p, &password, &stored).unwrap(),
            VerifyPlan {
                valid: true,
                rehash: RehashUrgency::None
            }
        );
        assert_eq!(
            verify_and_plan_with_policy(&p, &password, &stored, Argon2Params::default()).unwrap(),
            VerifyPlan {
                valid: true,
                rehash: RehashUrgency::Background
            }
        );

        // Still nothing on a wrong password, however far behind the hash is.
        assert_eq!(
            verify_and_plan_with_policy(&p, &secret("wrong"), &stored, Argon2Params::default())
                .unwrap(),
            VerifyPlan {
                valid: false,
                rehash: RehashUrgency::None
            }
        );
    }

    /// The burn costs what a verification costs, and follows the policy when it
    /// changes.
    ///
    /// Both halves in one test because the decoy is process-wide: two tests
    /// racing on it would measure each other. The second half is the one that
    /// matters — a decoy frozen at the first policy it ever saw keeps burning
    /// the old cost after the cost is raised, and the equalisation it exists
    /// for quietly stops working at exactly the moment the system is hardened.
    #[test]
    fn the_burn_matches_a_real_verification_and_follows_the_policy() {
        let p = provider();
        let submitted = secret("whatever a stranger typed");
        let policy = Argon2Params::default();

        let burn = |policy| {
            let started = Instant::now();
            burn_verification_time(&p, &submitted, policy);
            started.elapsed()
        };

        // Warm the decoy, so what follows measures the steady state rather than
        // the one call that also builds it.
        burn(policy);
        let burned = burn(policy);

        let stored = p.password().hash(&secret("real"), policy).unwrap();
        let started = Instant::now();
        let _ = p.password().verify(&secret("wrong"), &stored);
        let real = started.elapsed();

        assert!(
            burned * 4 > real,
            "the burn took {burned:?} against a real verification's {real:?}, \
             which is not the same order of work"
        );

        // The decoy follows the policy. Read from the cached hash rather than
        // timed: a decoy frozen at the old cost is visible in its own
        // parameters, while wall clock on a shared runner is not a measurement
        // of anything this module controls.
        let dearer = Argon2Params {
            m_cost: 128 * 1024,
            ..policy
        };
        assert_eq!(
            m_cost_of(&decoy_for(&p, dearer).expect("a decoy for the raised cost")),
            dearer.m_cost,
            "the decoy was not rebuilt for the raised cost"
        );

        // And back down, so the cache is keyed by the parameters in both
        // directions rather than merely replaced by the last one asked for.
        assert_eq!(
            m_cost_of(&decoy_for(&p, policy).expect("a decoy for the original cost")),
            policy.m_cost,
            "the decoy did not return to the original cost"
        );
    }

    /// The `m=` field of a PHC string.
    fn m_cost_of(encoded: &str) -> u32 {
        encoded
            .split('$')
            .find_map(|segment| {
                segment
                    .split(',')
                    .find_map(|field| field.strip_prefix("m="))
                    .and_then(|value| value.parse().ok())
            })
            .unwrap_or_else(|| panic!("no m= parameter in {encoded}"))
    }
}
