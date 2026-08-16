//! Reading an Argon2 PHC string, and deciding whether it is still good enough.
//!
//! The string comes from a database, which means it comes from outside: a realm
//! import, a migration from another system, a row somebody edited. So the
//! parser never panics, never indexes a slice, and bounds its own work.

use std::str::FromStr;

use crate::provider::{Argon2Params, CryptoError, Result};

/// Longest string the parser will look at.
///
/// A hostile row of several megabytes would otherwise be re-parsed on every
/// login attempt. Five hundred and twelve bytes is far above the real worst
/// case of a 32-byte salt and a 64-byte hash.
pub const PHC_MAX_LEN: usize = 512;

/// Shortest salt accepted, in bytes (RFC 9106 §3.1 asks for eight, recommends
/// sixteen). A short salt brings a precomputed table back into range.
const MIN_SALT_LEN: usize = 8;

/// The current Argon2 version, 0x13. Version 0x10 still exists in old
/// databases: it verifies, but it should be rehashed.
pub const ARGON2_VERSION_13: u32 = 0x13;

/// The variant the string declares.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Argon2Variant {
    Argon2d,
    Argon2i,
    Argon2id,
}

/// An Argon2 PHC string, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhcArgon2 {
    pub variant: Argon2Variant,
    pub version: u32,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// Salt, still in PHC base64 — standard alphabet, no padding.
    pub salt_b64: String,
    /// Hash, likewise.
    pub hash_b64: String,
}

impl PhcArgon2 {
    /// Read `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
    ///
    /// Every failure returns the same error. A parser that reports *why* a
    /// string was rejected answers questions about a stored credential that
    /// nobody outside should be able to ask.
    pub fn parse(encoded: &str) -> Result<Self> {
        let bad = || CryptoError::InvalidParams;

        if encoded.len() > PHC_MAX_LEN || !encoded.starts_with('$') {
            return Err(bad());
        }

        // Splitting a leading '$' yields an empty first field, which is
        // consumed here. PHC forbids '$' anywhere else, so any later empty
        // field is a malformed string.
        let mut fields = encoded.split('$');
        if fields.next() != Some("") {
            return Err(bad());
        }

        let variant = match fields.next().ok_or_else(bad)? {
            "argon2d" => Argon2Variant::Argon2d,
            "argon2i" => Argon2Variant::Argon2i,
            "argon2id" => Argon2Variant::Argon2id,
            _ => return Err(bad()),
        };

        // The version field is optional: Argon2 1.0 omitted it. Its absence is
        // not a format error, it names an obsolete version — which
        // `below_policy` turns into a rehash.
        let mut next = fields.next().ok_or_else(bad)?;
        let version = match next.strip_prefix("v=") {
            Some(value) => {
                next = fields.next().ok_or_else(bad)?;
                parse_u32(value)?
            }
            None => 0x10,
        };

        // Cost field: `m=<u32>,t=<u32>,p=<u32>`. Each key is required and may
        // appear once — a duplicate is a way to make two implementations read
        // one string differently.
        let (mut m_cost, mut t_cost, mut p_cost) = (None, None, None);
        for pair in next.split(',') {
            let (key, value) = pair.split_once('=').ok_or_else(bad)?;
            let value = parse_u32(value)?;
            let slot = match key {
                "m" => &mut m_cost,
                "t" => &mut t_cost,
                "p" => &mut p_cost,
                // Unknown keys ("keyid", "data") are refused rather than
                // skipped: ignoring a parameter that changes the derivation
                // means reading a different string than the one stored.
                _ => return Err(bad()),
            };
            if slot.is_some() {
                return Err(bad());
            }
            *slot = Some(value);
        }
        let (m_cost, t_cost, p_cost) = (
            m_cost.ok_or_else(bad)?,
            t_cost.ok_or_else(bad)?,
            p_cost.ok_or_else(bad)?,
        );

        // RFC 9106 §3.1: t >= 1, p >= 1, m >= 8p. A degenerate triple makes the
        // derivation nearly free, so it fails rather than verifies cheaply.
        if t_cost == 0 || p_cost == 0 || m_cost < p_cost.saturating_mul(8) {
            return Err(bad());
        }

        let salt_b64 = fields.next().ok_or_else(bad)?;
        let hash_b64 = fields.next().ok_or_else(bad)?;

        // Nothing left over: `$...$salt$hash$extra` is malformed.
        if fields.next().is_some() {
            return Err(bad());
        }

        if !is_phc_b64(salt_b64) || !is_phc_b64(hash_b64) {
            return Err(bad());
        }

        // How many bytes the salt decodes to, without decoding it. Four
        // characters carry three bytes, so the count is `len * 3 / 4` — in that
        // order. Dividing first floors twice and reads an 11-character field,
        // which is exactly the eight-byte minimum, as six bytes.
        if salt_b64.len() * 3 / 4 < MIN_SALT_LEN {
            return Err(bad());
        }

        Ok(Self {
            variant,
            version,
            m_cost,
            t_cost,
            p_cost,
            salt_b64: salt_b64.to_string(),
            hash_b64: hash_b64.to_string(),
        })
    }

    /// Whether this hash sits below `policy` and should be rehashed at the next
    /// successful login.
    ///
    /// Parallelism is not compared. Fewer lanes is the same work, not less of
    /// it, so a lower `p` is not a weaker hash.
    pub fn below_policy(&self, policy: Argon2Params) -> bool {
        self.variant != Argon2Variant::Argon2id
            || self.version < ARGON2_VERSION_13
            || self.m_cost < policy.m_cost
            || self.t_cost < policy.t_cost
    }
}

/// A strict `u32`: ASCII digits only, no sign.
///
/// `str::parse` accepts "+5". A canonical PHC string never carries a sign, and
/// accepting two spellings of one value is how two parsers come to disagree
/// about the same stored credential.
fn parse_u32(text: &str) -> Result<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CryptoError::InvalidParams);
    }

    u32::from_str(text).map_err(|_| CryptoError::InvalidParams)
}

/// The PHC base64 alphabet: standard, and without padding. PHC forbids '=',
/// and accepting it would change how long the field decodes to.
fn is_phc_b64(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Whether a stored Argon2id string is below policy — or cannot be read at all.
///
/// An unreadable string counts as below. If it verified a password despite
/// this parser rejecting it, then the verifier read something here that this
/// parser does not, and that disagreement is settled by rehashing to a form
/// both of them read the same way.
pub fn argon2id_below_policy(encoded: &str, policy: Argon2Params) -> bool {
    match PhcArgon2::parse(encoded) {
        Ok(phc) => phc.below_policy(policy),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::SecretBox;

    use crate::provider::openssl::OpenSslProvider;
    use crate::provider::{CryptoConfig, CryptoProvider};

    /// The reference string from the Argon2 documentation.
    const CANONICAL: &str = "$argon2id$v=19$m=19456,t=2,p=1\
                             $c29tZXNhbHQxMjM0NTY$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

    fn policy() -> Argon2Params {
        Argon2Params {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
            output_len: 32,
        }
    }

    /// Every field of the canonical string comes back as written.
    #[test]
    fn the_canonical_string_reads_field_by_field() {
        let phc = PhcArgon2::parse(CANONICAL).unwrap();

        assert_eq!(phc.variant, Argon2Variant::Argon2id);
        assert_eq!(phc.version, ARGON2_VERSION_13);
        assert_eq!(phc.m_cost, 19456);
        assert_eq!(phc.t_cost, 2);
        assert_eq!(phc.p_cost, 1);
        assert_eq!(phc.salt_b64, "c29tZXNhbHQxMjM0NTY");
        assert_eq!(phc.hash_b64, "RdescudvJCsgt3ub+b+dWRWJTmaaJObG");
    }

    /// What the provider writes, this reads. The two must agree or a freshly
    /// stored credential is judged unreadable and rehashed on sight.
    #[test]
    fn a_string_the_provider_wrote_reads_back() {
        let provider = OpenSslProvider::new(&CryptoConfig::default()).unwrap();
        let password = SecretBox::new(Box::new("correct horse".to_string()));
        let encoded = provider.password().hash(&password, policy()).unwrap();

        let phc = PhcArgon2::parse(&encoded).unwrap();
        assert_eq!(phc.variant, Argon2Variant::Argon2id);
        assert_eq!(phc.version, ARGON2_VERSION_13);
        assert_eq!(phc.m_cost, policy().m_cost);
        assert!(
            !phc.below_policy(policy()),
            "a fresh hash is not below policy"
        );
        assert!(!argon2id_below_policy(&encoded, policy()));
    }

    /// A salt of exactly the minimum is accepted.
    ///
    /// Eight bytes is eleven base64 characters. Computing the decoded length as
    /// `len / 4 * 3` floors twice and reads those eleven characters as six
    /// bytes, rejecting the shortest salt the RFC allows.
    #[test]
    fn a_salt_at_the_minimum_is_accepted() {
        let at_minimum =
            "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2g$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        assert_eq!("YWJjZGVmZ2g".len(), 11, "eleven characters is eight bytes");

        let phc = PhcArgon2::parse(at_minimum).expect("an eight-byte salt is legal");
        assert_eq!(phc.salt_b64, "YWJjZGVmZ2g");

        // Ten characters is seven bytes, which is below the floor.
        let too_short =
            "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZw$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
        assert_eq!("YWJjZGVmZw".len(), 10);
        assert!(
            PhcArgon2::parse(too_short).is_err(),
            "a seven-byte salt passed"
        );
    }

    /// The versionless form is readable, and is exactly what needs rehashing.
    #[test]
    fn the_versionless_form_reads_and_is_below_policy() {
        let old = "$argon2id$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

        let phc = PhcArgon2::parse(old).unwrap();
        assert_eq!(phc.version, 0x10);
        assert!(phc.below_policy(policy()));
    }

    /// What counts as below policy, and what does not.
    #[test]
    fn a_hash_is_below_policy_when_it_is_weaker_or_older() {
        let below = [
            ("less memory", "$argon2id$v=19$m=8192,t=2,p=1"),
            ("fewer passes", "$argon2id$v=19$m=19456,t=1,p=1"),
            ("another variant", "$argon2i$v=19$m=19456,t=2,p=1"),
            ("an older version", "$argon2id$v=16$m=19456,t=2,p=1"),
        ];

        for (what, prefix) in below {
            let encoded = format!("{prefix}$c29tZXNhbHQxMjM0NTY$RdescudvJCsgt3ub+b+dWRWJTmaaJObG");
            assert!(argon2id_below_policy(&encoded, policy()), "{what}");
        }

        // More than the policy asks for is not below it, and neither is fewer
        // lanes: parallelism divides the work, it does not reduce it.
        for (what, prefix) in [
            ("more memory", "$argon2id$v=19$m=65536,t=3,p=1"),
            ("fewer lanes", "$argon2id$v=19$m=19456,t=2,p=1"),
        ] {
            let encoded = format!("{prefix}$c29tZXNhbHQxMjM0NTY$RdescudvJCsgt3ub+b+dWRWJTmaaJObG");
            assert!(!argon2id_below_policy(&encoded, policy()), "{what}");
        }
    }

    /// Malformed strings are refused, one error for all of them.
    #[test]
    fn malformed_strings_are_refused() {
        let cases = [
            ("empty", ""),
            (
                "no leading marker",
                "argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "unknown variant",
                "$argon2z$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            ("no cost field", "$argon2id$v=19$c29tZXNhbHQxMjM0NTY$aGFzaA"),
            (
                "missing t",
                "$argon2id$v=19$m=19456,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "missing m",
                "$argon2id$v=19$t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "duplicate m",
                "$argon2id$v=19$m=19456,m=8,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            // Numeric values, so the only thing wrong with these is the key.
            // With a non-numeric one the pair is refused before the key is
            // looked at, and the case proves nothing.
            (
                "unknown key",
                "$argon2id$v=19$m=19456,t=2,p=1,keyid=5$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "unknown key first",
                "$argon2id$v=19$data=9,m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "zero passes",
                "$argon2id$v=19$m=19456,t=0,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "zero lanes",
                "$argon2id$v=19$m=19456,t=2,p=0$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "memory below 8p",
                "$argon2id$v=19$m=15,t=2,p=2$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "signed cost",
                "$argon2id$v=19$m=+19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "cost overflows",
                "$argon2id$v=19$m=99999999999,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA",
            ),
            (
                "padded salt",
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY=$aGFzaA",
            ),
            ("empty salt", "$argon2id$v=19$m=19456,t=2,p=1$$aGFzaA"),
            (
                "empty hash",
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$",
            ),
            (
                "no hash",
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY",
            ),
            (
                "trailing field",
                "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY$aGFzaA$extra",
            ),
            (
                "bcrypt",
                "$2b$12$c29tZXNhbHQyMmNoYXJhY3Rlcm4abcdefghijklmnopqrstuv",
            ),
        ];

        for (what, case) in cases {
            assert!(
                matches!(PhcArgon2::parse(case), Err(CryptoError::InvalidParams)),
                "{what} was accepted"
            );
            assert!(
                argon2id_below_policy(case, policy()),
                "{what} passed policy"
            );
        }
    }

    /// A string longer than the ceiling is refused before it is walked.
    #[test]
    fn an_oversized_string_is_refused() {
        let huge = format!(
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY${}",
            "A".repeat(PHC_MAX_LEN)
        );

        assert!(huge.len() > PHC_MAX_LEN);
        assert!(PhcArgon2::parse(&huge).is_err());
    }

    /// The parser is total: no truncation and no single-character change makes
    /// it panic.
    ///
    /// This is the property that matters most, because the input is a database
    /// row. A panic on the login path is an outage triggered by one bad record.
    #[test]
    fn no_truncation_or_mutation_makes_the_parser_panic() {
        for end in 0..=CANONICAL.len() {
            let _ = PhcArgon2::parse(&CANONICAL[..end]);
        }

        for position in 0..CANONICAL.len() {
            for &replacement in b"$=,0z+/ " {
                let mut bytes = CANONICAL.as_bytes().to_vec();
                bytes[position] = replacement;
                let mutated = String::from_utf8(bytes).expect("ascii in, ascii out");
                let _ = PhcArgon2::parse(&mutated);
                let _ = argon2id_below_policy(&mutated, policy());
            }
        }
    }
}
