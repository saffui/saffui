//! What one address may do in a realm in the window of the brake. Read from
//! the process alone, never from an option nor from a realm: the bound holds
//! for every realm of the node, and the node pays for each hash it lets in.

use saffui_core::settings::AddressBounds;

pub(crate) const SIGN_IN_ATTEMPTS_PER_ADDRESS: &str = "SAFFUI_SIGN_IN_ATTEMPTS_PER_ADDRESS";
pub(crate) const PENDING_SIGN_INS_PER_ADDRESS: &str = "SAFFUI_PENDING_SIGN_INS_PER_ADDRESS";
pub(crate) const REGISTRATIONS_PER_ADDRESS: &str = "SAFFUI_REGISTRATIONS_PER_ADDRESS";

/// The highest bound: a run of the conformance suite from one address needs
/// a few hundred, and past it the brake no longer holds the hashing back.
const MOST_PER_ADDRESS: u32 = 1_000;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{variable}: {written:?} is not a whole number from 1 to {MOST_PER_ADDRESS}")]
pub(crate) struct AddressBoundError {
    variable: &'static str,
    written: String,
}

/// Reads the three bounds, each its default when its variable is unset.
pub(crate) fn resolve_address_bounds(
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<AddressBounds, AddressBoundError> {
    let defaults = AddressBounds::default();
    let read = |variable: &'static str, default: u32| {
        let Some(written) = read_variable(variable) else {
            return Ok(default);
        };
        // Digits alone: `u32::from_str` also takes a sign.
        written
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| written.parse::<u32>().ok())
            .flatten()
            .filter(|bound| (1..=MOST_PER_ADDRESS).contains(bound))
            .ok_or(AddressBoundError { variable, written })
    };
    Ok(AddressBounds {
        sign_in_attempts: read(SIGN_IN_ATTEMPTS_PER_ADDRESS, defaults.sign_in_attempts)?,
        pending_sign_ins: read(PENDING_SIGN_INS_PER_ADDRESS, defaults.pending_sign_ins)?,
        registrations: read(REGISTRATIONS_PER_ADDRESS, defaults.registrations)?,
    })
}

/// Each bound that is not its default, by the variable that set it, for the
/// journal to say once at start.
pub(crate) fn list_changed_bounds(bounds: AddressBounds) -> Vec<(&'static str, u32, u32)> {
    let defaults = AddressBounds::default();
    [
        (
            SIGN_IN_ATTEMPTS_PER_ADDRESS,
            bounds.sign_in_attempts,
            defaults.sign_in_attempts,
        ),
        (
            PENDING_SIGN_INS_PER_ADDRESS,
            bounds.pending_sign_ins,
            defaults.pending_sign_ins,
        ),
        (
            REGISTRATIONS_PER_ADDRESS,
            bounds.registrations,
            defaults.registrations,
        ),
    ]
    .into_iter()
    .filter(|(_, bound, default)| bound != default)
    .collect()
}

#[cfg(test)]
mod tests {
    use saffui_core::settings::AddressBounds;

    use super::{
        PENDING_SIGN_INS_PER_ADDRESS, REGISTRATIONS_PER_ADDRESS, SIGN_IN_ATTEMPTS_PER_ADDRESS,
        list_changed_bounds, resolve_address_bounds,
    };

    #[test]
    fn each_bound_is_its_default_unless_its_variable_says_a_number_from_1_to_1000() {
        let defaults = AddressBounds::default();
        let read = |named: &'static str, written: &'static str| {
            resolve_address_bounds(move |name| (name == named).then(|| written.to_owned()))
        };

        assert_eq!(
            resolve_address_bounds(|_| None),
            Ok(defaults),
            "no variable set"
        );
        for (variable, raised) in [
            (
                SIGN_IN_ATTEMPTS_PER_ADDRESS,
                AddressBounds {
                    sign_in_attempts: 1_000,
                    ..defaults
                },
            ),
            (
                PENDING_SIGN_INS_PER_ADDRESS,
                AddressBounds {
                    pending_sign_ins: 1_000,
                    ..defaults
                },
            ),
            (
                REGISTRATIONS_PER_ADDRESS,
                AddressBounds {
                    registrations: 1_000,
                    ..defaults
                },
            ),
        ] {
            assert_eq!(read(variable, "1000"), Ok(raised), "{variable}");
            assert_eq!(
                read(variable, "1").map(|bounds| list_changed_bounds(bounds).len()),
                Ok(1),
                "{variable}"
            );
            for refused in ["0", "1001", "many", "-1", "+5", ""] {
                let told = read(variable, refused).expect_err("a refusal").to_string();
                assert!(told.starts_with(&format!("{variable}:")), "{told}");
            }
        }
    }

    #[test]
    fn only_a_bound_that_is_not_its_default_is_listed() {
        let defaults = AddressBounds::default();

        assert!(
            list_changed_bounds(defaults).is_empty(),
            "a node at the defaults"
        );
        assert_eq!(
            list_changed_bounds(AddressBounds {
                pending_sign_ins: 400,
                ..defaults
            }),
            vec![(PENDING_SIGN_INS_PER_ADDRESS, 400, defaults.pending_sign_ins)],
            "the bound raised, with its default"
        );
    }
}
