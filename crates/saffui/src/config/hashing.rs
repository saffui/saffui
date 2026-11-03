//! How many passwords a node hashes at once. Each hash takes the memory of
//! one Argon2id run for its whole length: the bound is what keeps a burst of
//! sign-ins from taking the node. A realm holds half of them at most.

use crate::config::serving::{Setting, Unreadable, resolve_setting};

pub(crate) const PASSWORD_HASHERS: Setting<usize> = Setting {
    option: "--password-hashers",
    variable: "SAFFUI_PASSWORD_HASHERS",
    default: 4,
};

/// The most a node runs at once: past it, the memory of the node goes to
/// hashing alone.
const MOST_HASHERS: usize = 64;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {:?} is not a number of hashers from 1 to {MOST_HASHERS}", .0.setting, .0.value)]
pub(crate) struct PasswordHashersError(Unreadable);

/// Reads how many passwords a node hashes at once.
pub(crate) fn resolve_password_hashers(
    option_value: Option<&str>,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<usize, PasswordHashersError> {
    let hashers = resolve_setting(&PASSWORD_HASHERS, option_value, &read_variable)
        .map_err(PasswordHashersError)?;
    if (1..=MOST_HASHERS).contains(&hashers) {
        return Ok(hashers);
    }
    let setting = if option_value.is_some() {
        PASSWORD_HASHERS.option
    } else {
        PASSWORD_HASHERS.variable
    };
    Err(PasswordHashersError(Unreadable {
        setting,
        value: hashers.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::resolve_password_hashers;

    #[test]
    fn a_node_hashes_four_at_once_unless_told_from_one_to_sixty_four() {
        let read = |written: Option<&'static str>| {
            resolve_password_hashers(None, move |name| {
                (name == "SAFFUI_PASSWORD_HASHERS")
                    .then_some(written)
                    .flatten()
                    .map(str::to_owned)
            })
        };

        assert_eq!(read(None), Ok(4));
        assert_eq!(read(Some("16")), Ok(16));
        assert_eq!(resolve_password_hashers(Some("2"), |_| None), Ok(2));
        for refused in ["0", "65", "many", "-1"] {
            let told = read(Some(refused)).expect_err("a refusal").to_string();
            assert!(told.starts_with("SAFFUI_PASSWORD_HASHERS:"), "{told}");
        }
        let told = resolve_password_hashers(Some("0"), |_| None)
            .expect_err("a refusal")
            .to_string();
        assert!(told.starts_with("--password-hashers:"), "{told}");
    }
}
