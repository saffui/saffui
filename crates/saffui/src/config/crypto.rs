//! Secrets of the deployment are given by reference: where the value is, not
//! the value. One reference names one place, and a place that cannot be read
//! is fatal: nothing falls back to another one.

use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::secret::Secret;
use zeroize::Zeroizing;

/// Where the root key is: the key every realm's data key is wrapped under.
/// It never reaches the database.
pub(crate) const ROOT_KEY: &str = "SAFFUI_ROOT_KEY";

const ROOT_KEY_BYTES: usize = 32;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RootKeyError {
    #[error("{ROOT_KEY} is required: a reference to the root key, as file:///path or env://NAME")]
    Missing,
    #[error("{ROOT_KEY}: the reference must start with file:// or env://")]
    UnknownScheme,
    #[error("{ROOT_KEY}: {0} is not set")]
    VariableNotSet(Place),
    #[error("{ROOT_KEY}: {0} cannot be read")]
    FileUnreadable(Place),
    #[error("{ROOT_KEY}: {0} is readable by others than its owner")]
    FileExposed(Place),
    #[error("{ROOT_KEY}: the root key must be 32 bytes, written in base64")]
    NotARootKey,
}

/// The place a reference names, told in a message only when it reads as a
/// place: `env://$SECRET`, expanded by a shell, puts the secret itself there.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Place {
    kind: &'static str,
    told: Option<String>,
}

impl Place {
    /// A variable, told when its name is written as names of variables are.
    fn variable(name: &str) -> Self {
        let mut characters = name.chars();
        let reads_as_a_name = characters
            .next()
            .is_some_and(|first| first.is_ascii_uppercase() || first == '_')
            && characters
                .all(|rest| rest.is_ascii_uppercase() || rest.is_ascii_digit() || rest == '_');
        Self {
            kind: "variable",
            told: reads_as_a_name.then(|| name.to_owned()),
        }
    }

    /// A file that exists, told by its path.
    fn found_file(path: &str) -> Self {
        Self {
            kind: "file",
            told: Some(path.to_owned()),
        }
    }

    /// A file that does not exist, never told: `file://$KEY` names none, and
    /// a key in base64 may start with `/`.
    fn missing_file() -> Self {
        Self {
            kind: "file",
            told: None,
        }
    }
}

impl fmt::Display for Place {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.told {
            Some(told) => write!(formatter, "the {} {told}", self.kind),
            None => write!(formatter, "the {} it names", self.kind),
        }
    }
}

/// Why a reference cannot be followed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReferenceFailure {
    UnknownScheme,
    VariableNotSet(Place),
    FileUnreadable(Place),
    FileExposed(Place),
}

/// Follows a reference, `env://NAME` or `file:///path`, to what it names.
/// What it names is wiped when it goes.
pub(crate) fn follow_reference(
    reference: &str,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<Zeroizing<String>, ReferenceFailure> {
    if let Some(name) = reference.strip_prefix("env://") {
        read_variable(name)
            .map(Zeroizing::new)
            .ok_or_else(|| ReferenceFailure::VariableNotSet(Place::variable(name)))
    } else if let Some(path) = reference.strip_prefix("file://") {
        read_private_file(path)
    } else {
        Err(ReferenceFailure::UnknownScheme)
    }
}

/// Resolves the root key from its reference. No message ever repeats the value.
pub(crate) fn resolve_root_key(
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<Secret, RootKeyError> {
    let reference = read_variable(ROOT_KEY).ok_or(RootKeyError::Missing)?;
    let written = follow_reference(&reference, read_variable).map_err(|failure| match failure {
        ReferenceFailure::UnknownScheme => RootKeyError::UnknownScheme,
        ReferenceFailure::VariableNotSet(place) => RootKeyError::VariableNotSet(place),
        ReferenceFailure::FileUnreadable(place) => RootKeyError::FileUnreadable(place),
        ReferenceFailure::FileExposed(place) => RootKeyError::FileExposed(place),
    })?;
    match STANDARD.decode(written.trim()) {
        Ok(key) if key.len() == ROOT_KEY_BYTES => Ok(Secret::new(key)),
        _ => Err(RootKeyError::NotARootKey),
    }
}

fn read_private_file(path: &str) -> Result<Zeroizing<String>, ReferenceFailure> {
    let mode = fs::metadata(path)
        .map_err(|_| ReferenceFailure::FileUnreadable(Place::missing_file()))?
        .permissions()
        .mode();
    // Group and others: a key anyone on the machine can read protects nothing.
    if mode & 0o077 != 0 {
        return Err(ReferenceFailure::FileExposed(Place::found_file(path)));
    }
    fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|_| ReferenceFailure::FileUnreadable(Place::found_file(path)))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::{Place, ROOT_KEY, RootKeyError, resolve_root_key};

    fn read_from(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(known, _)| *known == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn a_key_is_read_from_the_variable_its_reference_names() {
        let key = STANDARD.encode([7_u8; 32]);
        let read = move |name: &str| match name {
            ROOT_KEY => Some("env://THE_KEY".to_owned()),
            "THE_KEY" => Some(format!("{key}\n")),
            _ => None,
        };

        let resolved = resolve_root_key(read).expect("a root key");

        assert_eq!(resolved.expose(), [7_u8; 32]);
    }

    #[test]
    fn a_reference_that_leads_nowhere_is_fatal_and_says_where_it_led() {
        assert_eq!(
            resolve_root_key(read_from(&[])).map(|_| ()),
            Err(RootKeyError::Missing)
        );
        assert_eq!(
            resolve_root_key(read_from(&[(ROOT_KEY, "env://ABSENT")])).map(|_| ()),
            Err(RootKeyError::VariableNotSet(Place::variable("ABSENT")))
        );
        assert_eq!(
            resolve_root_key(read_from(&[(ROOT_KEY, "file:///no/such/file")])).map(|_| ()),
            Err(RootKeyError::FileUnreadable(Place::missing_file()))
        );
        assert_eq!(
            resolve_root_key(read_from(&[(ROOT_KEY, "c2VjcmV0")])).map(|_| ()),
            Err(RootKeyError::UnknownScheme),
            "a value given in place of a reference is refused"
        );
    }

    #[test]
    fn a_value_that_is_not_32_bytes_of_base64_is_refused_without_being_repeated() {
        let refused = resolve_root_key(read_from(&[
            (ROOT_KEY, "env://THE_KEY"),
            ("THE_KEY", "dG9vLXNob3J0LXNlY3JldA=="),
        ]))
        .expect_err("a key of the wrong length");

        assert_eq!(refused, RootKeyError::NotARootKey);
        assert!(!refused.to_string().contains("dG9v"));
    }

    #[test]
    fn a_key_file_others_can_read_is_refused_and_one_its_owner_alone_reads_is_read() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("saffui-root-key-{}", std::process::id()));
        fs::write(&path, format!("{}\n", STANDARD.encode([5_u8; 32]))).expect("a key file");
        let reference = format!("file://{}", path.display());
        let read = |name: &str| (name == ROOT_KEY).then(|| reference.clone());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("a mode");
        let exposed = resolve_root_key(read).map(|_| ());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("a mode");
        let private = resolve_root_key(read).map(|key| key.expose().to_vec());
        let _ = fs::remove_file(&path);

        assert_eq!(
            exposed,
            Err(RootKeyError::FileExposed(Place::found_file(
                &path.display().to_string()
            )))
        );
        assert_eq!(private, Ok(vec![5_u8; 32]));
    }

    #[test]
    fn a_reference_that_holds_a_secret_in_place_of_a_name_is_not_repeated() {
        // What `env://$KEY` and `file://$KEY` become once a shell expanded them,
        // with a key whose base64 starts with `/`, as one key in 64 does.
        let expanded = STANDARD.encode([0xFC_u8; 32]);
        assert!(expanded.starts_with('/'));
        for reference in [format!("env://{expanded}"), format!("file://{expanded}")] {
            let read = |name: &str| (name == ROOT_KEY).then(|| reference.clone());
            let refused = resolve_root_key(read).expect_err("nothing there");
            assert!(!refused.to_string().contains(&expanded), "{refused}");
        }
        assert_eq!(
            resolve_root_key(read_from(&[(ROOT_KEY, "env://ABSENT")]))
                .expect_err("not set")
                .to_string(),
            "SAFFUI_ROOT_KEY: the variable ABSENT is not set"
        );
    }
}
