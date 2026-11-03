//! Secrets of the deployment are given by reference: where the value is, not
//! the value. One reference names one place, and a place that cannot be read
//! is fatal: nothing falls back to another one.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::secret::Secret;

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
    #[error("{ROOT_KEY}: the variable {0} is not set")]
    VariableNotSet(String),
    #[error("{ROOT_KEY}: the file {0} cannot be read")]
    FileUnreadable(String),
    #[error("{ROOT_KEY}: the file {0} is readable by others than its owner")]
    FileExposed(String),
    #[error("{ROOT_KEY}: the root key must be 32 bytes, written in base64")]
    NotARootKey,
}

/// Why a reference cannot be followed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReferenceFailure {
    UnknownScheme,
    VariableNotSet(String),
    FileUnreadable(String),
    FileExposed(String),
}

/// Follows a reference, `env://NAME` or `file:///path`, to what it names.
pub(crate) fn follow_reference(
    reference: &str,
    read_variable: impl Fn(&str) -> Option<String>,
) -> Result<String, ReferenceFailure> {
    if let Some(name) = reference.strip_prefix("env://") {
        read_variable(name).ok_or_else(|| ReferenceFailure::VariableNotSet(name.to_owned()))
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
        ReferenceFailure::VariableNotSet(name) => RootKeyError::VariableNotSet(name),
        ReferenceFailure::FileUnreadable(path) => RootKeyError::FileUnreadable(path),
        ReferenceFailure::FileExposed(path) => RootKeyError::FileExposed(path),
    })?;
    match STANDARD.decode(written.trim()) {
        Ok(key) if key.len() == ROOT_KEY_BYTES => Ok(Secret::new(key)),
        _ => Err(RootKeyError::NotARootKey),
    }
}

fn read_private_file(path: &str) -> Result<String, ReferenceFailure> {
    let unreadable = || ReferenceFailure::FileUnreadable(path.to_owned());
    let mode = fs::metadata(path)
        .map_err(|_| unreadable())?
        .permissions()
        .mode();
    // Group and others: a key anyone on the machine can read protects nothing.
    if mode & 0o077 != 0 {
        return Err(ReferenceFailure::FileExposed(path.to_owned()));
    }
    fs::read_to_string(path).map_err(|_| unreadable())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::{ROOT_KEY, RootKeyError, resolve_root_key};

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
            Err(RootKeyError::VariableNotSet("ABSENT".to_owned()))
        );
        assert_eq!(
            resolve_root_key(read_from(&[(ROOT_KEY, "file:///no/such/file")])).map(|_| ()),
            Err(RootKeyError::FileUnreadable("/no/such/file".to_owned()))
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
            Err(RootKeyError::FileExposed(path.display().to_string()))
        );
        assert_eq!(private, Ok(vec![5_u8; 32]));
    }
}
