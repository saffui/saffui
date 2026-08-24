use std::fmt;

use secrecy::SecretBox;

/// The largest `file:` reference that will be read. No real secret is more than
/// a few hundred bytes, and the path comes from configuration.
const MAX_SECRET_LEN: u64 = 64 * 1024;

/// Why a reference could not be resolved. The message names the reference and
/// the reason, never the value: these reach a startup log.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// A `file:` reference whose file could not be read.
    File { path: String, reason: String },
    /// A `file:` reference whose file is too large to be a secret.
    TooLarge { path: String, len: u64 },
    /// An `env:` reference whose variable is unset.
    EnvUnset { var: String },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { path, reason } => {
                write!(f, "secret file '{path}' could not be read: {reason}")
            }
            Self::TooLarge { path, len } => write!(
                f,
                "secret file '{path}' is {len} bytes, over the {MAX_SECRET_LEN} byte limit"
            ),
            Self::EnvUnset { var } => write!(f, "secret env var '{var}' is not set"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Resolve a reference to its value.
///
/// The scheme is matched case-insensitively: `File:/run/secrets/kek` means the
/// file, and matching exactly would hand back the path as the secret and come
/// up working on a key derived from a pathname.
pub fn resolve(reference: &str) -> Result<SecretBox<String>, SecretError> {
    if let Some(path) = strip_scheme(reference, "file:") {
        return read_file(path).map(secret);
    }

    if let Some(var) = strip_scheme(reference, "env:") {
        return std::env::var(var)
            .map(secret)
            .map_err(|_| SecretError::EnvUnset {
                var: var.to_string(),
            });
    }

    Ok(secret(reference.to_string()))
}

/// Resolve a reference that may be absent. Empty stays absent rather than
/// becoming a secret of length zero that something accepts.
pub fn resolve_optional(reference: Option<&str>) -> Result<Option<SecretBox<String>>, SecretError> {
    match reference.filter(|value| !value.is_empty()) {
        Some(value) => resolve(value).map(Some),
        None => Ok(None),
    }
}

fn secret(value: String) -> SecretBox<String> {
    SecretBox::new(Box::new(value))
}

fn strip_scheme<'a>(reference: &'a str, scheme: &str) -> Option<&'a str> {
    reference
        .get(..scheme.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
        .map(|prefix| &reference[prefix.len()..])
}

fn read_file(path: &str) -> Result<String, SecretError> {
    let failed = |reason: String| SecretError::File {
        path: path.to_string(),
        reason,
    };

    // Measured before reading, not after.
    let len = std::fs::metadata(path)
        .map_err(|error| failed(error.to_string()))?
        .len();
    if len > MAX_SECRET_LEN {
        return Err(SecretError::TooLarge {
            path: path.to_string(),
            len,
        });
    }

    std::fs::read_to_string(path)
        .map(|contents| contents.trim_end_matches(['\n', '\r']).to_string())
        .map_err(|error| failed(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use secrecy::ExposeSecret;

    fn resolved(reference: &str) -> String {
        resolve(reference).unwrap().expose_secret().clone()
    }

    /// A throwaway file, removed when it drops.
    struct TempSecret(std::path::PathBuf);

    impl TempSecret {
        fn new(contents: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);

            let path = std::env::temp_dir().join(format!(
                "saffui_secret_{}_{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }

        fn reference(&self) -> String {
            format!("file:{}", self.0.display())
        }
    }

    impl Drop for TempSecret {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Anything without a known scheme is the value itself.
    #[test]
    fn a_literal_is_itself() {
        assert_eq!(resolved("s3cr3t"), "s3cr3t");
        // A colon alone is not a scheme, so a password may contain one.
        assert_eq!(resolved("my-file:thing"), "my-file:thing");
        assert_eq!(resolved("pa:ss:word"), "pa:ss:word");
    }

    /// The file's contents, with the trailing newline a mounted secret carries.
    #[test]
    fn a_file_reference_reads_and_trims() {
        for (written, expected) in [
            ("top-secret\n", "top-secret"),
            ("top-secret\r\n", "top-secret"),
            ("top-secret", "top-secret"),
            ("two\nlines\n", "two\nlines"),
        ] {
            let file = TempSecret::new(written);
            assert_eq!(resolved(&file.reference()), expected, "{written:?}");
        }
    }

    /// A file that is not there is an error naming it, not an empty secret.
    #[test]
    fn a_missing_file_is_an_error() {
        let error = resolve("file:/no/such/secret").unwrap_err();

        assert!(matches!(error, SecretError::File { .. }));
        assert!(error.to_string().contains("/no/such/secret"));
    }

    /// A file too large to be a secret is refused before it is read.
    #[test]
    fn an_oversized_file_is_refused() {
        let file = TempSecret::new(&"x".repeat(MAX_SECRET_LEN as usize + 1));

        assert!(matches!(
            resolve(&file.reference()),
            Err(SecretError::TooLarge { .. })
        ));
    }

    /// The variable's value, and an error when it is unset.
    #[test]
    fn an_env_reference_reads_the_variable() {
        // A name of this test's own, so a parallel test cannot see it.
        let name = "SAFFUI_TEST_SECRET_ENV_READS";
        // SAFETY: the name is unique to this test, so no other thread reads or
        // writes it.
        unsafe { std::env::set_var(name, "from-env") };

        assert_eq!(resolved(&format!("env:{name}")), "from-env");
        assert_eq!(
            resolve("env:SAFFUI_TEST_SECRET_NEVER_SET").unwrap_err(),
            SecretError::EnvUnset {
                var: "SAFFUI_TEST_SECRET_NEVER_SET".to_string()
            }
        );
    }

    /// The scheme is read whatever its case.
    ///
    /// Matching exactly would turn `File:/run/secrets/kek` into a literal, and
    /// the deployment would come up on a key derived from a pathname — working,
    /// and wrong, with nothing to say so.
    #[test]
    fn the_scheme_is_read_whatever_its_case() {
        let file = TempSecret::new("from-file\n");
        let path = file.0.display().to_string();

        for scheme in ["file", "File", "FILE", "fIlE"] {
            assert_eq!(
                resolved(&format!("{scheme}:{path}")),
                "from-file",
                "{scheme}"
            );
        }

        let name = "SAFFUI_TEST_SECRET_ENV_CASE";
        // SAFETY: a name unique to this test.
        unsafe { std::env::set_var(name, "from-env") };
        for scheme in ["env", "Env", "ENV"] {
            assert_eq!(
                resolved(&format!("{scheme}:{name}")),
                "from-env",
                "{scheme}"
            );
        }
    }

    /// Absent and empty both stay absent.
    #[test]
    fn an_absent_reference_resolves_to_nothing() {
        assert!(resolve_optional(None).unwrap().is_none());
        assert!(resolve_optional(Some("")).unwrap().is_none());

        let some = resolve_optional(Some("literal")).unwrap().unwrap();
        assert_eq!(some.expose_secret(), "literal");
    }

    /// The value does not reach a log through a formatter.
    #[test]
    fn the_resolved_secret_does_not_render() {
        let resolved = resolve("s3cr3t").unwrap();

        assert!(!format!("{resolved:?}").contains("s3cr3t"));
    }

    /// An error names the reference and never the value.
    #[test]
    fn an_error_never_carries_the_secret() {
        let file = TempSecret::new(&"x".repeat(MAX_SECRET_LEN as usize + 1));
        let message = resolve(&file.reference()).unwrap_err().to_string();

        assert!(message.contains(&file.0.display().to_string()));
        assert!(!message.contains("xxxx"));
    }
}
