//! The form by which a page asks a security key. The one script of the
//! hosted pages, `templates/key_script.js`, hands the ceremony to the
//! browser and posts what the key answered. Nothing else on these pages runs.

use uuid::Uuid;

/// What a page says when a form of a key was posted without an answer.
pub(crate) const KEY_SILENT: &str = "The security key did not answer.";

/// Which half of the browser's interface a form calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyCeremonyKind {
    Enrollment,
    Proof,
}

/// The form of a security key, as `templates/key_form.html` writes it. The
/// answer of the key is posted to `action` in the field `key`, with
/// `request` when a sign-in waits for it.
pub(crate) struct KeyPrompt<'a> {
    pub(crate) action: String,
    pub(crate) request: Option<Uuid>,
    pub(crate) kind: KeyCeremonyKind,
    /// What the browser hands the key, written into the form as JSON.
    pub(crate) options: &'a serde_json::Value,
    pub(crate) label: &'a str,
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_script_cannot_close_its_own_element() {
        let script = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/key_script.js"
        ));

        assert!(!script.to_ascii_lowercase().contains("</script"));
    }
}
