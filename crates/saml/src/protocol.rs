use crate::time::write_instant;
use crate::xml::push_attribute;

const NAMESPACES: &str = r#"xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;

/// Why a message could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unwritable {
    #[error("a time could not be written")]
    Time,
}

/// The start tag of a protocol message with what every request and response
/// carries, left open for the attributes its kind adds.
pub(crate) fn open_protocol_message(
    kind: &str,
    id: &str,
    issue_instant: i64,
    destination: &str,
) -> Result<String, Unwritable> {
    let instant = write_instant(issue_instant).ok_or(Unwritable::Time)?;
    let mut xml = format!("<samlp:{kind} {NAMESPACES}");
    push_attribute(&mut xml, "ID", id);
    push_attribute(&mut xml, "Version", "2.0");
    push_attribute(&mut xml, "IssueInstant", &instant);
    push_attribute(&mut xml, "Destination", destination);
    Ok(xml)
}
