use roxmltree::Node;

use crate::xml::{push_attribute, push_text, strict_text_of};

/// A name identifier as the identity provider wrote it. A logout request repeats
/// it whole, since the provider matches its qualifiers as well as its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    pub value: String,
    pub format: Option<String>,
    /// The identity provider's own qualifier, when it gave one.
    pub name_qualifier: Option<String>,
    /// The service provider the identifier was made for, when it was named.
    pub sp_name_qualifier: Option<String>,
}

/// A `NameID` element read strictly: text alone, and never an empty value, which
/// would name everyone the provider leaves unnamed.
pub(crate) fn read_name_id(element: Node<'_, '_>) -> Option<NameId> {
    let value = strict_text_of(element).filter(|value| !value.is_empty())?;
    Some(NameId {
        value,
        format: element.attribute("Format").map(str::to_owned),
        name_qualifier: element.attribute("NameQualifier").map(str::to_owned),
        sp_name_qualifier: element.attribute("SPNameQualifier").map(str::to_owned),
    })
}

/// A `saml:NameID` element with the attributes the identifier holds.
pub(crate) fn push_name_id(xml: &mut String, name_id: &NameId) {
    xml.push_str("<saml:NameID");
    for (name, value) in [
        ("Format", &name_id.format),
        ("NameQualifier", &name_id.name_qualifier),
        ("SPNameQualifier", &name_id.sp_name_qualifier),
    ] {
        if let Some(value) = value {
            push_attribute(xml, name, value);
        }
    }
    xml.push('>');
    push_text(xml, &name_id.value);
    xml.push_str("</saml:NameID>");
}

#[cfg(test)]
mod tests {
    use super::{NameId, push_name_id, read_name_id};
    use crate::xml::{Limits, read_message};

    const ASSERTION: &str = r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#;

    fn read(text: &str) -> Option<NameId> {
        let document = read_message(text, Limits::MESSAGE).expect("well-formed");
        read_name_id(document.root_element())
    }

    /// A name identifier is written with its format and qualifiers and read back
    /// the same, with none when it has none; an empty one, or one split by
    /// anything but text, is not read.
    #[test]
    fn a_name_identifier_is_written_and_read_whole() {
        let qualified = NameId {
            value: "AAdz&<ZWNy>".to_owned(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
            name_qualifier: Some("https://idp.test/metadata".to_owned()),
            sp_name_qualifier: Some("https://sp.test/metadata?a=1&b=\"2\"".to_owned()),
        };
        let bare = NameId {
            value: "someone".to_owned(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
        };
        for name_id in [qualified, bare] {
            let mut xml = String::new();
            push_name_id(&mut xml, &name_id);
            let declared = xml.replacen("<saml:NameID", &format!("<saml:NameID {ASSERTION}"), 1);
            assert_eq!(read(&declared), Some(name_id));
        }
        assert_eq!(
            read(&format!("<saml:NameID {ASSERTION}> </saml:NameID>")),
            None
        );
        assert_eq!(
            read(&format!(
                "<saml:NameID {ASSERTION}>AAdz<!-- -->ZWNy</saml:NameID>"
            )),
            None
        );
    }
}
