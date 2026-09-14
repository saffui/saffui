use roxmltree::{Document, Error, Node, ParsingOptions};

/// How much a message may hold before it is refused unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub bytes: usize,
    pub nodes: u32,
    pub depth: usize,
}

impl Limits {
    /// Room for a signed response carrying an encrypted assertion and its
    /// certificates, and nowhere near what a parser bomb needs.
    pub const MESSAGE: Limits = Limits {
        bytes: 256 * 1024,
        nodes: 16_384,
        depth: 48,
    };
}

/// Why a message was refused before anything read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the message is larger than allowed")]
    TooLarge,
    #[error("the message declares a document type")]
    DocumentType,
    #[error("the message is not well-formed XML")]
    Malformed,
    #[error("the message holds more nodes than allowed")]
    TooManyNodes,
    #[error("the message nests deeper than allowed")]
    TooDeep,
}

/// Parse a message under limits.
///
/// Any document type is refused, an empty one too: no SAML party needs one,
/// and its entities are where expansion bombs and external fetches live.
pub fn read_message(text: &str, limits: Limits) -> Result<Document<'_>, Unreadable> {
    if text.len() > limits.bytes {
        return Err(Unreadable::TooLarge);
    }
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: limits.nodes,
        ..ParsingOptions::default()
    };
    let document =
        Document::parse_with_options(text, options).map_err(|refused| match refused {
            Error::NodesLimitReached => Unreadable::TooManyNodes,
            Error::DtdDetected => Unreadable::DocumentType,
            _ => Unreadable::Malformed,
        })?;
    let deepest = document
        .descendants()
        .filter(|node| node.is_element())
        .map(|element| element.ancestors().filter(|node| node.is_element()).count())
        .max()
        .unwrap_or(0);
    if deepest > limits.depth {
        return Err(Unreadable::TooDeep);
    }
    Ok(document)
}

/// The element children of a node, in document order.
pub(crate) fn element_children<'a, 'input>(
    parent: Node<'a, 'input>,
) -> impl Iterator<Item = Node<'a, 'input>> {
    parent.children().filter(Node::is_element)
}

pub(crate) fn is_named(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

pub(crate) fn children_named<'a, 'input>(
    parent: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    parent
        .children()
        .filter(move |child| is_named(*child, namespace, name))
}

/// The bytes a base64 element holds, with the whitespace XML Schema allows
/// between its characters; nothing when it holds an element or is not base64.
pub(crate) fn base64_content_of(node: Node<'_, '_>) -> Option<Vec<u8>> {
    if element_children(node).next().is_some() {
        return None;
    }
    let compact: Vec<u8> = node
        .text()
        .unwrap_or_default()
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    data_encoding::BASE64.decode(&compact).ok()
}

/// The text an element holds when it holds text alone, trimmed. A comment or an
/// element inside makes it none, since a reader could take a part for the whole.
pub(crate) fn strict_text_of(element: Node<'_, '_>) -> Option<String> {
    let mut text = String::new();
    for child in element.children() {
        if !child.is_text() {
            return None;
        }
        text.push_str(child.text().unwrap_or_default());
    }
    Some(text.trim().to_owned())
}

/// ` name="value"` written into a start tag, the value escaped.
pub(crate) fn push_attribute(xml: &mut String, name: &str, value: &str) {
    xml.push(' ');
    xml.push_str(name);
    xml.push_str("=\"");
    for held in value.chars() {
        match held {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '"' => xml.push_str("&quot;"),
            other => xml.push(other),
        }
    }
    xml.push('"');
}

/// Text written as an element's content, escaped.
pub(crate) fn push_text(xml: &mut String, text: &str) {
    for held in text.chars() {
        match held {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            other => xml.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Limits, Unreadable, read_message};

    /// Base64 content reads across the whitespace XML allows inside it, and an
    /// element inside or characters outside the alphabet read as nothing.
    #[test]
    fn base64_content_reads_across_whitespace_only() {
        let document = read_message(
            "<r><a>aGVs\n  bG8=</a><b><c/></b><d>not base64!</d></r>",
            Limits::MESSAGE,
        )
        .expect("a message");
        let children: Vec<_> = super::element_children(document.root_element()).collect();
        assert_eq!(
            super::base64_content_of(children[0]).as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(super::base64_content_of(children[1]), None);
        assert_eq!(super::base64_content_of(children[2]), None);
    }

    /// A document type is refused whether it declares entities, names an
    /// external definition or declares nothing at all.
    #[test]
    fn a_document_type_is_refused_even_empty() {
        for text in [
            "<!DOCTYPE a><a/>",
            "<!DOCTYPE a []><a/>",
            "<!DOCTYPE a [<!ENTITY x \"expanded\">]><a>&x;</a>",
            "<?xml version=\"1.0\"?>\n<!DOCTYPE a SYSTEM \"http://example.org/a.dtd\"><a/>",
        ] {
            assert_eq!(
                read_message(text, Limits::MESSAGE).err(),
                Some(Unreadable::DocumentType),
                "{text}"
            );
        }
    }

    /// Each limit refuses the message that exceeds it, and a message within
    /// all of them reads.
    #[test]
    fn each_limit_refuses_what_exceeds_it() {
        let tight = Limits {
            bytes: 64,
            nodes: 8,
            depth: 3,
        };
        assert!(read_message("<a><b><c/></b></a>", tight).is_ok());
        assert_eq!(
            read_message("<a><b><c><d/></c></b></a>", tight).err(),
            Some(Unreadable::TooDeep)
        );
        assert_eq!(
            read_message(&format!("<a>{}</a>", "<b/>".repeat(8)), tight).err(),
            Some(Unreadable::TooManyNodes)
        );
        assert_eq!(
            read_message(&format!("<a>{}</a>", " ".repeat(64)), tight).err(),
            Some(Unreadable::TooLarge)
        );
    }

    /// What is not well-formed is refused: a crossed end tag, an undeclared
    /// prefix, a repeated attribute, nothing at all.
    #[test]
    fn a_message_that_is_not_well_formed_is_refused() {
        for text in ["<a><b></a>", "<x:a/>", "<a b=\"1\" b=\"2\"/>", ""] {
            assert_eq!(
                read_message(text, Limits::MESSAGE).err(),
                Some(Unreadable::Malformed),
                "{text:?}"
            );
        }
    }
}
