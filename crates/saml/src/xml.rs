use roxmltree::{Document, Error, ParsingOptions};

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

#[cfg(test)]
mod tests {
    use super::{Limits, Unreadable, read_message};

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
