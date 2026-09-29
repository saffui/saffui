//! The forms JSON-LD tells strings apart by.

/// The keywords of JSON-LD 1.1, framing's included: a term may be none of them.
const KEYWORDS: [&str; 29] = [
    "@base",
    "@container",
    "@context",
    "@default",
    "@direction",
    "@embed",
    "@explicit",
    "@graph",
    "@id",
    "@import",
    "@included",
    "@index",
    "@json",
    "@language",
    "@list",
    "@nest",
    "@none",
    "@omitDefault",
    "@prefix",
    "@preserve",
    "@propagate",
    "@protected",
    "@requireAll",
    "@reverse",
    "@set",
    "@type",
    "@value",
    "@version",
    "@vocab",
];

pub(crate) fn is_keyword(value: &str) -> bool {
    KEYWORDS.contains(&value)
}

/// `@` then letters only: reserved for keywords yet to come, and so meaning
/// nothing now.
pub(crate) fn has_keyword_form(value: &str) -> bool {
    value.len() > 1
        && value.starts_with('@')
        && value[1..].bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// An absolute IRI RDF can carry: a scheme, and none of the characters an IRI
/// reference may not hold.
pub(crate) fn is_absolute_iri(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    let mut scheme = scheme.bytes();
    scheme
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        && !value.chars().any(|character| {
            character <= ' '
                || character == '\u{7f}'
                || matches!(
                    character,
                    '<' | '>' | '"' | '{' | '}' | '|' | '\\' | '^' | '`'
                )
        })
}

pub(crate) fn is_blank_node_identifier(value: &str) -> bool {
    value.len() > 2 && value.starts_with("_:")
}

/// A language tag well formed as BCP 47 §2.2.9 asks, in the shape processors
/// check it: letters, then subtags of letters and digits.
pub(crate) fn is_language_tag(value: &str) -> bool {
    let mut subtags = value.split('-');
    let first_ok = subtags.next().is_some_and(|first| {
        (1..=8).contains(&first.len()) && first.bytes().all(|byte| byte.is_ascii_alphabetic())
    });
    first_ok
        && subtags.all(|subtag| {
            (1..=8).contains(&subtag.len())
                && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_iri_has_a_scheme_and_no_forbidden_character() {
        for absolute in [
            "https://example.com/a#b",
            "urn:uuid:1",
            "did:web:id.test:realms:acme",
            "mailto:a@b",
        ] {
            assert!(is_absolute_iri(absolute), "{absolute}");
        }
        for not in [
            "a",
            "/relative",
            "#fragment",
            "1http://x",
            "http://a b",
            "http://a<b",
            "_x:y z",
        ] {
            assert!(!is_absolute_iri(not), "{not}");
        }
    }

    #[test]
    fn a_keyword_form_is_at_then_letters() {
        assert!(has_keyword_form("@foo"));
        assert!(!has_keyword_form("@"));
        assert!(!has_keyword_form("@foo1"));
        assert!(!has_keyword_form("foo"));
    }

    #[test]
    fn a_language_tag_is_letters_then_subtags() {
        for tag in ["en", "en-US", "zh-Hant-TW", "sw"] {
            assert!(is_language_tag(tag), "{tag}");
        }
        for not in ["", "en_US", "en-", "toolonglanguage", "e1"] {
            assert!(!is_language_tag(not), "{not}");
        }
    }
}
