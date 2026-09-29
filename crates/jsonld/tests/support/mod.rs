//! What the suites share: the OpenSSL provider, and a reader of the N-Quads
//! the W3C suites write their inputs and results in.

use crypto::provider::CryptoConfig;
use crypto::provider::openssl::OpenSslProvider;
use jsonld::rdf::{Literal, Node, Object, Quad, RDF_LANG_STRING, XSD_STRING};

pub fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
}

/// Every statement of an N-Quads document, one per line.
pub fn quads_of(text: &str) -> Vec<Quad> {
    text.lines()
        .filter_map(|line| NQuads::new(line).statement())
        .collect()
}

/// A reader of the N-Quads the suite writes, one statement per line.
pub struct NQuads<'t> {
    rest: &'t str,
}

impl<'t> NQuads<'t> {
    pub fn new(line: &'t str) -> Self {
        Self { rest: line }
    }

    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t']);
    }

    pub fn statement(&mut self) -> Option<Quad> {
        self.skip_space();
        if self.rest.is_empty() || self.rest.starts_with('#') {
            return None;
        }
        let subject = self.node();
        let predicate = self.iri();
        let object = self.object();
        self.skip_space();
        let graph = (!self.rest.starts_with('.')).then(|| self.node());
        self.skip_space();
        assert!(self.rest.starts_with('.'), "a statement ends with a dot");
        Some(Quad {
            subject,
            predicate,
            object,
            graph,
        })
    }

    fn node(&mut self) -> Node {
        self.skip_space();
        if self.rest.starts_with("_:") {
            let end = self.rest.find([' ', '\t']).unwrap_or(self.rest.len());
            let label = self.rest[2..end].trim_end_matches('.').to_owned();
            self.rest = &self.rest[2 + label.len()..];
            Node::Blank(label)
        } else {
            Node::Iri(self.iri())
        }
    }

    fn iri(&mut self) -> String {
        self.skip_space();
        let body = self.rest.strip_prefix('<').expect("an IRI");
        let end = body.find('>').expect("an IRI's end");
        self.rest = &body[end + 1..];
        unescape(&body[..end])
    }

    fn object(&mut self) -> Object {
        self.skip_space();
        let Some(body) = self.rest.strip_prefix('"') else {
            return Object::Node(self.node());
        };
        let mut end = 0;
        let mut escaped = false;
        for (at, character) in body.char_indices() {
            match character {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = at;
                    break;
                }
                _ => escaped = false,
            }
        }
        let lexical = unescape(&body[..end]);
        self.rest = &body[end + 1..];
        if let Some(tagged) = self.rest.strip_prefix('@') {
            let tag_end = tagged.find([' ', '\t']).unwrap_or(tagged.len());
            let language = tagged[..tag_end].to_owned();
            self.rest = &tagged[tag_end..];
            return Object::Literal(Literal {
                lexical,
                datatype: RDF_LANG_STRING.to_owned(),
                language: Some(language),
            });
        }
        let datatype = match self.rest.strip_prefix("^^") {
            Some(typed) => {
                self.rest = typed;
                self.iri()
            }
            None => XSD_STRING.to_owned(),
        };
        Object::Literal(Literal {
            lexical,
            datatype,
            language: None,
        })
    }
}

/// ECHAR and UCHAR read back into the characters they stand for.
fn unescape(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut characters = escaped.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        let code = |length: usize, characters: &mut std::str::Chars<'_>| {
            let hex: String = characters.take(length).collect();
            char::from_u32(u32::from_str_radix(&hex, 16).expect("hexadecimal"))
                .expect("a character")
        };
        match characters.next().expect("an escape") {
            't' => out.push('\t'),
            'b' => out.push('\u{8}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            'f' => out.push('\u{c}'),
            'u' => out.push(code(4, &mut characters)),
            'U' => out.push(code(8, &mut characters)),
            other => out.push(other),
        }
    }
    out
}
