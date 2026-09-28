//! The canonical form of N-Quads, RDFC-1.0 Appendix A: one quad per line, one
//! space between terms, and a single spelling for every character.

use std::fmt::Write;

use crate::rdf::{Literal, Node, Object, Quad, XSD_STRING};

/// Write `quad` in canonical N-Quads form, its end of line included, each blank
/// node under the identifier `label` writes for it.
pub fn write_quad(out: &mut String, quad: &Quad, label: &dyn Fn(&str, &mut String)) {
    write_node(out, &quad.subject, label);
    out.push_str(" <");
    out.push_str(&quad.predicate);
    out.push_str("> ");
    match &quad.object {
        Object::Node(node) => write_node(out, node, label),
        Object::Literal(literal) => write_literal(out, literal),
    }
    if let Some(graph) = &quad.graph {
        out.push(' ');
        write_node(out, graph, label);
    }
    out.push_str(" .\n");
}

fn write_node(out: &mut String, node: &Node, label: &dyn Fn(&str, &mut String)) {
    match node {
        Node::Iri(iri) => {
            out.push('<');
            out.push_str(iri);
            out.push('>');
        }
        Node::Blank(identifier) => {
            out.push_str("_:");
            label(identifier, out);
        }
    }
}

fn write_literal(out: &mut String, literal: &Literal) {
    out.push('"');
    for character in literal.lexical.chars() {
        match character {
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            // The other controls, DEL, and the two code points XML 1.1 `Char`
            // leaves out that a Rust string can hold.
            '\u{0}'..='\u{7}'
            | '\u{b}'
            | '\u{e}'..='\u{1f}'
            | '\u{7f}'
            | '\u{fffe}'
            | '\u{ffff}' => {
                let _ = write!(out, "\\u{:04X}", u32::from(character));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    if let Some(language) = &literal.language {
        out.push('@');
        out.push_str(language);
    } else if literal.datatype != XSD_STRING {
        out.push_str("^^<");
        out.push_str(&literal.datatype);
        out.push('>');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdf::RDF_LANG_STRING;

    fn literal(lexical: &str, datatype: &str, language: Option<&str>) -> Quad {
        Quad {
            subject: Node::Blank("x".into()),
            predicate: "http://example.com/p".into(),
            object: Object::Literal(Literal {
                lexical: lexical.into(),
                datatype: datatype.into(),
                language: language.map(str::to_owned),
            }),
            graph: None,
        }
    }

    fn written(quad: &Quad) -> String {
        let mut out = String::new();
        write_quad(&mut out, quad, &|_, out| out.push_str("c14n0"));
        out
    }

    #[test]
    fn each_character_has_one_spelling() {
        let quad = literal(
            "\u{8}\t\n\u{c}\r\"\\\u{0}\u{7}\u{b}\u{e}\u{1f}\u{7f}\u{fffe}\u{ffff}é\u{10000}",
            XSD_STRING,
            None,
        );
        assert_eq!(
            written(&quad),
            "_:c14n0 <http://example.com/p> \"\\b\\t\\n\\f\\r\\\"\\\\\\u0000\\u0007\\u000B\\u000E\\u001F\\u007F\\uFFFE\\uFFFFé\u{10000}\" .\n"
        );
    }

    #[test]
    fn a_string_names_no_datatype_and_a_tagged_one_its_language() {
        assert!(written(&literal("a", XSD_STRING, None)).ends_with("\"a\" .\n"));
        assert!(written(&literal("a", RDF_LANG_STRING, Some("en"))).ends_with("\"a\"@en .\n"));
        let integer = literal("1", "http://www.w3.org/2001/XMLSchema#integer", None);
        assert!(
            written(&integer).ends_with("\"1\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n")
        );
    }

    #[test]
    fn a_graph_name_follows_the_object() {
        let quad = Quad {
            subject: Node::Iri("http://example.com/s".into()),
            predicate: "http://example.com/p".into(),
            object: Object::Node(Node::Blank("o".into())),
            graph: Some(Node::Blank("g".into())),
        };
        let mut out = String::new();
        write_quad(&mut out, &quad, &|identifier, out| {
            out.push_str(if identifier == "o" { "a" } else { "z" });
        });
        assert_eq!(
            out,
            "<http://example.com/s> <http://example.com/p> _:a _:z .\n"
        );
    }
}
