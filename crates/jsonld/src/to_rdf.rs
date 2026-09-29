//! A document read into an RDF dataset, JSON-LD 1.1 API §7.2, §7.4 and §8.1
//! to §8.3, with the literal forms of §8.6. What the algorithm would leave out
//! of the dataset, a term that names nothing well formed, refuses the document.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};

use crate::Unreadable;
use crate::context::{ActiveContext, Contexts};
use crate::expand::Expander;
use crate::iri::{is_absolute_iri, is_blank_node_identifier, is_keyword, is_language_tag};
use crate::rdf::{Literal, Node, Object, Quad, RDF_LANG_STRING, XSD_STRING};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const RDF_FIRST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first";
const RDF_REST: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest";
const RDF_NIL: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil";
const RDF_JSON: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";
const XSD_BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const XSD_INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const XSD_DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";

/// Read `document` into an RDF dataset of at most `most_quads` quads, every
/// context taken from `contexts`.
pub fn to_rdf(
    document: &Value,
    contexts: &dyn Contexts,
    most_quads: usize,
) -> Result<Vec<Quad>, Unreadable> {
    let expanded =
        Expander { contexts }.expand(&ActiveContext::default(), None, document, false)?;
    let expanded = match expanded {
        Value::Object(mut object) if object.len() == 1 && object.contains_key("@graph") => {
            object.remove("@graph").unwrap_or(Value::Null)
        }
        other => other,
    };
    let mut mapper = NodeMapper::default();
    mapper.map(&expanded, "@default", None, None, None)?;
    mapper.dataset(most_quads)
}

/// A node as the node map holds it.
#[derive(Default)]
struct MappedNode {
    types: Vec<Value>,
    index: Option<Value>,
    properties: BTreeMap<String, Vec<Value>>,
}

/// §7.2: every node of every graph gathered under its identifier, blank nodes
/// relabeled.
#[derive(Default)]
struct NodeMapper {
    graphs: BTreeMap<String, BTreeMap<String, MappedNode>>,
    labels: HashMap<String, String>,
    issued: usize,
}

impl NodeMapper {
    /// §7.4
    fn blank_node(&mut self, identifier: Option<&str>) -> String {
        if let Some(existing) = identifier.and_then(|identifier| self.labels.get(identifier)) {
            return existing.clone();
        }
        let label = format!("_:b{}", self.issued);
        self.issued += 1;
        if let Some(identifier) = identifier {
            self.labels.insert(identifier.to_owned(), label.clone());
        }
        label
    }

    fn node(&mut self, graph: &str, subject: &str) -> &mut MappedNode {
        self.graphs
            .entry(graph.to_owned())
            .or_default()
            .entry(subject.to_owned())
            .or_default()
    }

    fn relabel(&mut self, item: &mut Value) {
        if let Value::String(name) = item
            && is_blank_node_identifier(name)
        {
            *name = self.blank_node(Some(name));
        }
    }

    /// The values of `property` on `subject` in `graph`, created empty.
    fn values_of(&mut self, graph: &str, subject: &str, property: &str) -> &mut Vec<Value> {
        self.node(graph, subject)
            .properties
            .entry(property.to_owned())
            .or_default()
    }

    /// Add `item` to what `subject` says of `property`, unless it says it already.
    fn add_unique(&mut self, graph: &str, subject: &str, property: &str, item: Value) {
        let values = self.values_of(graph, subject, property);
        if !values.contains(&item) {
            values.push(item);
        }
    }

    /// §7.2.2
    fn map(
        &mut self,
        element: &Value,
        graph: &str,
        subject: Option<&str>,
        property: Option<&str>,
        mut list: Option<&mut Vec<Value>>,
    ) -> Result<(), Unreadable> {
        let element = match element {
            Value::Array(items) => {
                for item in items {
                    self.map(item, graph, subject, property, list.as_deref_mut())?;
                }
                return Ok(());
            }
            Value::Object(element) => element,
            _ => return Ok(()),
        };
        self.graphs.entry(graph.to_owned()).or_default();
        let mut element = element.clone();
        // 3: a blank node named as a type is relabeled, the entry keeping its
        // shape; a value object's type is its datatype.
        match element.get_mut("@type") {
            Some(Value::Array(items)) => {
                for item in items {
                    self.relabel(item);
                }
            }
            Some(single) => self.relabel(single),
            None => {}
        }

        if element.contains_key("@value") {
            match list {
                Some(list) => list.push(Value::Object(element)),
                None => {
                    if let (Some(subject), Some(property)) = (subject, property) {
                        self.add_unique(graph, subject, property, Value::Object(element));
                    }
                }
            }
            return Ok(());
        }

        if let Some(items) = element.get("@list") {
            let mut collected = Vec::new();
            self.map(items, graph, subject, property, Some(&mut collected))?;
            let result = json!({ "@list": collected });
            match list {
                Some(list) => list.push(result),
                None => {
                    if let (Some(subject), Some(property)) = (subject, property) {
                        self.values_of(graph, subject, property).push(result);
                    }
                }
            }
            return Ok(());
        }

        let id = match element.remove("@id") {
            Some(Value::String(id)) if is_blank_node_identifier(&id) => self.blank_node(Some(&id)),
            Some(Value::String(id)) => id,
            _ => self.blank_node(None),
        };
        self.node(graph, &id);
        if let (Some(subject), Some(property)) = (subject, property) {
            let reference = json!({ "@id": id });
            match list {
                Some(list) => list.push(reference),
                None => self.add_unique(graph, subject, property, reference),
            }
        }
        if let Some(Value::Array(types)) = element.remove("@type") {
            let node = self.node(graph, &id);
            for name in types {
                if !node.types.contains(&name) {
                    node.types.push(name);
                }
            }
        }
        if let Some(index) = element.remove("@index") {
            let node = self.node(graph, &id);
            match &node.index {
                Some(held) if *held != index => {
                    return Err(Unreadable::Invalid("conflicting indexes"));
                }
                _ => node.index = Some(index),
            }
        }
        if let Some(inner) = element.remove("@graph") {
            self.map(&inner, &id, None, None, None)?;
        }
        let mut properties: Vec<(String, Value)> = element.into_iter().collect();
        properties.sort_by(|left, right| left.0.cmp(&right.0));
        for (property, value) in properties {
            let property = if is_blank_node_identifier(&property) {
                self.blank_node(Some(&property))
            } else {
                property
            };
            self.values_of(graph, &id, &property);
            self.map(&value, graph, Some(&id), Some(&property), None)?;
        }
        Ok(())
    }

    /// §8.1.2
    fn dataset(mut self, most_quads: usize) -> Result<Vec<Quad>, Unreadable> {
        let graphs = std::mem::take(&mut self.graphs);
        let mut quads = Vec::new();
        for (graph_name, graph) in graphs {
            let graph_term = match graph_name.as_str() {
                "@default" => None,
                name => Some(node_named(name)?),
            };
            for (subject, node) in graph {
                let subject = node_named(&subject)?;
                for name in &node.types {
                    quads.push(Quad {
                        subject: subject.clone(),
                        predicate: RDF_TYPE.to_owned(),
                        object: Object::Node(node_named(name.as_str().unwrap_or_default())?),
                        graph: graph_term.clone(),
                    });
                }
                for (property, values) in node.properties {
                    if is_keyword(&property) {
                        continue;
                    }
                    if is_blank_node_identifier(&property) {
                        return Err(Unreadable::Dropped("a property named by a blank node"));
                    }
                    if !is_absolute_iri(&property) {
                        return Err(Unreadable::NotAbsolute(property));
                    }
                    for item in values {
                        let mut list_triples = Vec::new();
                        let object = self.object_of(&item, &mut list_triples)?;
                        quads.push(Quad {
                            subject: subject.clone(),
                            predicate: property.clone(),
                            object,
                            graph: graph_term.clone(),
                        });
                        for (list_subject, list_predicate, list_object) in list_triples {
                            quads.push(Quad {
                                subject: list_subject,
                                predicate: list_predicate,
                                object: list_object,
                                graph: graph_term.clone(),
                            });
                        }
                    }
                    if quads.len() > most_quads {
                        return Err(Unreadable::TooLarge);
                    }
                }
            }
        }
        if quads.len() > most_quads {
            return Err(Unreadable::TooLarge);
        }
        Ok(quads)
    }

    /// §8.2.2
    fn object_of(
        &mut self,
        item: &Value,
        list_triples: &mut Vec<(Node, String, Object)>,
    ) -> Result<Object, Unreadable> {
        let Some(item) = item.as_object() else {
            return Err(Unreadable::Invalid("invalid value object"));
        };
        if let Some(list) = item.get("@list") {
            return self.list_of(
                list.as_array().map(Vec::as_slice).unwrap_or_default(),
                list_triples,
            );
        }
        let Some(value) = item.get("@value") else {
            let id = item.get("@id").and_then(Value::as_str).unwrap_or_default();
            return Ok(Object::Node(node_named(id)?));
        };
        let datatype = item.get("@type").and_then(Value::as_str);
        if let Some(datatype) = datatype
            && datatype != "@json"
            && !is_absolute_iri(datatype)
        {
            return Err(Unreadable::NotAbsolute(datatype.to_owned()));
        }
        let language = item.get("@language").and_then(Value::as_str);
        if let Some(language) = language
            && !is_language_tag(language)
        {
            return Err(Unreadable::Dropped("a string in a malformed language tag"));
        }
        let (lexical, datatype) = match (datatype, value) {
            (Some("@json"), value) => {
                let mut lexical = String::new();
                write_canonical_json(value, &mut lexical)?;
                (lexical, RDF_JSON.to_owned())
            }
            (datatype, Value::Bool(boolean)) => (
                boolean.to_string(),
                datatype.unwrap_or(XSD_BOOLEAN).to_owned(),
            ),
            (datatype, Value::Number(number)) => {
                let as_double = datatype == Some(XSD_DOUBLE)
                    || number.as_f64().is_some_and(|float| {
                        (!number.is_i64() && !number.is_u64())
                            && (float.fract() != 0.0 || float.abs() >= 1e21)
                    });
                if as_double {
                    let float = number.as_f64().unwrap_or_default();
                    (
                        canonical_double(float),
                        datatype.unwrap_or(XSD_DOUBLE).to_owned(),
                    )
                } else {
                    let integer = match (number.as_i64(), number.as_u64(), number.as_f64()) {
                        (Some(integer), _, _) => integer.to_string(),
                        (_, Some(integer), _) => integer.to_string(),
                        // A JSON -0 reads as a float; the canonical integer has no sign.
                        (_, _, Some(float)) => {
                            format!("{:.0}", if float == 0.0 { 0.0 } else { float })
                        }
                        _ => return Err(Unreadable::Invalid("invalid value object value")),
                    };
                    (integer, datatype.unwrap_or(XSD_INTEGER).to_owned())
                }
            }
            (datatype, Value::String(string)) => (
                string.clone(),
                datatype.map_or_else(
                    || {
                        if language.is_some() {
                            RDF_LANG_STRING
                        } else {
                            XSD_STRING
                        }
                        .to_owned()
                    },
                    str::to_owned,
                ),
            ),
            _ => return Err(Unreadable::Invalid("invalid value object value")),
        };
        Ok(Object::Literal(Literal {
            lexical,
            language: language
                .filter(|_| datatype == RDF_LANG_STRING)
                .map(str::to_owned),
            datatype,
        }))
    }

    /// §8.3.2
    fn list_of(
        &mut self,
        items: &[Value],
        list_triples: &mut Vec<(Node, String, Object)>,
    ) -> Result<Object, Unreadable> {
        let nil = Object::Node(Node::Iri(RDF_NIL.to_owned()));
        if items.is_empty() {
            return Ok(nil);
        }
        let nodes: Vec<String> = items.iter().map(|_| self.blank_node(None)).collect();
        for (at, item) in items.iter().enumerate() {
            let subject = node_named(&nodes[at])?;
            let mut embedded = Vec::new();
            let object = self.object_of(item, &mut embedded)?;
            list_triples.push((subject.clone(), RDF_FIRST.to_owned(), object));
            let rest = match nodes.get(at + 1) {
                Some(next) => Object::Node(node_named(next)?),
                None => nil.clone(),
            };
            list_triples.push((subject, RDF_REST.to_owned(), rest));
            list_triples.extend(embedded);
        }
        Ok(Object::Node(node_named(&nodes[0])?))
    }
}

/// A subject, an object or a graph name, which must be well formed to be in
/// the dataset at all.
fn node_named(name: &str) -> Result<Node, Unreadable> {
    if let Some(label) = name.strip_prefix("_:").filter(|label| !label.is_empty()) {
        return Ok(Node::Blank(label.to_owned()));
    }
    if is_absolute_iri(name) {
        return Ok(Node::Iri(name.to_owned()));
    }
    Err(Unreadable::NotAbsolute(name.to_owned()))
}

/// §8.6: the canonical lexical form of an `xsd:double`, the mantissa rounded
/// to fifteen digits after its point.
fn canonical_double(value: f64) -> String {
    if value == 0.0 {
        return "0.0E0".to_owned();
    }
    let written = format!("{value:.15e}");
    let (mantissa, exponent) = written.split_once('e').unwrap_or((&written, "0"));
    let mantissa = mantissa.trim_end_matches('0');
    let mantissa = if mantissa.ends_with('.') {
        format!("{mantissa}0")
    } else {
        mantissa.to_owned()
    };
    format!("{mantissa}E{exponent}")
}

/// The canonical form of a JSON literal: members in the order of their names'
/// UTF-16 code units, no white space, strings escaped as JSON serializers do.
/// A number with a fraction has no single form both sides would agree on, and
/// is refused.
fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), Unreadable> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(boolean) => out.push_str(if *boolean { "true" } else { "false" }),
        Value::Number(number) => match (number.as_i64(), number.as_u64(), number.as_f64()) {
            (Some(integer), _, _) => out.push_str(&integer.to_string()),
            (_, Some(integer), _) => out.push_str(&integer.to_string()),
            (_, _, Some(float))
                if float.fract() == 0.0 && float.abs() < 9_007_199_254_740_992.0 =>
            {
                out.push_str(&format!("{float:.0}"));
            }
            _ => {
                return Err(Unreadable::Unsupported(
                    "a number with a fraction in a JSON literal",
                ));
            }
        },
        Value::String(string) => write_json_string(string, out),
        Value::Array(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut names: Vec<&String> = members.keys().collect();
            names.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            out.push('{');
            for (at, name) in names.into_iter().enumerate() {
                if at > 0 {
                    out.push(',');
                }
                write_json_string(name, out);
                out.push(':');
                write_canonical_json(&members[name.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_json_string(string: &str, out: &mut String) {
    out.push('"');
    for character in string.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control < ' ' => out.push_str(&format!("\\u{:04x}", u32::from(control))),
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_double_is_written_in_its_canonical_form() {
        for (value, written) in [
            (2.5, "2.5E0"),
            (0.0, "0.0E0"),
            (-0.0, "0.0E0"),
            (1e21, "1.0E21"),
            (1.5e-7, "1.5E-7"),
            (-12.75, "-1.275E1"),
            (0.1, "1.0E-1"),
            (123456.789, "1.23456789E5"),
        ] {
            assert_eq!(canonical_double(value), written, "{value}");
        }
    }

    #[test]
    fn a_json_literal_is_written_in_one_form() {
        let mut out = String::new();
        write_canonical_json(&json!([56.0, {"d": true, "10": null, "1": []}]), &mut out)
            .expect("canonical");
        assert_eq!(out, r#"[56,{"1":[],"10":null,"d":true}]"#);
        // UTF-16 code units, as RFC 8785 orders names: U+1F600 is a surrogate
        // pair below U+FFFD, though its UTF-8 bytes sort above.
        let mut out = String::new();
        write_canonical_json(&json!({"\u{fffd}": 1, "\u{1f600}": 2}), &mut out).expect("canonical");
        assert_eq!(out, "{\"\u{1f600}\":2,\"\u{fffd}\":1}");
        assert_eq!(
            write_canonical_json(&json!(2.5), &mut String::new()),
            Err(Unreadable::Unsupported(
                "a number with a fraction in a JSON literal"
            ))
        );
    }
}
