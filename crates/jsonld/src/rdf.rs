//! The RDF data model: quads over IRIs, blank nodes and literals.

pub const XSD_STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
pub const RDF_LANG_STRING: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString";

/// A subject or a graph name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Node {
    Iri(String),
    /// A blank node by its identifier, without the `_:` N-Quads writes first.
    Blank(String),
}

/// What a quad says of its subject.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Object {
    Node(Node),
    Literal(Literal),
}

/// A literal. The language is set for `rdf:langString` and only then.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Literal {
    pub lexical: String,
    pub datatype: String,
    pub language: Option<String>,
}

/// A triple and the graph it belongs to, `None` for the default graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Quad {
    pub subject: Node,
    pub predicate: String,
    pub object: Object,
    pub graph: Option<Node>,
}

/// Where a blank node sits in a quad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Position {
    Subject,
    Object,
    Graph,
}

impl Position {
    /// The letter RDFC-1.0 §4.7 hashes a position as.
    pub(crate) fn letter(self) -> char {
        match self {
            Self::Subject => 's',
            Self::Object => 'o',
            Self::Graph => 'g',
        }
    }
}

impl Quad {
    /// The blank nodes this quad mentions, each with its position.
    pub(crate) fn blank_nodes(&self) -> impl Iterator<Item = (&str, Position)> {
        let object = match &self.object {
            Object::Node(node) => Some(node),
            Object::Literal(_) => None,
        };
        [
            (Some(&self.subject), Position::Subject),
            (object, Position::Object),
            (self.graph.as_ref(), Position::Graph),
        ]
        .into_iter()
        .filter_map(|(node, position)| match node {
            Some(Node::Blank(label)) => Some((label.as_str(), position)),
            _ => None,
        })
    }
}
