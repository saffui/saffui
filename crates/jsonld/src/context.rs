//! Contexts, JSON-LD 1.1 API §4.1 and §4.2: what each key of a document means.
//! A remote context is read from the contexts held here, never fetched while a
//! document is read.
//!
//! Left out, and refused where met: a base IRI (relative IRIs would resolve
//! against nothing a proof names), a vocabulary mapping (it would give meaning
//! to keys no context defines), a default language or direction, imported and
//! propagated contexts, reverse properties, nesting, `@prefix`, `@id` and
//! `@type` maps, and index mappings.

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::Unreadable;
use crate::iri::{has_keyword_form, is_absolute_iri, is_blank_node_identifier, is_keyword};

/// The contexts a document may name, by the URL it names them with.
pub trait Contexts {
    /// The context document held for `url`, or `None` when none is.
    fn document(&self, url: &str) -> Option<&Value>;
}

impl Contexts for HashMap<String, Value> {
    fn document(&self, url: &str) -> Option<&Value> {
        self.get(url)
    }
}

/// How many remote contexts one chain of references loads before the document
/// is refused: JSON-LD's context overflow.
const MOST_REMOTE_CONTEXTS: usize = 32;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Container {
    pub set: bool,
    pub list: bool,
    pub language: bool,
    pub index: bool,
    pub graph: bool,
}

/// A term definition: what one key means.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Term {
    /// An IRI, a blank node identifier or a keyword; `None` for a term defined
    /// as null, which maps to nothing.
    pub iri: Option<String>,
    pub prefix: bool,
    pub protected: bool,
    pub type_mapping: Option<String>,
    pub container: Container,
    /// A scoped context, as the definition gives it.
    pub context: Option<Value>,
}

impl Term {
    /// The same definition, whatever it says of protection.
    fn same_as(&self, other: &Term) -> bool {
        Term {
            protected: other.protected,
            ..self.clone()
        } == *other
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ActiveContext {
    pub terms: HashMap<String, Term>,
    /// The context a type-scoped context stood in front of, back in force for
    /// the next node object.
    pub previous: Option<Box<ActiveContext>>,
}

impl ActiveContext {
    /// §5.2.2 while a document is expanded: no local context to define terms
    /// from, no base IRI and no vocabulary mapping.
    pub(crate) fn expand_iri(&self, value: &str, vocab: bool) -> Option<String> {
        if is_keyword(value) {
            return Some(value.to_owned());
        }
        if has_keyword_form(value) {
            return None;
        }
        if let Some(term) = self.terms.get(value)
            && (term.iri.as_deref().is_some_and(is_keyword) || vocab)
        {
            return term.iri.clone();
        }
        if let Some(at) = colon_after_first(value) {
            let (prefix, suffix) = (&value[..at], &value[at + 1..]);
            if prefix == "_" || suffix.starts_with("//") {
                return Some(value.to_owned());
            }
            if let Some(Term {
                iri: Some(iri),
                prefix: true,
                ..
            }) = self.terms.get(prefix)
            {
                return Some(format!("{iri}{suffix}"));
            }
        }
        Some(value.to_owned())
    }

    pub(crate) fn term(&self, key: &str) -> Option<&Term> {
        self.terms.get(key)
    }
}

/// The position of the first colon after the first character.
fn colon_after_first(value: &str) -> Option<usize> {
    value.get(1..)?.find(':').map(|at| at + 1)
}

/// Whether a context document reads here: each term it defines well formed and
/// every context it names held, as a document naming it would read it.
pub fn check_context_document(document: &Value, contexts: &dyn Contexts) -> Result<(), Unreadable> {
    let local = document
        .as_object()
        .and_then(|document| document.get("@context"))
        .ok_or(Unreadable::Invalid("invalid remote context"))?;
    process(
        contexts,
        &ActiveContext::default(),
        local,
        &[],
        false,
        true,
        true,
    )
    .map(|_| ())
}

/// §4.1.2: `active` updated with `local`.
pub(crate) fn process(
    contexts: &dyn Contexts,
    active: &ActiveContext,
    local: &Value,
    remote: &[String],
    override_protected: bool,
    propagate: bool,
    validate_scoped: bool,
) -> Result<ActiveContext, Unreadable> {
    let mut result = active.clone();
    if let Value::Object(definition) = local
        && definition.contains_key("@propagate")
    {
        return Err(Unreadable::Unsupported("@propagate"));
    }
    if !propagate && result.previous.is_none() {
        result.previous = Some(Box::new(active.clone()));
    }
    let listed: Vec<&Value> = match local {
        Value::Array(items) => items.iter().collect(),
        single => vec![single],
    };
    for context in listed {
        match context {
            Value::Null => {
                if !override_protected && result.terms.values().any(|term| term.protected) {
                    return Err(Unreadable::Invalid("invalid context nullification"));
                }
                let previous = (!propagate).then(|| Box::new(result.clone()));
                result = ActiveContext {
                    terms: HashMap::new(),
                    previous,
                };
            }
            Value::String(url) => {
                if !is_absolute_iri(url) {
                    return Err(Unreadable::NotAbsolute(url.clone()));
                }
                if !validate_scoped && remote.contains(url) {
                    continue;
                }
                if remote.len() >= MOST_REMOTE_CONTEXTS {
                    return Err(Unreadable::Invalid("context overflow"));
                }
                let document = contexts
                    .document(url)
                    .ok_or_else(|| Unreadable::UnknownContext(url.clone()))?;
                let loaded = document
                    .as_object()
                    .and_then(|document| document.get("@context"))
                    .ok_or(Unreadable::Invalid("invalid remote context"))?;
                let mut chain = remote.to_vec();
                chain.push(url.clone());
                result = process(
                    contexts,
                    &result,
                    loaded,
                    &chain,
                    false,
                    true,
                    validate_scoped,
                )?;
            }
            Value::Object(definition) => {
                if let Some(version) = definition.get("@version")
                    && version.as_f64() != Some(1.1)
                {
                    return Err(Unreadable::Invalid("invalid @version value"));
                }
                if definition.contains_key("@import") {
                    return Err(Unreadable::Unsupported("@import"));
                }
                if definition.contains_key("@base") {
                    return Err(Unreadable::Unsupported("a base IRI"));
                }
                for (keyword, what) in [
                    ("@vocab", "a vocabulary mapping"),
                    ("@language", "a default language"),
                    ("@direction", "a default base direction"),
                ] {
                    if definition
                        .get(keyword)
                        .is_some_and(|value| !value.is_null())
                    {
                        return Err(Unreadable::Unsupported(what));
                    }
                }
                if definition
                    .get("@protected")
                    .is_some_and(|protected| !protected.is_boolean())
                {
                    return Err(Unreadable::Invalid("invalid @protected value"));
                }
                let mut definer = Definer {
                    contexts,
                    local: definition,
                    defined: HashMap::new(),
                    override_protected,
                    remote,
                };
                for key in definition.keys() {
                    if !matches!(
                        key.as_str(),
                        "@base"
                            | "@direction"
                            | "@import"
                            | "@language"
                            | "@propagate"
                            | "@protected"
                            | "@version"
                            | "@vocab"
                    ) {
                        definer.define(&mut result, key)?;
                    }
                }
            }
            _ => return Err(Unreadable::Invalid("invalid local context")),
        }
    }
    Ok(result)
}

/// The terms of one local context, defined in dependency order.
struct Definer<'a> {
    contexts: &'a dyn Contexts,
    local: &'a Map<String, Value>,
    /// Whether each term is defined (`true`) or being defined (`false`).
    defined: HashMap<String, bool>,
    override_protected: bool,
    remote: &'a [String],
}

impl Definer<'_> {
    /// §4.2.2
    fn define(&mut self, active: &mut ActiveContext, term: &str) -> Result<(), Unreadable> {
        match self.defined.get(term) {
            Some(true) => return Ok(()),
            Some(false) => return Err(Unreadable::Invalid("cyclic IRI mapping")),
            None => {}
        }
        if term.is_empty() {
            return Err(Unreadable::Invalid("invalid term definition"));
        }
        self.defined.insert(term.to_owned(), false);
        let value = self.local.get(term).cloned().unwrap_or(Value::Null);

        if term == "@type" {
            let only_set = value.as_object().is_some_and(|definition| {
                definition.iter().all(|(key, value)| {
                    (key == "@container" && value == "@set") || key == "@protected"
                })
            });
            if !only_set {
                return Err(Unreadable::Invalid("keyword redefinition"));
            }
        } else if is_keyword(term) {
            return Err(Unreadable::Invalid("keyword redefinition"));
        } else if has_keyword_form(term) {
            self.defined.insert(term.to_owned(), true);
            return Ok(());
        }

        let previous = active.terms.remove(term);
        let (value, simple) = match value {
            Value::Null => (Map::from_iter([("@id".to_owned(), Value::Null)]), false),
            Value::String(iri) => (
                Map::from_iter([("@id".to_owned(), Value::String(iri))]),
                true,
            ),
            Value::Object(definition) => (definition, false),
            _ => return Err(Unreadable::Invalid("invalid term definition")),
        };
        let mut definition = Term {
            iri: None,
            prefix: false,
            protected: matches!(self.local.get("@protected"), Some(Value::Bool(true))),
            type_mapping: None,
            container: Container::default(),
            context: None,
        };
        if let Some(protected) = value.get("@protected") {
            definition.protected = protected
                .as_bool()
                .ok_or(Unreadable::Invalid("invalid @protected value"))?;
        }
        if let Some(type_mapping) = value.get("@type") {
            let type_mapping = type_mapping
                .as_str()
                .ok_or(Unreadable::Invalid("invalid type mapping"))?;
            let expanded = self
                .expand(active, type_mapping, true)?
                .filter(|expanded| {
                    matches!(expanded.as_str(), "@id" | "@json" | "@none" | "@vocab")
                        || is_absolute_iri(expanded)
                })
                .ok_or(Unreadable::Invalid("invalid type mapping"))?;
            definition.type_mapping = Some(expanded);
        }
        if value.contains_key("@reverse") {
            return Err(Unreadable::Unsupported("a reverse property"));
        }

        match value.get("@id") {
            Some(id) if id.as_str() != Some(term) => match id {
                Value::Null => {}
                Value::String(id) => {
                    if !is_keyword(id) && has_keyword_form(id) {
                        self.defined.insert(term.to_owned(), true);
                        return Ok(());
                    }
                    let iri = self
                        .expand(active, id, true)?
                        .filter(|iri| {
                            is_keyword(iri) || is_absolute_iri(iri) || is_blank_node_identifier(iri)
                        })
                        .ok_or(Unreadable::Invalid("invalid IRI mapping"))?;
                    if iri == "@context" {
                        return Err(Unreadable::Invalid("invalid keyword alias"));
                    }
                    let colon_inside = term
                        .find(':')
                        .is_some_and(|at| at > 0 && at + 1 < term.len());
                    if colon_inside || term.contains('/') {
                        self.defined.insert(term.to_owned(), true);
                        if self.expand(active, term, true)?.as_deref() != Some(iri.as_str()) {
                            return Err(Unreadable::Invalid("invalid IRI mapping"));
                        }
                    }
                    if !term.contains([':', '/'])
                        && simple
                        && (iri.ends_with([':', '/', '?', '#', '[', ']', '@'])
                            || is_blank_node_identifier(&iri))
                    {
                        definition.prefix = true;
                    }
                    definition.iri = Some(iri);
                }
                _ => return Err(Unreadable::Invalid("invalid IRI mapping")),
            },
            _ => {
                if let Some(at) = colon_after_first(term) {
                    let (prefix, suffix) = (&term[..at], &term[at + 1..]);
                    if self.local.contains_key(prefix) {
                        self.define(active, prefix)?;
                    }
                    definition.iri = Some(
                        match active.terms.get(prefix).and_then(|held| held.iri.as_ref()) {
                            Some(iri) => format!("{iri}{suffix}"),
                            None => term.to_owned(),
                        },
                    );
                } else if term.contains('/') {
                    let iri = self
                        .expand(active, term, false)?
                        .filter(|iri| is_absolute_iri(iri))
                        .ok_or(Unreadable::Invalid("invalid IRI mapping"))?;
                    definition.iri = Some(iri);
                } else if term == "@type" {
                    definition.iri = Some("@type".to_owned());
                } else {
                    return Err(Unreadable::Invalid("invalid IRI mapping"));
                }
            }
        }

        if let Some(container) = value.get("@container") {
            definition.container = container_of(container)?;
        }
        if value.contains_key("@index") {
            return Err(Unreadable::Unsupported("an index mapping"));
        }
        if let Some(scoped) = value.get("@context") {
            process(
                self.contexts,
                active,
                scoped,
                self.remote,
                true,
                true,
                false,
            )
            .map_err(|error| match error {
                Unreadable::UnknownContext(_)
                | Unreadable::Unsupported(_)
                | Unreadable::NotAbsolute(_) => error,
                _ => Unreadable::Invalid("invalid scoped context"),
            })?;
            definition.context = Some(scoped.clone());
        }
        for (keyword, what) in [
            ("@language", "a language mapping"),
            ("@direction", "a direction mapping"),
            ("@nest", "nesting"),
            ("@prefix", "@prefix"),
        ] {
            if value.contains_key(keyword) {
                return Err(Unreadable::Unsupported(what));
            }
        }
        if value.keys().any(|key| {
            !matches!(
                key.as_str(),
                "@id" | "@container" | "@context" | "@protected" | "@type"
            )
        }) {
            return Err(Unreadable::Invalid("invalid term definition"));
        }

        if !self.override_protected
            && let Some(previous) = previous
            && previous.protected
        {
            if !definition.same_as(&previous) {
                return Err(Unreadable::Invalid("protected term redefinition"));
            }
            definition = previous;
        }
        active.terms.insert(term.to_owned(), definition);
        self.defined.insert(term.to_owned(), true);
        Ok(())
    }

    /// §5.2.2 while a local context is processed, defining the terms a value
    /// depends on first.
    fn expand(
        &mut self,
        active: &mut ActiveContext,
        value: &str,
        vocab: bool,
    ) -> Result<Option<String>, Unreadable> {
        if is_keyword(value) {
            return Ok(Some(value.to_owned()));
        }
        if has_keyword_form(value) {
            return Ok(None);
        }
        if self.local.contains_key(value) && self.defined.get(value) != Some(&true) {
            self.define(active, value)?;
        }
        if let Some(term) = active.terms.get(value)
            && (term.iri.as_deref().is_some_and(is_keyword) || vocab)
        {
            return Ok(term.iri.clone());
        }
        if let Some(at) = colon_after_first(value) {
            let (prefix, suffix) = (&value[..at], &value[at + 1..]);
            if prefix == "_" || suffix.starts_with("//") {
                return Ok(Some(value.to_owned()));
            }
            if self.local.contains_key(prefix) && self.defined.get(prefix) != Some(&true) {
                self.define(active, prefix)?;
            }
            if let Some(Term {
                iri: Some(iri),
                prefix: true,
                ..
            }) = active.terms.get(prefix)
            {
                return Ok(Some(format!("{iri}{suffix}")));
            }
        }
        Ok(Some(value.to_owned()))
    }
}

/// A container mapping this processor reads: `@set`, `@list`, `@language`,
/// `@index` and `@graph`, alone or with `@set`.
fn container_of(value: &Value) -> Result<Container, Unreadable> {
    let invalid = Unreadable::Invalid("invalid container mapping");
    let named: Vec<&str> = match value {
        Value::String(name) => vec![name.as_str()],
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().ok_or(invalid.clone()))
            .collect::<Result<_, _>>()?,
        _ => return Err(invalid),
    };
    let mut container = Container::default();
    for name in &named {
        match *name {
            "@set" => container.set = true,
            "@list" => container.list = true,
            "@language" => container.language = true,
            "@index" => container.index = true,
            "@graph" => container.graph = true,
            "@id" | "@type" => return Err(Unreadable::Unsupported("@id and @type maps")),
            _ => return Err(invalid),
        }
    }
    if container.graph && container.index {
        return Err(Unreadable::Unsupported("graph maps"));
    }
    let kinds = [
        container.list,
        container.language,
        container.index,
        container.graph,
    ]
    .into_iter()
    .filter(|&kind| kind)
    .count();
    if named.len() > 1 && (container.list || kinds > 1) {
        return Err(invalid);
    }
    Ok(container)
}
