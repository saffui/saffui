//! Expansion, JSON-LD 1.1 API §5.1 and §5.3: every key an IRI or a keyword,
//! every value in expanded form. Where the algorithm drops what it cannot
//! read, the document is refused instead; a null value says nothing, and is
//! the one thing let go.

use serde_json::{Map, Value, json};

use crate::Unreadable;
use crate::context::{ActiveContext, Contexts, process};
use crate::iri::{is_absolute_iri, is_blank_node_identifier, is_keyword};

pub(crate) struct Expander<'c> {
    pub contexts: &'c dyn Contexts,
}

impl Expander<'_> {
    /// §5.1.2: `element` expanded, `Value::Null` for nothing.
    pub(crate) fn expand(
        &self,
        active: &ActiveContext,
        active_property: Option<&str>,
        element: &Value,
        from_map: bool,
    ) -> Result<Value, Unreadable> {
        // 1, 3
        if element.is_null() {
            return Ok(Value::Null);
        }
        let property_scoped = active_property
            .and_then(|property| active.term(property))
            .and_then(|term| term.context.clone());

        match element {
            // 4
            Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                let Some(property) = active_property.filter(|property| *property != "@graph")
                else {
                    return Err(Unreadable::Dropped("a value outside any property"));
                };
                let active = match &property_scoped {
                    Some(scoped) => process(self.contexts, active, scoped, &[], false, true, true)?,
                    None => active.clone(),
                };
                expand_value(&active, property, element)
            }
            // 5
            Value::Array(items) => {
                let list = active_property
                    .and_then(|property| active.term(property))
                    .is_some_and(|term| term.container.list);
                let mut result = Vec::new();
                for item in items {
                    let mut expanded = self.expand(active, active_property, item, from_map)?;
                    if list && expanded.is_array() {
                        expanded = json!({ "@list": expanded });
                    }
                    match expanded {
                        Value::Array(expanded) => result.extend(expanded),
                        Value::Null => {}
                        other => result.push(other),
                    }
                }
                Ok(Value::Array(result))
            }
            Value::Object(element) => {
                self.expand_object(active, active_property, element, from_map, property_scoped)
            }
            Value::Null => Ok(Value::Null),
        }
    }

    fn expand_object(
        &self,
        active: &ActiveContext,
        active_property: Option<&str>,
        element: &Map<String, Value>,
        from_map: bool,
        property_scoped: Option<Value>,
    ) -> Result<Value, Unreadable> {
        // 7: a context a type stood up does not reach into another node.
        let mut active = active.clone();
        if let Some(previous) = active.previous.clone() {
            let keeps_value = element
                .keys()
                .any(|key| active.expand_iri(key, true).as_deref() == Some("@value"));
            let only_id = element.len() == 1
                && element
                    .keys()
                    .all(|key| active.expand_iri(key, true).as_deref() == Some("@id"));
            if !from_map && !keeps_value && !only_id {
                active = *previous;
            }
        }
        // 8
        if let Some(scoped) = &property_scoped {
            active = process(self.contexts, &active, scoped, &[], true, true, true)?;
        }
        // 9
        if let Some(local) = element.get("@context") {
            active = process(self.contexts, &active, local, &[], false, true, true)?;
        }
        // 10, 11: each type's scoped context, in the lexicographic order of keys
        // and of types.
        let type_scoped = active.clone();
        let mut type_keys: Vec<&String> = element
            .keys()
            .filter(|key| active.expand_iri(key, true).as_deref() == Some("@type"))
            .collect();
        type_keys.sort();
        for key in &type_keys {
            let mut types: Vec<&str> = match &element[key.as_str()] {
                Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                Value::String(single) => vec![single.as_str()],
                _ => Vec::new(),
            };
            types.sort_unstable();
            for name in types {
                if let Some(scoped) = type_scoped.term(name).and_then(|term| term.context.clone()) {
                    active = process(self.contexts, &active, &scoped, &[], false, false, true)?;
                }
            }
        }
        // 12
        let input_type = type_keys.first().and_then(|key| {
            let last = match &element[key.as_str()] {
                Value::Array(items) => items.last().and_then(Value::as_str),
                Value::String(single) => Some(single.as_str()),
                _ => None,
            }?;
            active.expand_iri(last, true)
        });

        // 13
        let mut result = Map::new();
        for (key, value) in element {
            if key == "@context" {
                continue;
            }
            let expanded_property = active
                .expand_iri(key, true)
                .filter(|expanded| expanded.contains(':') || is_keyword(expanded))
                .ok_or_else(|| Unreadable::Undefined(key.clone()))?;
            if is_keyword(&expanded_property) {
                self.expand_keyword(
                    &active,
                    &type_scoped,
                    active_property,
                    &expanded_property,
                    value,
                    input_type.as_deref(),
                    &mut result,
                )?;
                continue;
            }

            let term = active.term(key);
            let container = term.map(|term| term.container).unwrap_or_default();
            let mut expanded =
                if term.and_then(|term| term.type_mapping.as_deref()) == Some("@json") {
                    json!({ "@value": value, "@type": "@json" })
                } else if container.language && value.is_object() {
                    expand_language_map(&active, value)?
                } else if container.index && value.is_object() {
                    self.expand_index_map(&active, key, value)?
                } else {
                    self.expand(&active, Some(key), value, false)?
                };
            if expanded.is_null() {
                continue;
            }
            if container.list && !is_list_object(&expanded) {
                let items = match expanded {
                    Value::Array(items) => items,
                    single => vec![single],
                };
                expanded = json!({ "@list": items });
            }
            if container.graph {
                let items = match expanded {
                    Value::Array(items) => items,
                    single => vec![single],
                };
                expanded = Value::Array(
                    items
                        .into_iter()
                        .map(|item| json!({ "@graph": [item] }))
                        .collect(),
                );
            }
            add_value(&mut result, &expanded_property, expanded);
        }

        // 15
        if result.contains_key("@value") {
            if result.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "@direction" | "@index" | "@language" | "@type" | "@value"
                )
            }) || (result.contains_key("@type") && result.contains_key("@language"))
            {
                return Err(Unreadable::Invalid("invalid value object"));
            }
            let value = &result["@value"];
            if result.get("@type").and_then(Value::as_str) != Some("@json") {
                if value.is_null() || value.as_array().is_some_and(Vec::is_empty) {
                    return Ok(Value::Null);
                }
                if !value.is_string() && result.contains_key("@language") {
                    return Err(Unreadable::Invalid("invalid language-tagged value"));
                }
                if let Some(datatype) = result.get("@type")
                    && !datatype.as_str().is_some_and(is_absolute_iri)
                {
                    return Err(Unreadable::Invalid("invalid typed value"));
                }
            }
        } else if let Some(types) = result.get_mut("@type") {
            // 16
            if !types.is_array() {
                *types = Value::Array(vec![types.take()]);
            }
        } else if result.contains_key("@set") || result.contains_key("@list") {
            // 17
            if result.len() > 2 || (result.len() == 2 && !result.contains_key("@index")) {
                return Err(Unreadable::Invalid("invalid set or list object"));
            }
            if let Some(set) = result.remove("@set") {
                return self.drop_free_floating(active_property, set);
            }
        }
        // 18
        if result.len() == 1 && result.contains_key("@language") {
            return Err(Unreadable::Dropped("a language without a value"));
        }
        self.drop_free_floating(active_property, Value::Object(result))
    }

    /// 19: what would float free of any property is refused rather than
    /// dropped.
    fn drop_free_floating(
        &self,
        active_property: Option<&str>,
        result: Value,
    ) -> Result<Value, Unreadable> {
        if active_property.is_none_or(|property| property == "@graph")
            && let Value::Object(object) = &result
        {
            if object.is_empty() || object.contains_key("@value") || object.contains_key("@list") {
                return Err(Unreadable::Dropped("a value outside any property"));
            }
            if object.len() == 1 && object.contains_key("@id") {
                return Err(Unreadable::Dropped("a node that says nothing of itself"));
            }
        }
        Ok(result)
    }

    /// 13.4: a key that expands to a keyword.
    #[allow(clippy::too_many_arguments)]
    fn expand_keyword(
        &self,
        active: &ActiveContext,
        type_scoped: &ActiveContext,
        active_property: Option<&str>,
        keyword: &str,
        value: &Value,
        input_type: Option<&str>,
        result: &mut Map<String, Value>,
    ) -> Result<(), Unreadable> {
        if active_property == Some("@reverse") {
            return Err(Unreadable::Invalid("invalid reverse property map"));
        }
        if result.contains_key(keyword) && keyword != "@type" {
            return Err(Unreadable::Invalid("colliding keywords"));
        }
        let expanded = match keyword {
            "@id" => {
                let id = value
                    .as_str()
                    .ok_or(Unreadable::Invalid("invalid @id value"))?;
                Value::String(
                    active
                        .expand_iri(id, false)
                        .ok_or_else(|| Unreadable::Undefined(id.to_owned()))?,
                )
            }
            "@type" => {
                let names: Vec<&str> = match value {
                    Value::String(single) => vec![single.as_str()],
                    Value::Array(items) => items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .ok_or(Unreadable::Invalid("invalid type value"))
                        })
                        .collect::<Result<_, _>>()?,
                    _ => return Err(Unreadable::Invalid("invalid type value")),
                };
                let mut expanded = Vec::with_capacity(names.len());
                for name in names {
                    let iri = type_scoped
                        .expand_iri(name, true)
                        .ok_or_else(|| Unreadable::Undefined(name.to_owned()))?;
                    if !(is_absolute_iri(&iri) || is_blank_node_identifier(&iri) || iri == "@json")
                    {
                        return Err(Unreadable::NotAbsolute(name.to_owned()));
                    }
                    expanded.push(Value::String(iri));
                }
                let mut expanded = match value {
                    Value::String(_) if expanded.len() == 1 => expanded.remove(0),
                    _ => Value::Array(expanded),
                };
                if let Some(held) = result.remove("@type") {
                    let mut types = match held {
                        Value::Array(items) => items,
                        single => vec![single],
                    };
                    match expanded {
                        Value::Array(items) => types.extend(items),
                        single => types.push(single),
                    }
                    expanded = Value::Array(types);
                }
                expanded
            }
            "@graph" => match self.expand(active, Some("@graph"), value, false)? {
                Value::Array(items) => Value::Array(items),
                Value::Null => Value::Array(Vec::new()),
                single => Value::Array(vec![single]),
            },
            "@value" => {
                if input_type == Some("@json") {
                    value.clone()
                } else if value.is_array() || value.is_object() {
                    return Err(Unreadable::Invalid("invalid value object value"));
                } else {
                    value.clone()
                }
            }
            "@language" => {
                if !value.is_string() {
                    return Err(Unreadable::Invalid("invalid language-tagged string"));
                }
                value.clone()
            }
            "@index" => {
                if !value.is_string() {
                    return Err(Unreadable::Invalid("invalid @index value"));
                }
                value.clone()
            }
            "@list" => {
                if active_property.is_none_or(|property| property == "@graph") {
                    return Err(Unreadable::Dropped("a list outside any property"));
                }
                match self.expand(active, active_property, value, false)? {
                    Value::Array(items) => Value::Array(items),
                    Value::Null => Value::Array(Vec::new()),
                    single => Value::Array(vec![single]),
                }
            }
            "@set" => self.expand(active, active_property, value, false)?,
            "@included" => return Err(Unreadable::Unsupported("@included")),
            "@direction" => return Err(Unreadable::Unsupported("a base direction")),
            "@reverse" => return Err(Unreadable::Unsupported("a reverse property")),
            "@nest" => return Err(Unreadable::Unsupported("nesting")),
            _ => return Err(Unreadable::Invalid("a keyword out of place")),
        };
        result.insert(keyword.to_owned(), expanded);
        Ok(())
    }

    /// 13.8: an index map, each value carrying its index. The index itself is
    /// not part of the RDF a proof signs.
    fn expand_index_map(
        &self,
        active: &ActiveContext,
        key: &str,
        value: &Value,
    ) -> Result<Value, Unreadable> {
        let mut expanded = Vec::new();
        for (index, index_value) in value.as_object().into_iter().flatten() {
            let expanded_index = active.expand_iri(index, true);
            let items = match self.expand(active, Some(key), index_value, true)? {
                Value::Array(items) => items,
                Value::Null => Vec::new(),
                single => vec![single],
            };
            for mut item in items {
                if let Value::Object(object) = &mut item
                    && !object.contains_key("@index")
                    && expanded_index.as_deref() != Some("@none")
                {
                    object.insert("@index".to_owned(), Value::String(index.clone()));
                }
                expanded.push(item);
            }
        }
        Ok(Value::Array(expanded))
    }
}

/// 13.7: a language map, one value object per string.
fn expand_language_map(active: &ActiveContext, value: &Value) -> Result<Value, Unreadable> {
    let mut expanded = Vec::new();
    for (language, language_value) in value.as_object().into_iter().flatten() {
        let items: Vec<&Value> = match language_value {
            Value::Array(items) => items.iter().collect(),
            single => vec![single],
        };
        for item in items {
            if item.is_null() {
                continue;
            }
            let Value::String(string) = item else {
                return Err(Unreadable::Invalid("invalid language map value"));
            };
            let none = language == "@none"
                || active.expand_iri(language, true).as_deref() == Some("@none");
            expanded.push(if none {
                json!({ "@value": string })
            } else {
                json!({ "@value": string, "@language": language })
            });
        }
    }
    Ok(Value::Array(expanded))
}

/// §5.3.2
fn expand_value(
    active: &ActiveContext,
    property: &str,
    value: &Value,
) -> Result<Value, Unreadable> {
    let type_mapping = active
        .term(property)
        .and_then(|term| term.type_mapping.as_deref());
    if let (Some(mapping @ ("@id" | "@vocab")), Value::String(string)) = (type_mapping, value) {
        let iri = active
            .expand_iri(string, mapping == "@vocab")
            .ok_or_else(|| Unreadable::Undefined(string.clone()))?;
        return Ok(json!({ "@id": iri }));
    }
    let mut result = Map::from_iter([("@value".to_owned(), value.clone())]);
    if let Some(datatype) =
        type_mapping.filter(|mapping| !matches!(*mapping, "@id" | "@vocab" | "@none"))
    {
        result.insert("@type".to_owned(), Value::String(datatype.to_owned()));
    }
    Ok(Value::Object(result))
}

fn is_list_object(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key("@list"))
}

/// "Add value", with `as array`: the entry always an array.
fn add_value(result: &mut Map<String, Value>, key: &str, value: Value) {
    let entry = result
        .entry(key.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    let Value::Array(held) = entry else {
        return;
    };
    match value {
        Value::Array(items) => held.extend(items),
        single => held.push(single),
    }
}
