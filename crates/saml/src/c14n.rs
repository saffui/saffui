use roxmltree::{Node, NodeId, NodeType};

/// Why an element could not be canonicalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Uncanonical {
    #[error("only an element can be canonicalized")]
    NotAnElement,
    #[error("the element to canonicalize is the one to omit")]
    OmittedApex,
    #[error("the element holds a processing instruction")]
    ProcessingInstruction,
}

/// The exclusive canonical form, without comments, of an element and its
/// descendants less the `omitted` subtree (Exclusive XML Canonicalization 1.0).
///
/// `omitted` is where an enveloped signature sits. `inclusive_prefixes` is the
/// InclusiveNamespaces PrefixList, `#default` standing for the default
/// namespace; those prefixes are rendered the way inclusive canonicalization
/// renders them. A processing instruction is refused rather than rendered: no
/// SAML party writes one inside what it signs, and it is one more construct
/// two implementations could read apart.
pub fn canonicalize_exclusive(
    apex: Node<'_, '_>,
    omitted: Option<NodeId>,
    inclusive_prefixes: &[&str],
) -> Result<Vec<u8>, Uncanonical> {
    if !apex.is_element() {
        return Err(Uncanonical::NotAnElement);
    }
    if omitted == Some(apex.id()) {
        return Err(Uncanonical::OmittedApex);
    }
    let mut written = Vec::new();
    let mut pending = vec![Visit::Open(apex)];
    while let Some(visit) = pending.pop() {
        match visit {
            Visit::Open(node) if omitted == Some(node.id()) => {}
            Visit::Open(node) => match node.node_type() {
                NodeType::Element => {
                    write_start_tag(&mut written, node, apex.id(), inclusive_prefixes);
                    pending.push(Visit::Close(node));
                    let children: Vec<_> = node.children().collect();
                    pending.extend(children.into_iter().rev().map(Visit::Open));
                }
                NodeType::Text => write_escaped_text(&mut written, node.text().unwrap_or_default()),
                NodeType::Comment => {}
                NodeType::PI => return Err(Uncanonical::ProcessingInstruction),
                NodeType::Root => return Err(Uncanonical::NotAnElement),
            },
            Visit::Close(node) => {
                written.extend_from_slice(b"</");
                written.extend_from_slice(qualified_name_of(node).as_bytes());
                written.push(b'>');
            }
        }
    }
    Ok(written)
}

enum Visit<'a, 'input> {
    Open(Node<'a, 'input>),
    Close(Node<'a, 'input>),
}

fn write_start_tag(
    written: &mut Vec<u8>,
    element: Node<'_, '_>,
    apex: NodeId,
    inclusive_prefixes: &[&str],
) {
    written.push(b'<');
    written.extend_from_slice(qualified_name_of(element).as_bytes());
    for (prefix, uri) in rendered_namespaces(element, apex, inclusive_prefixes) {
        if prefix.is_empty() {
            written.extend_from_slice(b" xmlns=\"");
        } else {
            written.extend_from_slice(b" xmlns:");
            written.extend_from_slice(prefix.as_bytes());
            written.extend_from_slice(b"=\"");
        }
        write_escaped_attribute(written, uri);
        written.push(b'"');
    }
    let source = element.document().input_text();
    let mut attributes: Vec<_> = element.attributes().collect();
    attributes.sort_by(|left, right| {
        (left.namespace().unwrap_or_default(), left.name())
            .cmp(&(right.namespace().unwrap_or_default(), right.name()))
    });
    for attribute in attributes {
        written.push(b' ');
        written.extend_from_slice(source[attribute.range_qname()].as_bytes());
        written.extend_from_slice(b"=\"");
        write_escaped_attribute(written, attribute.value());
        written.push(b'"');
    }
    written.push(b'>');
}

/// The namespace declarations an element's start tag carries, sorted by prefix.
///
/// A prefix the element or one of its attributes uses is declared unless the
/// nearest output ancestor using it bound it to the same value; a listed prefix
/// is declared unless the parent in the output binds it the same way. The
/// empty default declaration follows from the same comparison.
fn rendered_namespaces<'a>(
    element: Node<'a, '_>,
    apex: NodeId,
    inclusive_prefixes: &[&str],
) -> Vec<(&'a str, &'a str)> {
    let listed = |prefix: &str| {
        inclusive_prefixes.iter().any(|held| {
            if prefix.is_empty() {
                *held == "#default"
            } else {
                *held == prefix
            }
        })
    };
    let utilized = visibly_utilized_prefixes(element);
    let mut candidates = utilized.clone();
    candidates.extend(
        element
            .namespaces()
            .filter_map(|namespace| namespace.name())
            .filter(|prefix| listed(prefix)),
    );
    if listed("") {
        candidates.push("");
    }
    candidates.sort_unstable();
    candidates.dedup();

    let parent = if element.id() == apex {
        None
    } else {
        element.parent_element()
    };
    let mut rendered = Vec::new();
    for prefix in candidates {
        let bound = binding_of(element, prefix);
        let compared = if listed(prefix) {
            parent
        } else if utilized.contains(&prefix) {
            nearest_output_ancestor_utilizing(element, apex, prefix)
        } else {
            continue;
        };
        let declared = match compared {
            Some(ancestor) => binding_of(ancestor, prefix) != bound,
            None => bound.is_some(),
        };
        if declared {
            rendered.push((prefix, bound.unwrap_or_default()));
        }
    }
    rendered
}

fn nearest_output_ancestor_utilizing<'a, 'input>(
    element: Node<'a, 'input>,
    apex: NodeId,
    prefix: &str,
) -> Option<Node<'a, 'input>> {
    if element.id() == apex {
        return None;
    }
    for ancestor in element.ancestors().skip(1).filter(|node| node.is_element()) {
        if visibly_utilized_prefixes(ancestor).contains(&prefix) {
            return Some(ancestor);
        }
        if ancestor.id() == apex {
            return None;
        }
    }
    None
}

/// The prefixes an element's own name and its attributes' names use, the
/// empty one standing for the default namespace of an unprefixed element.
fn visibly_utilized_prefixes<'input>(element: Node<'_, 'input>) -> Vec<&'input str> {
    let source = element.document().input_text();
    let mut prefixes = vec![prefix_of(qualified_name_of(element))];
    prefixes.extend(
        element
            .attributes()
            .map(|attribute| prefix_of(&source[attribute.range_qname()]))
            .filter(|prefix| !prefix.is_empty()),
    );
    prefixes.sort_unstable();
    prefixes.dedup();
    prefixes
}

/// What a prefix is bound to where the element stands; an undeclared default
/// reads as an empty name, which binds nothing.
fn binding_of<'a>(element: Node<'a, '_>, prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() {
        element.default_namespace().filter(|uri| !uri.is_empty())
    } else {
        element.lookup_namespace_uri(Some(prefix))
    }
}

/// The element's name as its start tag spells it, prefix included.
fn qualified_name_of<'input>(element: Node<'_, 'input>) -> &'input str {
    let source = element.document().input_text();
    let tag = &source[element.range().start + 1..];
    let end = tag
        .find(|held: char| held.is_ascii_whitespace() || held == '/' || held == '>')
        .unwrap_or(tag.len());
    &tag[..end]
}

fn prefix_of(qualified: &str) -> &str {
    qualified.split_once(':').map_or("", |(prefix, _)| prefix)
}

fn write_escaped_text(written: &mut Vec<u8>, text: &str) {
    for byte in text.bytes() {
        match byte {
            b'&' => written.extend_from_slice(b"&amp;"),
            b'<' => written.extend_from_slice(b"&lt;"),
            b'>' => written.extend_from_slice(b"&gt;"),
            b'\r' => written.extend_from_slice(b"&#xD;"),
            other => written.push(other),
        }
    }
}

fn write_escaped_attribute(written: &mut Vec<u8>, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'&' => written.extend_from_slice(b"&amp;"),
            b'<' => written.extend_from_slice(b"&lt;"),
            b'"' => written.extend_from_slice(b"&quot;"),
            b'\t' => written.extend_from_slice(b"&#x9;"),
            b'\n' => written.extend_from_slice(b"&#xA;"),
            b'\r' => written.extend_from_slice(b"&#xD;"),
            other => written.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Uncanonical, canonicalize_exclusive};
    use crate::xml::{Limits, read_message};
    use roxmltree::{Document, Node};

    struct Row {
        rule: &'static str,
        document: &'static str,
        element: &'static str,
        omitted: Option<&'static str>,
        prefixes: &'static [&'static str],
        expected: &'static str,
    }

    fn element_named<'a, 'input>(document: &'a Document<'input>, name: &str) -> Node<'a, 'input> {
        document
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == name)
            .expect("the element")
    }

    fn canonical(
        text: &str,
        element: &str,
        omitted: Option<&str>,
        prefixes: &[&str],
    ) -> Result<String, Uncanonical> {
        let document = read_message(text, Limits::MESSAGE).expect("a well-formed message");
        let omitted = omitted.map(|name| element_named(&document, name).id());
        canonicalize_exclusive(element_named(&document, element), omitted, prefixes)
            .map(|written| String::from_utf8(written).expect("UTF-8"))
    }

    fn assert_forms(rows: &[Row]) {
        for row in rows {
            assert_eq!(
                canonical(row.document, row.element, row.omitted, row.prefixes).as_deref(),
                Ok(row.expected),
                "{}",
                row.rule
            );
        }
    }

    /// Each expected form was written by libxml2's exclusive canonicalizer,
    /// through lxml, from the same document, element, omission and prefix
    /// list; each row names the rule it holds.
    #[test]
    fn each_canonical_form_matches_libxml2() {
        let rows = [
            Row {
                rule: "only the namespaces an element uses are declared on it",
                document: r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r"><saml:Assertion ID="a" Version="2.0"><saml:Issuer>idp</saml:Issuer></saml:Assertion></samlp:Response>"#,
                element: "Assertion",
                omitted: None,
                prefixes: &[],
                expected: r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a" Version="2.0"><saml:Issuer>idp</saml:Issuer></saml:Assertion>"#,
            },
            Row {
                rule: "an omitted signature leaves the whitespace around it",
                document: "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" ID=\"a\">\n  <saml:Issuer>idp</saml:Issuer>\n  <ds:Signature><ds:SignedInfo/></ds:Signature>\n  <saml:Subject/>\n</saml:Assertion>",
                element: "Assertion",
                omitted: Some("Signature"),
                prefixes: &[],
                expected: "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"a\">\n  <saml:Issuer>idp</saml:Issuer>\n  \n  <saml:Subject></saml:Subject>\n</saml:Assertion>",
            },
            Row {
                rule: "declarations sort by prefix, attributes by namespace then name",
                document: r#"<r xmlns:z="urn:a" xmlns:b="urn:b" b:y="2" c="3" z:x="1" a="4"/>"#,
                element: "r",
                omitted: None,
                prefixes: &[],
                expected: r#"<r xmlns:b="urn:b" xmlns:z="urn:a" a="4" c="3" z:x="1" b:y="2"></r>"#,
            },
            Row {
                rule: "attribute values and text are escaped their own ways",
                document: r##"<r a="&amp;&lt;&quot;&#9;&#10;&#13;&gt;">&amp;&lt;&gt;&#13;"'<![CDATA[<cdata&>]]></r>"##,
                element: "r",
                omitted: None,
                prefixes: &[],
                expected: r##"<r a="&amp;&lt;&quot;&#x9;&#xA;&#xD;>">&amp;&lt;&gt;&#xD;"'&lt;cdata&amp;&gt;</r>"##,
            },
            Row {
                rule: "an empty default is declared under a default",
                document: r#"<a xmlns="urn:d"><b xmlns=""><c/></b></a>"#,
                element: "a",
                omitted: None,
                prefixes: &[],
                expected: r#"<a xmlns="urn:d"><b xmlns=""><c></c></b></a>"#,
            },
            Row {
                rule: "an empty default is not declared with nothing above it",
                document: r#"<a xmlns="urn:d"><b xmlns=""><c/></b></a>"#,
                element: "b",
                omitted: None,
                prefixes: &[],
                expected: "<b><c></c></b>",
            },
            Row {
                rule: "a listed prefix is declared on the apex though unused",
                document: r#"<r xmlns="urn:d" xmlns:xs="urn:xs" xmlns:u="urn:u"><e><f/></e></r>"#,
                element: "e",
                omitted: None,
                prefixes: &["xs", "#default"],
                expected: r#"<e xmlns="urn:d" xmlns:xs="urn:xs"><f></f></e>"#,
            },
            Row {
                rule: "a prefix bound anew is declared again",
                document: r#"<one:x xmlns:one="urn:1"><one:y xmlns:one="urn:2"><one:z/></one:y></one:x>"#,
                element: "x",
                omitted: None,
                prefixes: &[],
                expected: r#"<one:x xmlns:one="urn:1"><one:y xmlns:one="urn:2"><one:z></one:z></one:y></one:x>"#,
            },
            Row {
                rule: "a prefix only an attribute uses is declared on its element",
                document: r#"<r xmlns:a="urn:a"><e a:k="v"><f/></e></r>"#,
                element: "e",
                omitted: None,
                prefixes: &[],
                expected: r#"<e xmlns:a="urn:a" a:k="v"><f></f></e>"#,
            },
            Row {
                rule: "comments are dropped",
                document: "<r><!-- c --><e>t<!-- d --></e></r>",
                element: "r",
                omitted: None,
                prefixes: &[],
                expected: "<r><e>t</e></r>",
            },
            Row {
                rule: "the same binding is not declared twice",
                document: r#"<saml:A xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:B xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></saml:A>"#,
                element: "A",
                omitted: None,
                prefixes: &[],
                expected: r#"<saml:A xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:B></saml:B></saml:A>"#,
            },
            Row {
                rule: "an unused prefix waits for the element that uses it",
                document: r#"<p:r xmlns:p="urn:p" xmlns:q="urn:q"><e><q:f/></e></p:r>"#,
                element: "r",
                omitted: None,
                prefixes: &[],
                expected: r#"<p:r xmlns:p="urn:p"><e><q:f xmlns:q="urn:q"></q:f></e></p:r>"#,
            },
            Row {
                rule: "xml attributes are not inherited",
                document: r#"<r xml:lang="en"><e xml:space="preserve"/></r>"#,
                element: "e",
                omitted: None,
                prefixes: &[],
                expected: r#"<e xml:space="preserve"></e>"#,
            },
            Row {
                rule: "a default under a prefixed element is declared where it is used",
                document: r#"<p:r xmlns:p="urn:p" xmlns="urn:d"><e/></p:r>"#,
                element: "r",
                omitted: None,
                prefixes: &[],
                expected: r#"<p:r xmlns:p="urn:p"><e xmlns="urn:d"></e></p:r>"#,
            },
            Row {
                rule: "a listed default that is not in scope declares nothing",
                document: r#"<p:r xmlns:p="urn:p"><e/></p:r>"#,
                element: "r",
                omitted: None,
                prefixes: &["#default"],
                expected: r#"<p:r xmlns:p="urn:p"><e></e></p:r>"#,
            },
            Row {
                rule: "a listed prefix bound anew below is declared again",
                document: r#"<r xmlns:u="urn:u"><e xmlns:u="urn:v"><f/></e></r>"#,
                element: "r",
                omitted: None,
                prefixes: &["u"],
                expected: r#"<r xmlns:u="urn:u"><e xmlns:u="urn:v"><f></f></e></r>"#,
            },
        ];
        assert_forms(&rows);
    }

    /// A listed default and a listed `xml` prefix follow the inclusive rules.
    /// lxml drops `#default` from a prefix list before libxml2 sees it, so these
    /// forms were written by libxml2 through its C API instead.
    #[test]
    fn listed_prefixes_render_as_libxml2_renders_them() {
        assert_forms(&[
            Row {
                rule: "the xml prefix is never declared, even listed",
                document: r#"<r xml:lang="en"><e xml:space="preserve"/></r>"#,
                element: "r",
                omitted: None,
                prefixes: &["xml"],
                expected: r#"<r xml:lang="en"><e xml:space="preserve"></e></r>"#,
            },
            Row {
                rule: "a listed default is declared on a prefixed apex that does not use it",
                document: r#"<p:e xmlns:p="urn:p" xmlns="urn:d"><p:f/></p:e>"#,
                element: "e",
                omitted: None,
                prefixes: &["#default"],
                expected: r#"<p:e xmlns="urn:d" xmlns:p="urn:p"><p:f></p:f></p:e>"#,
            },
            Row {
                rule: "a listed default bound anew below is declared again",
                document: r#"<p:r xmlns:p="urn:p" xmlns="urn:d"><p:e xmlns="urn:e"/></p:r>"#,
                element: "r",
                omitted: None,
                prefixes: &["#default"],
                expected: r#"<p:r xmlns="urn:d" xmlns:p="urn:p"><p:e xmlns="urn:e"></p:e></p:r>"#,
            },
            Row {
                rule: "a listed default undeclared below is declared empty",
                document: r#"<p:r xmlns:p="urn:p" xmlns="urn:d"><p:e xmlns=""/></p:r>"#,
                element: "r",
                omitted: None,
                prefixes: &["#default"],
                expected: r#"<p:r xmlns="urn:d" xmlns:p="urn:p"><p:e xmlns=""></p:e></p:r>"#,
            },
        ]);
    }

    /// A processing instruction inside the element is refused, and neither a
    /// node that is not an element nor an element that is itself omitted is
    /// canonicalized.
    #[test]
    fn instructions_and_impossible_requests_are_refused() {
        assert_eq!(
            canonical("<r><e><?pi data?></e></r>", "r", None, &[]),
            Err(Uncanonical::ProcessingInstruction)
        );
        assert_eq!(
            canonical("<r><e/></r>", "e", Some("e"), &[]),
            Err(Uncanonical::OmittedApex)
        );
        let document = read_message("<r>text</r>", Limits::MESSAGE).expect("a message");
        let text = document.root_element().first_child().expect("the text");
        assert_eq!(
            canonicalize_exclusive(text, None, &[]),
            Err(Uncanonical::NotAnElement)
        );
    }
}
