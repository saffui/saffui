use authz::rebac::{Rule, compile, parse};

/// The shape everything else is written against.
const EXAMPLE: &str = "
definition user {}

definition group {
    relation member: user | group#member
}

definition document {
    relation owner: user
    relation editor: user | group#member
    relation parent: document
    permission edit = editor + owner
    permission view = edit + view from parent
}
";

fn compiled(source: &str) -> authz::rebac::CompiledSchema {
    compile(&parse(source).expect("a schema that reads")).expect("a schema that compiles")
}

#[test]
fn a_schema_reads_and_compiles() {
    let schema = compiled(EXAMPLE);

    assert!(schema.has_type("user"));
    assert!(schema.has_type("document"));
    assert!(!schema.has_type("nothing"));
    assert_eq!(schema.format, authz::rebac::FORMAT);

    assert!(matches!(
        schema.lookup("document", "edit"),
        Some(Rule::Any { .. })
    ));
    assert!(matches!(
        schema.lookup("document", "owner"),
        Some(Rule::Direct { .. })
    ));
    assert_eq!(schema.lookup("document", "nothing"), None);
}

/// The declared subject types travel into the compiled form. Checked and then
/// dropped, the declaration is documentation: a walk expands whatever the store
/// returns for a relation, and an edge naming a type the schema never allowed
/// is indistinguishable from one it did.
#[test]
fn what_may_stand_in_a_relation_survives_compilation() {
    let schema = compiled(EXAMPLE);

    let Some(Rule::Direct { subjects }) = schema.lookup("document", "editor") else {
        panic!("editor is a relation");
    };
    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0].type_name, "user");
    assert_eq!(subjects[0].relation, None);
    assert_eq!(subjects[1].type_name, "group");
    assert_eq!(
        subjects[1].relation.as_deref(),
        Some("member"),
        "a userset lost the relation whose holders it names"
    );
}

/// A permission that computes from itself never finishes. It is decidable when
/// the schema is written, and left to the walk it becomes a cost paid on every
/// request and a denial nothing explains.
#[test]
fn a_permission_that_computes_from_itself_is_refused() {
    for source in [
        "definition d { permission p = p }",
        "definition d { permission p = q  permission q = p }",
        "definition d { permission p = q  permission q = r  permission r = p }",
    ] {
        let schema = parse(source).expect("it reads");
        let faults = compile(&schema).expect_err("a ring");
        assert!(
            faults.0.iter().any(|fault| fault.says.contains("itself")),
            "{source} compiled, and would have been walked forever"
        );
    }
}

/// An arrow leaves the object, so it cannot close a ring on it. Refusing one
/// would refuse the ordinary recursive shape every hierarchy is written with.
#[test]
fn a_permission_that_reaches_the_same_name_elsewhere_is_not_a_ring() {
    let schema = compiled(
        "
definition document {
    relation parent: document
    relation viewer: document
    permission view = viewer + view from parent
}
",
    );
    assert!(matches!(
        schema.lookup("document", "view"),
        Some(Rule::Any { .. })
    ));
}

/// Every fault, not the first. An author with ten mistakes is told about ten.
#[test]
fn a_schema_is_told_everything_that_is_wrong_with_it() {
    let schema = parse(
        "
definition d {
    relation r: ghost
    permission p = nowhere
    permission q = p from p
}
",
    )
    .expect("it reads");

    let faults = compile(&schema).expect_err("three faults");
    assert_eq!(
        faults.0.len(),
        3,
        "compiling stopped at the first fault: {faults}"
    );

    // And each one points at where it was written.
    let lines: Vec<u32> = faults.0.iter().map(|fault| fault.at.line).collect();
    assert_eq!(lines, vec![3, 4, 5], "a fault pointed at the wrong line");
}

/// A name that does not resolve is a missing name, not a ring, so the ring
/// check does not run until the names do resolve. Otherwise a typo reports
/// twice and the second report is nonsense.
#[test]
fn a_missing_name_is_reported_once() {
    let schema = parse("definition d { permission p = ghost }").expect("it reads");
    let faults = compile(&schema).expect_err("one fault");
    assert_eq!(faults.0.len(), 1);
    assert!(faults.0[0].says.contains("ghost"));
}

/// The two operators do not mix without parentheses. Any precedence between
/// them would be one this language invented, and a reader would have to know it
/// to read a rule that grants access.
#[test]
fn the_operators_do_not_mix_without_parentheses() {
    let refused = parse(
        "definition d { relation a: d  relation b: d  relation c: d \
                         permission p = a + b & c }",
    )
    .expect_err("mixed operators");
    assert!(format!("{refused}").contains("parentheses"));

    assert!(
        parse(
            "definition d { relation a: d  relation b: d  relation c: d \
               permission p = a + (b & c) }"
        )
        .is_ok(),
        "parenthesised, it reads"
    );
}

/// A fault says where it is. The reference parses positions and drops them, so
/// an author with a typo in one of forty definitions is told which name is
/// wrong and never where.
#[test]
fn a_refusal_says_where() {
    let refused = parse("definition d {\n    relation r\n}").expect_err("no colon");
    assert!(refused.to_string().contains("line 3"), "{refused}");
}

/// Running out of input is reported at the end of the input, not at whichever
/// token happened to be read last.
#[test]
fn running_out_of_input_is_reported_at_the_end() {
    let refused = parse("definition d {").expect_err("unterminated");
    let text = refused.to_string();
    assert!(text.contains("line 1"), "{text}");
    assert!(text.contains("column 15"), "{text}");
}

/// An empty intersection answers yes to everything, and the compiled form is
/// reloaded from a column, so a hand edited row must not be able to say one.
#[test]
fn an_empty_intersection_cannot_be_read_back() {
    let refused: Result<Rule, _> = serde_json::from_str(r#"{"kind": "all", "parts": []}"#);
    assert!(
        refused.is_err(),
        "an empty intersection deserialised, and it grants to everybody"
    );

    let one: Result<Rule, _> =
        serde_json::from_str(r#"{"kind": "all", "parts": [{"kind": "computed", "name": "a"}]}"#);
    assert!(one.is_err(), "a join of one is not a join");

    let two: Result<Rule, _> = serde_json::from_str(
        r#"{"kind": "all", "parts": [{"kind": "computed", "name": "a"},
                                     {"kind": "computed", "name": "b"}]}"#,
    );
    assert!(two.is_ok());
}

/// The compiled form round trips through the column it is stored in.
#[test]
fn the_compiled_form_survives_the_column() {
    let schema = compiled(EXAMPLE);
    let written = serde_json::to_value(&schema).expect("it serialises");
    let read: authz::rebac::CompiledSchema =
        serde_json::from_value(written).expect("it reads back");
    assert_eq!(read, schema);
    assert_eq!(read.format, authz::rebac::FORMAT);
}

/// Bounded before anything recurses on it.
#[test]
fn a_source_longer_than_the_bound_is_refused() {
    let long = "a".repeat(authz::rebac::parse::MAX_SOURCE + 1);
    assert!(matches!(
        parse(&long),
        Err(authz::rebac::Unreadable::TooLong { .. })
    ));

    let nested = format!(
        "definition d {{ relation a: d  permission p = {}a{} }}",
        "(".repeat(64),
        ")".repeat(64)
    );
    assert!(parse(&nested).is_err(), "nesting was unbounded");
}
