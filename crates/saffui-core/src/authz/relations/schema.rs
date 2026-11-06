//! The schema of relations: the types of objects a realm has, the relations
//! a subject may stand in to an object of each type, and the permissions
//! computed from them.
//!
//! ```text
//! schema      := definition*
//! definition  := "definition" NAME "{" (relation | permission)* "}"
//! relation    := "relation" NAME ":" subject ("|" subject)*
//! subject     := NAME ("#" NAME)?
//! permission  := "permission" NAME "=" expression
//! expression  := term ("+" term)* | term ("&" term)*
//! term        := NAME ("from" NAME)? | "(" expression ")"
//! ```
//!
//! In `view from parent`, `parent` is a relation of the object and `view` a
//! member of every object it names. A sum and an intersection do not mix
//! without parentheses. A line that starts with `//` is a comment.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::clients::is_unshowable;

/// The version of the compiled form. A form of another version is compiled
/// again from its source, never read.
pub const COMPILED_VERSION: u32 = 1;

/// The longest source a realm keeps, in bytes.
pub const SCHEMA_MAX_BYTES: usize = 64 * 1024;

/// How deep parentheses nest in a permission. The parser walks them on the
/// stack of the thread that compiles: deeper is refused, never walked.
pub const MAX_NESTING: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledSchema {
    pub version: u32,
    pub types: BTreeMap<String, ObjectType>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectType {
    /// Each relation, and the subjects it admits: nothing else is walked.
    pub relations: BTreeMap<String, Vec<AllowedSubject>>,
    pub permissions: BTreeMap<String, Rule>,
}

/// A subject a relation admits: an object of a type, or the members of a
/// member of an object of a type (`group#member`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AllowedSubject {
    pub object_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rule {
    /// Another member of the same object.
    Computed {
        member: String,
    },
    /// A member of each object that a relation of this one names.
    Arrow {
        relation: String,
        member: String,
    },
    Union {
        rules: Vec<Rule>,
    },
    Intersection {
        rules: Vec<Rule>,
    },
}

/// What a name means on a type.
pub enum MemberKind<'a> {
    Relation(&'a [AllowedSubject]),
    Permission(&'a Rule),
}

impl CompiledSchema {
    #[must_use]
    pub fn find_member(&self, object_type: &str, member: &str) -> Option<MemberKind<'_>> {
        let found = self.types.get(object_type)?;
        if let Some(allowed) = found.relations.get(member) {
            return Some(MemberKind::Relation(allowed));
        }
        found.permissions.get(member).map(MemberKind::Permission)
    }
}

/// A fault of a schema, at the line it is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaFault {
    pub line: usize,
    pub message: String,
}

/// Whether a text may name a type or a member: a lowercase letter, then up
/// to 63 lowercase letters, digits or underscores.
#[must_use]
pub fn is_schema_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && text.len() <= 64
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Name(String),
    Mark(char),
}

#[derive(Clone, Debug)]
struct Lexeme {
    token: Token,
    line: usize,
}

fn read_lexemes(source: &str) -> Result<Vec<Lexeme>, SchemaFault> {
    let mut lexemes = Vec::new();
    for (index, text) in source.lines().enumerate() {
        let line = index + 1;
        // A comment is read by whoever reviews the schema: what cannot be
        // shown, there too, could make a line read as another.
        if let Some(unshowable) = text.chars().find(|&character| is_unshowable(character)) {
            return Err(SchemaFault {
                line,
                message: format!("U+{:04X} cannot be shown", u32::from(unshowable)),
            });
        }
        let text = text.split_once("//").map_or(text, |(code, _)| code);
        let mut characters = text.char_indices().peekable();
        while let Some((start, character)) = characters.next() {
            if character.is_whitespace() {
                continue;
            }
            if "{}():|#+&=".contains(character) {
                lexemes.push(Lexeme {
                    token: Token::Mark(character),
                    line,
                });
                continue;
            }
            if !(character.is_ascii_alphanumeric() || character == '_') {
                return Err(SchemaFault {
                    line,
                    // Only a character that can be shown gets here.
                    message: format!("`{character}` has no meaning here"),
                });
            }
            let mut end = start + character.len_utf8();
            while let Some(&(next, following)) = characters.peek() {
                if following.is_ascii_alphanumeric() || following == '_' {
                    end = next + following.len_utf8();
                    characters.next();
                } else {
                    break;
                }
            }
            lexemes.push(Lexeme {
                token: Token::Name(text[start..end].to_owned()),
                line,
            });
        }
    }
    Ok(lexemes)
}

#[derive(Debug)]
enum Expression {
    Member {
        name: String,
        line: usize,
    },
    Arrow {
        member: String,
        relation: String,
        line: usize,
    },
    Union(Vec<Expression>),
    Intersection(Vec<Expression>),
}

#[derive(Debug)]
enum Declaration {
    Relation {
        name: String,
        line: usize,
        subjects: Vec<(String, Option<String>, usize)>,
    },
    Permission {
        name: String,
        line: usize,
        expression: Expression,
    },
}

#[derive(Debug)]
struct Definition {
    name: String,
    line: usize,
    declarations: Vec<Declaration>,
}

struct Parser {
    lexemes: Vec<Lexeme>,
    at: usize,
    /// How many parentheses are open where the parser stands.
    nesting: usize,
}

type Parsed<T> = Result<T, SchemaFault>;

impl Parser {
    fn peek(&self) -> Option<&Lexeme> {
        self.lexemes.get(self.at)
    }

    fn line(&self) -> usize {
        self.peek()
            .or_else(|| self.lexemes.last())
            .map_or(1, |lexeme| lexeme.line)
    }

    fn fault(&self, message: impl Into<String>) -> SchemaFault {
        SchemaFault {
            line: self.line(),
            message: message.into(),
        }
    }

    fn take_name(&mut self, what: &str) -> Parsed<(String, usize)> {
        match self.peek().cloned() {
            Some(Lexeme {
                token: Token::Name(name),
                line,
            }) => {
                self.at += 1;
                Ok((name, line))
            }
            _ => Err(self.fault(format!("{what} is expected"))),
        }
    }

    fn take_mark(&mut self, mark: char) -> Parsed<()> {
        if self.is_mark(mark) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.fault(format!("`{mark}` is expected")))
        }
    }

    fn is_mark(&self, mark: char) -> bool {
        matches!(self.peek(), Some(Lexeme { token: Token::Mark(found), .. }) if *found == mark)
    }

    fn is_word(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Lexeme { token: Token::Name(found), .. }) if found == word)
    }

    fn read_definition(&mut self) -> Parsed<Definition> {
        let (keyword, _) = self.take_name("`definition`")?;
        if keyword != "definition" {
            self.at -= 1;
            return Err(self.fault("`definition` is expected"));
        }
        let (name, line) = self.take_name("the name of a type")?;
        self.take_mark('{')?;
        let mut declarations = Vec::new();
        while !self.is_mark('}') {
            if self.peek().is_none() {
                return Err(self.fault("`}` is expected"));
            }
            declarations.push(self.read_declaration()?);
        }
        self.take_mark('}')?;
        Ok(Definition {
            name,
            line,
            declarations,
        })
    }

    fn read_declaration(&mut self) -> Parsed<Declaration> {
        let (keyword, _) = self.take_name("`relation` or `permission`")?;
        match keyword.as_str() {
            "relation" => {
                let (name, line) = self.take_name("the name of a relation")?;
                self.take_mark(':')?;
                let mut subjects = vec![self.read_subject()?];
                while self.is_mark('|') {
                    self.at += 1;
                    subjects.push(self.read_subject()?);
                }
                Ok(Declaration::Relation {
                    name,
                    line,
                    subjects,
                })
            }
            "permission" => {
                let (name, line) = self.take_name("the name of a permission")?;
                self.take_mark('=')?;
                let expression = self.read_expression()?;
                Ok(Declaration::Permission {
                    name,
                    line,
                    expression,
                })
            }
            _ => {
                self.at -= 1;
                Err(self.fault("`relation` or `permission` is expected"))
            }
        }
    }

    fn read_subject(&mut self) -> Parsed<(String, Option<String>, usize)> {
        let (object_type, line) = self.take_name("the type of a subject")?;
        if self.is_mark('#') {
            self.at += 1;
            let (member, _) = self.take_name("a member after `#`")?;
            return Ok((object_type, Some(member), line));
        }
        Ok((object_type, None, line))
    }

    fn read_expression(&mut self) -> Parsed<Expression> {
        let first = self.read_term()?;
        let joined = if self.is_mark('+') {
            '+'
        } else if self.is_mark('&') {
            '&'
        } else {
            return Ok(first);
        };
        let mut terms = vec![first];
        while self.is_mark(joined) {
            self.at += 1;
            terms.push(self.read_term()?);
        }
        if self.is_mark('+') || self.is_mark('&') {
            return Err(self.fault("`+` and `&` do not mix without parentheses"));
        }
        Ok(if joined == '+' {
            Expression::Union(terms)
        } else {
            Expression::Intersection(terms)
        })
    }

    fn read_term(&mut self) -> Parsed<Expression> {
        if self.is_mark('(') {
            if self.nesting == MAX_NESTING {
                return Err(self.fault(format!("parentheses nest at most {MAX_NESTING} deep")));
            }
            self.at += 1;
            self.nesting += 1;
            let inner = self.read_expression()?;
            self.take_mark(')')?;
            self.nesting -= 1;
            return Ok(inner);
        }
        let (name, line) = self.take_name("a member")?;
        if self.is_word("from") {
            self.at += 1;
            let (relation, _) = self.take_name("a relation after `from`")?;
            return Ok(Expression::Arrow {
                member: name,
                relation,
                line,
            });
        }
        Ok(Expression::Member { name, line })
    }

    /// Skips to the next `definition` at the top level, after a fault.
    fn skip_to_next_definition(&mut self) {
        self.at += 1;
        self.nesting = 0;
        let mut depth = 0_usize;
        while let Some(lexeme) = self.peek() {
            match &lexeme.token {
                Token::Mark('{') => depth += 1,
                Token::Mark('}') => depth = depth.saturating_sub(1),
                Token::Name(name) if name == "definition" && depth == 0 => return,
                _ => {}
            }
            self.at += 1;
        }
    }
}

struct Compiler<'a> {
    definitions: &'a [Definition],
    faults: Vec<SchemaFault>,
}

impl Compiler<'_> {
    fn note(&mut self, line: usize, message: String) {
        self.faults.push(SchemaFault { line, message });
    }

    fn find(&self, object_type: &str) -> Option<&Definition> {
        self.definitions
            .iter()
            .find(|definition| definition.name == object_type)
    }

    fn has_member(definition: &Definition, member: &str) -> bool {
        definition
            .declarations
            .iter()
            .any(|declaration| match declaration {
                Declaration::Relation { name, .. } | Declaration::Permission { name, .. } => {
                    name == member
                }
            })
    }

    fn find_relation<'d>(
        definition: &'d Definition,
        relation: &str,
    ) -> Option<&'d [(String, Option<String>, usize)]> {
        definition
            .declarations
            .iter()
            .find_map(|declaration| match declaration {
                Declaration::Relation { name, subjects, .. } if name == relation => {
                    Some(subjects.as_slice())
                }
                _ => None,
            })
    }

    fn compile_expression(&mut self, definition: &Definition, expression: &Expression) -> Rule {
        match expression {
            Expression::Member { name, line } => {
                if !Self::has_member(definition, name) {
                    self.note(
                        *line,
                        format!("`{}` has no member `{name}`", definition.name),
                    );
                }
                Rule::Computed {
                    member: name.clone(),
                }
            }
            Expression::Arrow {
                member,
                relation,
                line,
            } => {
                match Self::find_relation(definition, relation) {
                    None => self.note(
                        *line,
                        format!("`{}` has no relation `{relation}` to walk", definition.name),
                    ),
                    Some(subjects) => {
                        let objects: Vec<&String> = subjects
                            .iter()
                            .filter(|(_, member, _)| member.is_none())
                            .map(|(object_type, _, _)| object_type)
                            .collect();
                        if objects.is_empty() {
                            self.note(*line, format!("`{relation}` names no object to walk to"));
                        }
                        for object_type in objects {
                            let lacks = self
                                .find(object_type)
                                .is_some_and(|target| !Self::has_member(target, member));
                            if lacks {
                                self.note(
                                    *line,
                                    format!("`{object_type}` has no member `{member}`"),
                                );
                            }
                        }
                    }
                }
                Rule::Arrow {
                    relation: relation.clone(),
                    member: member.clone(),
                }
            }
            Expression::Union(terms) => Rule::Union {
                rules: terms
                    .iter()
                    .map(|term| self.compile_expression(definition, term))
                    .collect(),
            },
            Expression::Intersection(terms) => Rule::Intersection {
                rules: terms
                    .iter()
                    .map(|term| self.compile_expression(definition, term))
                    .collect(),
            },
        }
    }

    fn compile_type(&mut self, definition: &Definition) -> ObjectType {
        let mut compiled = ObjectType::default();
        let mut seen = BTreeSet::new();
        for declaration in &definition.declarations {
            let (name, line) = match declaration {
                Declaration::Relation { name, line, .. }
                | Declaration::Permission { name, line, .. } => (name, *line),
            };
            if !is_schema_name(name) {
                self.note(line, format!("`{name}` cannot name a member"));
            }
            if !seen.insert(name.clone()) {
                self.note(
                    line,
                    format!("`{}` declares `{name}` twice", definition.name),
                );
            }
            match declaration {
                Declaration::Relation { subjects, .. } => {
                    let mut allowed = BTreeSet::new();
                    for (object_type, member, line) in subjects {
                        match (self.find(object_type), member) {
                            (None, _) => {
                                self.note(*line, format!("no type is named `{object_type}`"));
                            }
                            (Some(target), Some(member)) if !Self::has_member(target, member) => {
                                self.note(
                                    *line,
                                    format!("`{object_type}` has no member `{member}`"),
                                );
                            }
                            _ => {}
                        }
                        allowed.insert(AllowedSubject {
                            object_type: object_type.clone(),
                            member: member.clone(),
                        });
                    }
                    compiled
                        .relations
                        .insert(name.clone(), allowed.into_iter().collect());
                }
                Declaration::Permission { expression, .. } => {
                    let rule = self.compile_expression(definition, expression);
                    compiled.permissions.insert(name.clone(), rule);
                }
            }
        }
        compiled
    }

    /// Refuses a permission that computes itself on the same object: it
    /// would never be decided. A walk to another object is bounded when it
    /// runs, not here.
    fn find_cycles(&mut self, definition: &Definition, compiled: &ObjectType) {
        fn collect<'r>(rule: &'r Rule, into: &mut Vec<&'r str>) {
            match rule {
                Rule::Computed { member } => into.push(member),
                Rule::Arrow { .. } => {}
                Rule::Union { rules } | Rule::Intersection { rules } => {
                    for inner in rules {
                        collect(inner, into);
                    }
                }
            }
        }
        for (start, line) in
            definition
                .declarations
                .iter()
                .filter_map(|declaration| match declaration {
                    Declaration::Permission { name, line, .. } => Some((name.as_str(), *line)),
                    Declaration::Relation { .. } => None,
                })
        {
            let mut stack = vec![start];
            let mut seen = BTreeSet::new();
            while let Some(member) = stack.pop() {
                let Some(rule) = compiled.permissions.get(member) else {
                    continue;
                };
                let mut next = Vec::new();
                collect(rule, &mut next);
                if next.contains(&start) {
                    self.note(line, format!("`{start}` is computed from itself"));
                    break;
                }
                for member in next {
                    if seen.insert(member) {
                        stack.push(member);
                    }
                }
            }
        }
    }
}

/// Compiles a schema. Every fault found is told, each at its line.
///
/// # Errors
///
/// Returns the faults of the schema: a syntax fault per definition it
/// spoils, then every fault of meaning in what could be read.
pub fn compile_schema(source: &str) -> Result<CompiledSchema, Vec<SchemaFault>> {
    if source.len() > SCHEMA_MAX_BYTES {
        return Err(vec![SchemaFault {
            line: 1,
            message: format!("a schema is at most {SCHEMA_MAX_BYTES} bytes"),
        }]);
    }
    let lexemes = read_lexemes(source).map_err(|fault| vec![fault])?;
    let mut parser = Parser {
        lexemes,
        at: 0,
        nesting: 0,
    };
    let mut definitions = Vec::new();
    let mut faults = Vec::new();
    while parser.peek().is_some() {
        match parser.read_definition() {
            Ok(definition) => definitions.push(definition),
            Err(fault) => {
                faults.push(fault);
                parser.skip_to_next_definition();
            }
        }
    }

    let mut compiler = Compiler {
        definitions: &definitions,
        faults,
    };
    let mut types = BTreeMap::new();
    for definition in &definitions {
        if !is_schema_name(&definition.name) {
            compiler.note(
                definition.line,
                format!("`{}` cannot name a type", definition.name),
            );
        }
        let object_type = compiler.compile_type(definition);
        compiler.find_cycles(definition, &object_type);
        if types.insert(definition.name.clone(), object_type).is_some() {
            compiler.note(
                definition.line,
                format!("`{}` is defined twice", definition.name),
            );
        }
    }
    if compiler.faults.is_empty() {
        Ok(CompiledSchema {
            version: COMPILED_VERSION,
            types,
        })
    } else {
        let mut faults = compiler.faults;
        faults.sort_by_key(|fault| fault.line);
        Err(faults)
    }
}

#[cfg(test)]
mod tests {
    use super::{AllowedSubject, MemberKind, Rule, compile_schema, is_schema_name};

    const DOCUMENTS: &str = "
        // People, and the teams they are members of.
        definition user {}

        definition team {
            relation member: user | team#member
        }

        definition folder {
            relation parent: folder
            relation owner: user
            relation viewer: user | team#member
            permission view = viewer + owner + view from parent
        }

        definition document {
            relation folder: folder
            relation owner: user
            relation editor: user | team#member
            permission edit = owner + editor
            permission view = edit + view from folder
            permission delete = owner & edit
        }
    ";

    fn read_lines(source: &str) -> Vec<(usize, String)> {
        compile_schema(source)
            .expect_err("a faulty schema")
            .into_iter()
            .map(|fault| (fault.line, fault.message))
            .collect()
    }

    #[test]
    fn a_schema_compiles_to_its_relations_with_their_subjects_and_its_permissions() {
        let schema = compile_schema(DOCUMENTS).expect("a schema");

        let Some(MemberKind::Relation(viewers)) = schema.find_member("folder", "viewer") else {
            panic!("viewer is a relation of folder");
        };
        assert_eq!(
            viewers,
            [
                AllowedSubject {
                    object_type: "team".to_owned(),
                    member: Some("member".to_owned()),
                },
                AllowedSubject {
                    object_type: "user".to_owned(),
                    member: None,
                },
            ],
            "the subjects a relation admits are kept: nothing else is walked"
        );
        let Some(MemberKind::Permission(view)) = schema.find_member("document", "view") else {
            panic!("view is a permission of document");
        };
        assert_eq!(
            view,
            &Rule::Union {
                rules: vec![
                    Rule::Computed {
                        member: "edit".to_owned(),
                    },
                    Rule::Arrow {
                        relation: "folder".to_owned(),
                        member: "view".to_owned(),
                    },
                ],
            }
        );
        assert!(schema.find_member("document", "share").is_none());
        assert!(schema.find_member("printer", "view").is_none());
    }

    #[test]
    fn every_fault_of_meaning_is_told_at_its_line() {
        let source = "definition user {}
definition folder {
  relation viewer: user | robot
  relation owner: user | team#member
  permission view = viewer + share
  permission view = viewer
  permission open = read from viewer
}";

        assert_eq!(
            read_lines(source),
            [
                (3, "no type is named `robot`".to_owned()),
                (4, "no type is named `team`".to_owned()),
                (5, "`folder` has no member `share`".to_owned()),
                (6, "`folder` declares `view` twice".to_owned()),
                (7, "`user` has no member `read`".to_owned()),
            ]
        );
    }

    #[test]
    fn a_permission_computed_from_itself_is_refused_and_a_walk_to_another_object_is_not() {
        assert_eq!(
            read_lines(
                "definition doc {\n permission a = b\n permission b = a + c\n relation c: doc\n}"
            ),
            [
                (2, "`a` is computed from itself".to_owned()),
                (3, "`b` is computed from itself".to_owned()),
            ]
        );
        assert_eq!(
            read_lines("definition doc {\n permission p = p\n}"),
            [(2, "`p` is computed from itself".to_owned())]
        );
        assert!(
            compile_schema(
                "definition doc {\n relation parent: doc\n permission view = view from parent\n}"
            )
            .is_ok()
        );
    }

    #[test]
    fn a_syntax_fault_spoils_its_definition_and_the_next_ones_are_still_read() {
        let source = "definition user {}
definition folder {
  relation viewer user
}
definition document {
  permission view = viewer + owner & editor
}
definition team {
  relation member: ghost
}";

        assert_eq!(
            read_lines(source),
            [
                (3, "`:` is expected".to_owned()),
                (6, "`+` and `&` do not mix without parentheses".to_owned()),
                (9, "no type is named `ghost`".to_owned()),
            ]
        );
        assert_eq!(
            read_lines("definition doc { relation r: doc ! }"),
            [(1, "`!` has no meaning here".to_owned())]
        );
    }

    #[test]
    fn an_arrow_walks_to_objects_that_have_the_member_and_through_a_relation() {
        assert_eq!(
            read_lines(
                "definition user {}\ndefinition team {\n relation member: user\n}\ndefinition doc {\n relation team: team#member\n permission view = view from team\n}"
            ),
            [(7, "`team` names no object to walk to".to_owned())]
        );
        assert_eq!(
            read_lines(
                "definition user {}\ndefinition doc {\n relation viewer: user\n permission p = viewer from ghost\n}"
            ),
            [(4, "`doc` has no relation `ghost` to walk".to_owned())]
        );
    }

    #[test]
    fn names_are_lowercase_and_a_schema_has_a_ceiling() {
        assert!(is_schema_name("folder_2"));
        for name in ["Folder", "2folder", "", "a-b", &"a".repeat(65)] {
            assert!(!is_schema_name(name), "{name:?}");
        }
        assert_eq!(
            read_lines("definition Folder {}"),
            [(1, "`Folder` cannot name a type".to_owned())]
        );
        let huge = format!("definition doc {{}}\n{}", "// padding\n".repeat(7000));
        assert_eq!(
            read_lines(&huge),
            [(1, "a schema is at most 65536 bytes".to_owned())]
        );
    }

    #[test]
    fn parentheses_past_the_bound_are_a_fault_and_never_overflow_the_stack() {
        let deep = format!(
            "definition a {{ relation r: a permission p = {}r{} }}",
            "(".repeat(32_000),
            ")".repeat(32_000)
        );
        // The stack of a worker thread: a walk 32 000 deep would overflow it.
        let compiled = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || compile_schema(&deep).map(|_| ()))
            .expect("a thread")
            .join()
            .expect("the thread returns");
        let faults = compiled.expect_err("faults");
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].message, "parentheses nest at most 16 deep");
        let sixteen = format!(
            "definition a {{ relation r: a permission p = {}r{} }}",
            "(".repeat(16),
            ")".repeat(16)
        );
        assert!(compile_schema(&sixteen).is_ok(), "sixteen deep is read");
    }

    #[test]
    fn a_character_that_cannot_be_shown_is_a_fault_even_in_a_comment() {
        for source in [
            "definition user {} // \u{202e}evil",
            "definition user {}\u{2028}definition team {}",
            "definition us\u{200b}er {}",
        ] {
            let faults = compile_schema(source).expect_err("a fault");
            assert!(
                faults[0].message.starts_with("U+") && !faults[0].message.contains('\u{202e}'),
                "{source:?}: {}",
                faults[0].message
            );
        }
    }
}
