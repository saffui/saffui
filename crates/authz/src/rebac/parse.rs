use std::fmt;

use super::ast::{
    At, Definition, Expr, Member, Name, PermissionDecl, RelationDecl, Schema, SubjectType,
};

/// The longest source accepted, in bytes.
///
/// The schema column refuses more than this too. Two ceilings for one value is
/// usually a smell; here the database's is what stops a row already written
/// from being loaded, and this one is what stops a request being parsed, and a
/// realm can be sent a schema by someone who never writes it down.
pub const MAX_SOURCE: usize = 65_536;

/// How deeply parentheses may nest.
///
/// The parser recurses through them, so this is what keeps a crafted source
/// from ending the process rather than the request. Far above anything an
/// author writes and far below a stack.
pub const MAX_NESTING: u32 = 32;

/// Why a source could not be read, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub at: At,
    pub expected: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}, column {}: expected {}",
            self.at.line, self.at.column, self.expected
        )
    }
}

impl std::error::Error for ParseError {}

/// Why a source could not be read at all, before any of it was.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the schema is {length} bytes, and {MAX_SOURCE} is the most that is accepted")]
    TooLong { length: usize },
    #[error("{0}")]
    Malformed(ParseError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Open,
    Close,
    LParen,
    RParen,
    Colon,
    Pipe,
    Hash,
    Plus,
    Amp,
    Equals,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Self::Word(word) => format!("'{word}'"),
            Self::Open => "'{'".to_owned(),
            Self::Close => "'}'".to_owned(),
            Self::LParen => "'('".to_owned(),
            Self::RParen => "')'".to_owned(),
            Self::Colon => "':'".to_owned(),
            Self::Pipe => "'|'".to_owned(),
            Self::Hash => "'#'".to_owned(),
            Self::Plus => "'+'".to_owned(),
            Self::Amp => "'&'".to_owned(),
            Self::Equals => "'='".to_owned(),
        }
    }
}

struct Lexed {
    tok: Tok,
    at: At,
}

/// Read a schema, or say where it stopped making sense.
pub fn parse(source: &str) -> Result<Schema, Unreadable> {
    if source.len() > MAX_SOURCE {
        return Err(Unreadable::TooLong {
            length: source.len(),
        });
    }
    let tokens = lex(source).map_err(Unreadable::Malformed)?;
    Parser {
        tokens: &tokens,
        next: 0,
        end: end_of(source),
    }
    .schema()
    .map_err(Unreadable::Malformed)
}

/// Where the source ends, so running out of input is reported there rather than
/// at the last token that happened to be read.
fn end_of(source: &str) -> At {
    let mut line = 1;
    let mut column = 1;
    for character in source.chars() {
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    At { line, column }
}

fn lex(source: &str) -> Result<Vec<Lexed>, ParseError> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();
    let mut line = 1;
    let mut column = 1;

    while let Some(&character) = chars.peek() {
        let at = At { line, column };

        if character == '\n' {
            chars.next();
            line += 1;
            column = 1;
            continue;
        }
        if character.is_whitespace() {
            chars.next();
            column += 1;
            continue;
        }
        if character == '/' {
            chars.next();
            column += 1;
            if chars.peek() != Some(&'/') {
                return Err(ParseError {
                    at,
                    expected: "'//' to begin a comment".to_owned(),
                });
            }
            while let Some(&inside) = chars.peek() {
                if inside == '\n' {
                    break;
                }
                chars.next();
                column += 1;
            }
            continue;
        }
        if character.is_ascii_alphabetic() || character == '_' {
            let mut word = String::new();
            while let Some(&inside) = chars.peek() {
                if inside.is_ascii_alphanumeric() || inside == '_' {
                    word.push(inside);
                    chars.next();
                    column += 1;
                } else {
                    break;
                }
            }
            tokens.push(Lexed {
                tok: Tok::Word(word),
                at,
            });
            continue;
        }

        let tok = match character {
            '{' => Tok::Open,
            '}' => Tok::Close,
            '(' => Tok::LParen,
            ')' => Tok::RParen,
            ':' => Tok::Colon,
            '|' => Tok::Pipe,
            '#' => Tok::Hash,
            '+' => Tok::Plus,
            '&' => Tok::Amp,
            '=' => Tok::Equals,
            other => {
                return Err(ParseError {
                    at,
                    expected: format!("something a schema can contain, not '{other}'"),
                });
            }
        };
        chars.next();
        column += 1;
        tokens.push(Lexed { tok, at });
    }

    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Lexed],
    next: usize,
    end: At,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a Tok> {
        self.tokens.get(self.next).map(|lexed| &lexed.tok)
    }

    fn here(&self) -> At {
        self.tokens
            .get(self.next)
            .map(|lexed| lexed.at)
            .unwrap_or(self.end)
    }

    /// What was wanted, and what was there instead. The second half is the one
    /// an author reads: knowing a colon was expected is less useful than seeing
    /// what was written where it should have been.
    fn missing(&self, expected: &str) -> ParseError {
        let found = match self.peek() {
            Some(tok) => format!(", found {}", tok.describe()),
            None => String::new(),
        };
        ParseError {
            at: self.here(),
            expected: format!("{expected}{found}"),
        }
    }

    fn take(&mut self) -> Option<&'a Lexed> {
        let lexed = self.tokens.get(self.next);
        if lexed.is_some() {
            self.next += 1;
        }
        lexed
    }

    fn expect(&mut self, want: &Tok, expected: &str) -> Result<(), ParseError> {
        match self.peek() {
            Some(tok) if tok == want => {
                self.next += 1;
                Ok(())
            }
            _ => Err(self.missing(expected)),
        }
    }

    fn word(&mut self, expected: &str) -> Result<Name, ParseError> {
        match self.take() {
            Some(Lexed {
                tok: Tok::Word(text),
                at,
            }) => Ok(Name {
                text: text.clone(),
                at: *at,
            }),
            Some(_) => {
                self.next -= 1;
                Err(self.missing(expected))
            }
            None => Err(self.missing(expected)),
        }
    }

    fn keyword(&mut self, want: &str, expected: &str) -> Result<(), ParseError> {
        match self.peek() {
            Some(Tok::Word(text)) if text == want => {
                self.next += 1;
                Ok(())
            }
            _ => Err(self.missing(expected)),
        }
    }

    fn schema(&mut self) -> Result<Schema, ParseError> {
        let mut definitions = Vec::new();
        while self.peek().is_some() {
            self.keyword("definition", "'definition'")?;
            definitions.push(self.definition()?);
        }
        Ok(Schema { definitions })
    }

    fn definition(&mut self) -> Result<Definition, ParseError> {
        let name = self.word("a type name")?;
        self.expect(&Tok::Open, "'{'")?;

        let mut members = Vec::new();
        loop {
            match self.peek() {
                Some(Tok::Close) => {
                    self.next += 1;
                    break;
                }
                Some(Tok::Word(word)) if word == "relation" => {
                    self.next += 1;
                    members.push(Member::Relation(self.relation()?));
                }
                Some(Tok::Word(word)) if word == "permission" => {
                    self.next += 1;
                    members.push(Member::Permission(self.permission()?));
                }
                _ => return Err(self.missing("'relation', 'permission' or '}'")),
            }
        }

        Ok(Definition { name, members })
    }

    fn relation(&mut self) -> Result<RelationDecl, ParseError> {
        let name = self.word("a relation name")?;
        self.expect(&Tok::Colon, "':'")?;

        let mut subjects = vec![self.subject()?];
        while self.peek() == Some(&Tok::Pipe) {
            self.next += 1;
            subjects.push(self.subject()?);
        }

        Ok(RelationDecl { name, subjects })
    }

    fn subject(&mut self) -> Result<SubjectType, ParseError> {
        let type_name = self.word("a subject type")?;
        let relation = if self.peek() == Some(&Tok::Hash) {
            self.next += 1;
            Some(self.word("a relation after '#'")?)
        } else {
            None
        };
        Ok(SubjectType {
            type_name,
            relation,
        })
    }

    fn permission(&mut self) -> Result<PermissionDecl, ParseError> {
        let name = self.word("a permission name")?;
        self.expect(&Tok::Equals, "'='")?;
        let body = self.expr(0)?;
        Ok(PermissionDecl { name, body })
    }

    /// One expression. `+` and `&` do not mix without parentheses, which is not
    /// a missing feature: any precedence between them would be one this
    /// language invented, and a reader would have to know it to read a rule
    /// that grants access.
    fn expr(&mut self, depth: u32) -> Result<Expr, ParseError> {
        if depth > MAX_NESTING {
            return Err(self.missing("fewer nested groups"));
        }

        let first = self.term(depth)?;
        let at = first.at();

        let joiner = match self.peek() {
            Some(Tok::Plus) => Tok::Plus,
            Some(Tok::Amp) => Tok::Amp,
            _ => return Ok(first),
        };

        let mut parts = vec![first];
        while self.peek() == Some(&joiner) {
            self.next += 1;
            parts.push(self.term(depth)?);
        }

        // The other operator, here, is a schema whose meaning depends on a
        // precedence nobody stated.
        if matches!(self.peek(), Some(Tok::Plus) | Some(Tok::Amp)) {
            return Err(self.missing("parentheses, since '+' and '&' do not mix"));
        }

        Ok(match joiner {
            Tok::Plus => Expr::Any { parts, at },
            _ => Expr::All { parts, at },
        })
    }

    fn term(&mut self, depth: u32) -> Result<Expr, ParseError> {
        if self.peek() == Some(&Tok::LParen) {
            self.next += 1;
            let inner = self.expr(depth + 1)?;
            self.expect(&Tok::RParen, "')'")?;
            return Ok(inner);
        }

        let name = self.word("a relation or permission name")?;
        if matches!(self.peek(), Some(Tok::Word(word)) if word == "from") {
            self.next += 1;
            let tupleset = self.word("a relation after 'from'")?;
            let at = name.at;
            return Ok(Expr::Arrow {
                computed: name,
                tupleset,
                at,
            });
        }
        Ok(Expr::Member(name))
    }
}
