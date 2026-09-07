//! What an agent may do, said as tool names.
//!
//! The grammar is the one the trusted platforms already speak for their
//! subjects: an exact name, or a prefix ending in `*`. A capability token
//! carries the narrowed list in its `cap` claim, and narrowing is the only
//! move there is: what a root does not admit is refused, never granted.

/// Whether one held pattern admits one asked name or pattern.
///
/// An exact name is admitted by itself or by a prefix that covers it. An
/// asked *pattern* is only admitted by a pattern at least as wide: `a.b*`
/// fits under `a.*`, and never the other way around, so nobody widens a
/// grant by asking in the plural.
fn admitted(held: &str, asked: &str) -> bool {
    match (held.strip_suffix('*'), asked.strip_suffix('*')) {
        (None, None) => held == asked,
        (Some(prefix), None) => asked.starts_with(prefix),
        (Some(prefix), Some(narrower)) => narrower.starts_with(prefix),
        (None, Some(_)) => false,
    }
}

/// Why a request could not be narrowed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unnarrowable {
    /// The request names something the root does not admit. Which
    /// capability it was is not said back: an agent probing for the edge of
    /// a grant reads one refusal.
    #[error("the request reaches outside what is held")]
    Widened,
    /// The request names nothing at all.
    #[error("the request names no capability")]
    Empty,
}

/// Narrow a root down to what was asked: every asked entry must sit inside
/// the root, and the result is exactly the asked list, deduplicated in the
/// asked order. Asking for nothing is refused rather than granted whole,
/// because a token whose powers nobody spelled is the overpermission this
/// exists to end.
pub fn narrowed(root: &[String], asked: &str) -> Result<Vec<String>, Unnarrowable> {
    let mut kept: Vec<String> = Vec::new();
    for wanted in asked.split_whitespace() {
        if !root.iter().any(|held| admitted(held, wanted)) {
            return Err(Unnarrowable::Widened);
        }
        if !kept.iter().any(|held| held == wanted) {
            kept.push(wanted.to_owned());
        }
    }
    if kept.is_empty() {
        return Err(Unnarrowable::Empty);
    }
    Ok(kept)
}

/// The capability list a verified token carries, when it carries one.
pub fn carried(claims: &serde_json::Map<String, serde_json::Value>) -> Option<Vec<String>> {
    Some(
        claims
            .get("cap")?
            .as_array()?
            .iter()
            .filter_map(|held| held.as_str().map(str::to_owned))
            .collect(),
    )
}

/// Why a written pattern is refused at the door, in words an operator can
/// act on. The reader's grammar never widens; this keeps what is stored
/// inside what will ever be read.
pub fn well_formed(pattern: &str) -> Result<(), &'static str> {
    if pattern.is_empty() || pattern.len() > 200 {
        return Err("a capability is 1 to 200 characters");
    }
    if pattern.chars().any(char::is_whitespace) {
        return Err("a capability carries no whitespace");
    }
    let inner = pattern.strip_suffix('*').unwrap_or(pattern);
    if inner.contains('*') {
        return Err("`*` stands only at the end, as a prefix mark");
    }
    if inner.is_empty() {
        return Err("a bare `*` grants everything, which is what this exists to end");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(held: &[&str]) -> Vec<String> {
        held.iter().map(|one| (*one).to_owned()).collect()
    }

    /// Exact under exact, exact under prefix, narrower prefix under wider:
    /// admitted. A pattern asked under an exact name, or wider than its
    /// root: not.
    #[test]
    fn a_grant_narrows_and_never_widens() {
        let held = root(&["github.create_issue", "saffui.user.*"]);

        assert_eq!(
            narrowed(&held, "github.create_issue").unwrap(),
            vec!["github.create_issue".to_owned()]
        );
        assert_eq!(
            narrowed(&held, "saffui.user.read saffui.user.list").unwrap(),
            vec!["saffui.user.read".to_owned(), "saffui.user.list".to_owned()]
        );
        assert_eq!(
            narrowed(&held, "saffui.user.re*").unwrap(),
            vec!["saffui.user.re*".to_owned()],
            "a narrower pattern fits under a wider one"
        );

        assert_eq!(
            narrowed(&held, "saffui.*"),
            Err(Unnarrowable::Widened),
            "a wider pattern does not fit under a narrower root"
        );
        assert_eq!(
            narrowed(&held, "github.*"),
            Err(Unnarrowable::Widened),
            "a pattern does not fit under an exact name"
        );
        assert_eq!(
            narrowed(&held, "saffui.user.read github.delete_repo"),
            Err(Unnarrowable::Widened),
            "one entry outside refuses the whole request"
        );
        assert_eq!(narrowed(&held, "  "), Err(Unnarrowable::Empty));
    }

    /// The door refuses in the reader's own grammar, naming the rule.
    #[test]
    fn a_written_pattern_is_held_to_the_readers_grammar() {
        assert!(well_formed("a.tool").is_ok());
        assert!(well_formed("a.prefix.*").is_ok());
        assert!(well_formed("sp ace").is_err());
        assert!(well_formed("a.*b").is_err());
        assert!(well_formed("*").is_err());
        assert!(well_formed("").is_err());
    }

    /// Asking twice holds once; the order is the asker's.
    #[test]
    fn a_request_is_kept_in_its_own_order_once_each() {
        let held = root(&["a.*", "b"]);
        assert_eq!(
            narrowed(&held, "b a.one b a.one").unwrap(),
            vec!["b".to_owned(), "a.one".to_owned()]
        );
    }
}
