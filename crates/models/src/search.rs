use serde::Deserialize;

/// `search` + `exact` (substring against equality over a per-resource column
/// set), `q` (attribute `key:value` pairs), and `sort` (`column:asc|desc`,
/// allow-listed per resource).
///
/// Typed fields rather than a free-form map: every list endpoint supports a
/// subset and documents which, and a map would let a caller send a filter no
/// endpoint reads without ever learning that it was ignored.
#[derive(Debug, Default, Deserialize)]
pub struct SearchParams {
    pub search: Option<String>,
    pub exact: Option<bool>,
    pub q: Option<String>,
    pub sort: Option<String>,
}

impl SearchParams {
    /// The term and whether it must match exactly, when a non-empty `search`
    /// was sent.
    ///
    /// Empty is nothing rather than a substring match on the empty string, which
    /// every row satisfies — `?search=` is a caller that built a query string
    /// from a blank box, not one asking for the whole table.
    pub fn search_term(&self) -> Option<(&str, bool)> {
        self.search
            .as_deref()
            .filter(|term| !term.is_empty())
            .map(|term| (term, self.exact.unwrap_or(false)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_term_is_a_substring_match_unless_exact_is_asked_for() {
        assert_eq!(
            SearchParams {
                search: Some("ada".into()),
                ..Default::default()
            }
            .search_term(),
            Some(("ada", false))
        );

        assert_eq!(
            SearchParams {
                search: Some("ada".into()),
                exact: Some(true),
                ..Default::default()
            }
            .search_term(),
            Some(("ada", true))
        );
    }

    /// `exact` without a term filters nothing, rather than matching every row
    /// exactly against the empty string.
    #[test]
    fn no_term_means_no_search() {
        assert_eq!(SearchParams::default().search_term(), None);
        assert_eq!(
            SearchParams {
                search: Some(String::new()),
                exact: Some(true),
                ..Default::default()
            }
            .search_term(),
            None
        );
    }
}
