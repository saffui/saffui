use models::paging::Window;
use postgres_types::ToSql;

use crate::query::write_set::Bind;

/// Which way a sort runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

impl SortDirection {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Ascending => "ASC",
            Self::Descending => "DESC",
        }
    }
}

/// A collection read: what to match, how to order it, and how much of it.
///
/// The order is a list of compile time strings, and both halves of that are the
/// guard. A sort column is the one part of a statement that cannot be a
/// placeholder, so a column that could come off a request would be interpolated
/// from something a caller chose; an endpoint maps what was asked onto a
/// constant it declares. And it is a list because an offset window is only well
/// defined over a total order: where the leading column ties, the database may
/// break the tie differently between two statements, and one row is then served
/// on two pages while another is served on none. The ties are ordinary rather
/// than exotic, since `now()` is the transaction's clock and every row written
/// together carries the same timestamp exactly.
pub struct ListQuery<'a> {
    filters: Vec<Bind<'a>>,
    sort: Vec<(&'static str, SortDirection)>,
    window: Window,
}

impl<'a> ListQuery<'a> {
    pub fn new(window: Window) -> Self {
        Self {
            filters: Vec::new(),
            sort: Vec::new(),
            window,
        }
    }

    /// Narrow the read.
    pub fn filter(mut self, binds: Vec<Bind<'a>>) -> Self {
        self.filters.extend(binds);
        self
    }

    /// Put a scoping filter in front of whatever the caller asked for.
    ///
    /// Prepended rather than appended so the scope reads first, and, the part
    /// that matters, it goes through the same list as everything else so a count
    /// over the same query sees it too. A scope applied to the page but not to
    /// its total is how one tenant learns how many rows another has.
    pub fn scoped_by(mut self, scope: Bind<'a>) -> Self {
        self.filters.insert(0, scope);
        self
    }

    /// Order by one more column, after whatever was already asked for.
    ///
    /// Additive rather than replacing, so a tiebreaker is added by naming it
    /// and never by rewriting the sort somebody else established.
    pub fn sorted_by(mut self, column: &'static str, direction: SortDirection) -> Self {
        self.sort.push((column, direction));
        self
    }

    pub fn window(&self) -> Window {
        self.window
    }

    /// The `WHERE` fragment, with placeholders numbered from one.
    ///
    /// Empty when nothing is filtered, so a caller pastes it in either way
    /// rather than deciding whether to.
    pub fn where_clause(&self) -> String {
        if self.filters.is_empty() {
            return String::new();
        }
        let conditions: Vec<String> = self
            .filters
            .iter()
            .enumerate()
            .map(|(index, bind)| format!("{} = ${}", bind.column(), index + 1))
            .collect();
        format!(" WHERE {}", conditions.join(" AND "))
    }

    /// The ordering, when one was asked for.
    pub fn order_clause(&self) -> String {
        if self.sort.is_empty() {
            return String::new();
        }
        let terms: Vec<String> = self
            .sort
            .iter()
            .map(|(column, direction)| format!("{column} {}", direction.as_sql()))
            .collect();
        format!(" ORDER BY {}", terms.join(", "))
    }

    /// The window, as literals.
    ///
    /// Numbers rather than placeholders because they are this crate's own,
    /// already bounded by the type that produced them, and never a caller's
    /// string.
    pub fn limit_clause(&self) -> String {
        format!(" LIMIT {} OFFSET {}", self.window.max, self.window.first)
    }

    /// The values the filters bind, in placeholder order.
    pub fn params(&self) -> Vec<&'a (dyn ToSql + Sync)> {
        self.filters.iter().map(Bind::value).collect()
    }

    /// The whole read.
    pub fn select(&self, columns: &str, table: &str) -> String {
        format!(
            "SELECT {columns} FROM {table}{}{}{}",
            self.where_clause(),
            self.order_clause(),
            self.limit_clause()
        )
    }

    /// The total under the same filters.
    ///
    /// Built from the same list as the page, and without the window: a count
    /// bounded by a page would report the page's size.
    pub fn count(&self, table: &str) -> String {
        format!("SELECT count(*) FROM {table}{}", self.where_clause())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::write_set::col;
    use models::paging::PagingParams;

    fn window(first: i64, max: i64) -> Window {
        PagingParams {
            first: Some(first),
            max: Some(max),
            ..Default::default()
        }
        .window()
        .expect("a usable window")
    }

    /// The placeholders are numbered from one, in the order the values are
    /// handed over.
    #[test]
    fn the_filters_are_numbered_in_the_order_they_are_bound() {
        let tenant = "acme".to_owned();
        let enabled = true;

        let query = ListQuery::new(window(0, 10))
            .filter(vec![col("tenant", &tenant), col("enabled", &enabled)]);

        assert_eq!(query.where_clause(), " WHERE tenant = $1 AND enabled = $2");
        assert_eq!(query.params().len(), 2);
    }

    /// A scope goes in front and through the same list, so the count sees it.
    /// Applied to the page and not to its total is how one tenant learns how
    /// many rows another has.
    #[test]
    fn a_scope_reaches_the_count_as_well_as_the_page() {
        let tenant = "acme".to_owned();
        let enabled = true;

        let query = ListQuery::new(window(0, 10))
            .filter(vec![col("enabled", &enabled)])
            .scoped_by(col("tenant", &tenant));

        assert_eq!(query.where_clause(), " WHERE tenant = $1 AND enabled = $2");
        assert_eq!(
            query.count("realms"),
            "SELECT count(*) FROM realms WHERE tenant = $1 AND enabled = $2"
        );
        assert!(
            !query.count("realms").contains("LIMIT"),
            "a count bounded by a page reports the page"
        );
    }

    /// Nothing filtered is an empty fragment rather than a clause with nothing
    /// in it, which no statement would accept.
    #[test]
    fn filtering_nothing_produces_no_clause() {
        let query = ListQuery::new(window(0, 10));
        assert!(query.where_clause().is_empty());
        assert!(query.params().is_empty());
        assert_eq!(
            query.select("*", "realms"),
            "SELECT * FROM realms LIMIT 10 OFFSET 0"
        );
    }

    /// The window is the one the request type already bounded, carried through
    /// rather than recomputed.
    #[test]
    fn the_window_is_the_one_that_was_handed_in() {
        let bounded = PagingParams {
            max: Some(100_000),
            ..Default::default()
        }
        .window()
        .unwrap();
        assert!(bounded.clamped, "the request type cut it down");

        let query = ListQuery::new(bounded);
        assert_eq!(query.window(), bounded);
        assert_eq!(
            query.limit_clause(),
            format!(" LIMIT {} OFFSET 0", models::paging::MAX_MAX)
        );
    }

    /// The ordering is present only when it was asked for, and reads the way it
    /// was asked.
    #[test]
    fn the_ordering_is_only_there_when_it_was_asked_for() {
        let query = ListQuery::new(window(0, 10));
        assert!(query.order_clause().is_empty());

        let ascending = ListQuery::new(window(0, 10)).sorted_by("name", SortDirection::Ascending);
        assert_eq!(ascending.order_clause(), " ORDER BY name ASC");

        let descending =
            ListQuery::new(window(0, 10)).sorted_by("created_at", SortDirection::Descending);
        assert_eq!(descending.order_clause(), " ORDER BY created_at DESC");
    }

    /// A window over an offset needs a total order. Where the leading column
    /// ties, the database may break the tie differently between two statements,
    /// and then one row is served on two pages and another on none. The tie is
    /// the ordinary case rather than the odd one: `now()` is the transaction's
    /// clock, so every row written together carries the same timestamp.
    #[test]
    fn a_tiebreaker_is_added_by_naming_it_and_never_by_replacing_the_sort() {
        let query = ListQuery::new(window(0, 10))
            .sorted_by("occurred_at", SortDirection::Descending)
            .sorted_by("decision_id", SortDirection::Descending);

        assert_eq!(
            query.order_clause(),
            " ORDER BY occurred_at DESC, decision_id DESC",
            "the second column replaced the first instead of following it"
        );
    }

    /// The parts of one order may run in different directions, so a natural
    /// reading order can still be made total by an ascending identity.
    #[test]
    fn the_columns_of_one_order_keep_their_own_directions() {
        let query = ListQuery::new(window(0, 10))
            .sorted_by("created_at", SortDirection::Descending)
            .sorted_by("receipt_id", SortDirection::Ascending);

        assert_eq!(
            query.order_clause(),
            " ORDER BY created_at DESC, receipt_id ASC"
        );
    }

    /// The whole statement, in the order the clauses have to appear in.
    #[test]
    fn a_read_reads_in_the_order_a_statement_wants() {
        let tenant = "acme".to_owned();
        let query = ListQuery::new(window(20, 5))
            .scoped_by(col("tenant", &tenant))
            .sorted_by("name", SortDirection::Ascending);

        assert_eq!(
            query.select("realm_id, name", "realms"),
            "SELECT realm_id, name FROM realms WHERE tenant = $1 ORDER BY name ASC \
             LIMIT 5 OFFSET 20"
        );
    }
}
