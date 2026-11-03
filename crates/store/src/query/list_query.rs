use std::fmt::Write as _;

use saffui_core::clients::store::ListWindow;

use super::bind::Built;
use super::ident::{Column, Table};
use super::select::{SortDirection, write_columns, write_order};

/// A collection read: how to order it, and how much of it.
///
/// The order is a list of constants, and both halves of that are the guard.
/// A sort column is the one part of a statement that cannot be a
/// placeholder, so a column that could come off a request would be
/// interpolated from something a caller chose; an endpoint maps what was
/// asked onto a constant it declares. And it is a list because an offset
/// window is only well defined over a total order: where the leading column
/// ties, the database may break the tie differently between two statements,
/// and one row is then served on two pages while another is served on none.
///
/// The scope is not a filter a caller adds. It opens the `WHERE` of the page
/// and of its count alike: a scope applied to the page but not to its total
/// is how one tenant learns how many rows another has.
pub(crate) struct ListQuery {
    sort: Vec<(Column, SortDirection)>,
    max: i64,
    first: i64,
}

impl ListQuery {
    pub(crate) fn new(window: ListWindow) -> Self {
        Self {
            sort: Vec::new(),
            max: i64::from(window.max),
            first: i64::from(window.first),
        }
    }

    /// Orders by one more column, after whatever was already asked for.
    pub(crate) fn sorted_by(mut self, column: Column, direction: SortDirection) -> Self {
        self.sort.push((column, direction));
        self
    }

    /// The page: named columns, the order, and the window bound after the
    /// scope, so every page of a listing is one statement, which a
    /// connection prepares once.
    pub(crate) fn select(&self, table: Table, columns: &'static [Column]) -> Built<'_> {
        let mut sql = String::from("SELECT ");
        write_columns(&mut sql, columns);
        let _ = write!(sql, " FROM {}", table.name);
        sql.push_str(table.keys.predicate());
        write_order(&mut sql, &self.sort);
        let after = table.keys.count();
        let _ = write!(sql, " LIMIT ${} OFFSET ${}", after + 1, after + 2);
        Built::new(sql, table.keys, vec![&self.max, &self.first])
    }

    /// The total under the same scope, without the window: a count bounded
    /// by a page would report the size of the page.
    pub(crate) fn count(table: Table) -> Built<'static> {
        let mut sql = format!("SELECT count(*) FROM {}", table.name);
        sql.push_str(table.keys.predicate());
        Built::new(sql, table.keys, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::clients::store::ListWindow;

    use super::{ListQuery, SortDirection};
    use crate::query::ident::{Column, ScopeKeys, Table};

    const NOTES: Table = Table {
        name: "notes",
        keys: ScopeKeys::TenantAndRealm,
    };
    const ID: Column = Column("note_id");
    const BODY: Column = Column("body");
    const READ: &[Column] = &[ID, BODY];
    const WINDOW: ListWindow = ListWindow { first: 20, max: 10 };

    #[test]
    fn the_page_and_its_count_open_with_the_scope_and_the_window_is_bound() {
        let query = ListQuery::new(WINDOW)
            .sorted_by(BODY, SortDirection::Ascending)
            .sorted_by(ID, SortDirection::Ascending);

        let page = query.select(NOTES, READ);

        assert_eq!(
            page.sql,
            "SELECT note_id, body FROM notes WHERE tenant_id = $1 AND realm_id = $2 \
             ORDER BY body ASC, note_id ASC LIMIT $3 OFFSET $4"
        );
        assert_eq!(page.count_values(), 2, "the window");
        assert_eq!(
            ListQuery::count(NOTES).sql,
            "SELECT count(*) FROM notes WHERE tenant_id = $1 AND realm_id = $2"
        );
    }
}
