use std::fmt::Write as _;

use super::bind::{Built, Value};
use super::criteria::Criteria;
use super::ident::{Column, Table};

/// Which way a sort runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SortDirection {
    Ascending,
}

impl SortDirection {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Ascending => "ASC",
        }
    }
}

/// A read of named columns. There is no way to ask for every column: a row
/// read whole carries sealed values nobody asked for, and a statement
/// prepared on `*` fails after the migration that changes the table.
pub(crate) struct Select<'a> {
    table: Table,
    columns: &'static [Column],
    criteria: Criteria<'a>,
    sort: Vec<(Column, SortDirection)>,
    limit: Option<Value<'a>>,
}

impl<'a> Select<'a> {
    pub(crate) fn from(table: Table, columns: &'static [Column]) -> Self {
        Self {
            table,
            columns,
            criteria: Criteria::new(),
            sort: Vec::new(),
            limit: None,
        }
    }

    /// Narrows the read.
    pub(crate) fn filter(mut self, criteria: Criteria<'a>) -> Self {
        self.criteria = criteria;
        self
    }

    /// Orders by one more column, after whatever was already asked for.
    pub(crate) fn sorted_by(mut self, column: Column, direction: SortDirection) -> Self {
        self.sort.push((column, direction));
        self
    }

    /// Keeps at most as many rows as the bound value says.
    pub(crate) fn limited_to(mut self, rows: Value<'a>) -> Self {
        self.limit = Some(rows);
        self
    }

    pub(crate) fn build(self) -> Built<'a> {
        let mut sql = String::from("SELECT ");
        write_columns(&mut sql, self.columns);
        let _ = write!(sql, " FROM {}", self.table.name);
        sql.push_str(self.table.keys.predicate());
        let mut values = self.criteria.write(&mut sql, self.table.keys.count() + 1);
        for (position, (column, direction)) in self.sort.iter().enumerate() {
            sql.push_str(if position == 0 { " ORDER BY " } else { ", " });
            let _ = write!(sql, "{} {}", column.0, direction.as_sql());
        }
        if let Some(rows) = self.limit {
            let _ = write!(
                sql,
                " LIMIT ${}",
                self.table.keys.count() + values.len() + 1
            );
            values.push(rows);
        }
        Built::new(sql, self.table.keys, values)
    }
}

fn write_columns(sql: &mut String, columns: &[Column]) {
    for (position, column) in columns.iter().enumerate() {
        if position > 0 {
            sql.push_str(", ");
        }
        sql.push_str(column.0);
    }
}

#[cfg(test)]
mod tests {
    use super::{Select, SortDirection};
    use crate::query::criteria::Criteria;
    use crate::query::ident::{Column, ScopeKeys, Table};

    const NOTES: Table = Table {
        name: "notes",
        keys: ScopeKeys::TenantAndRealm,
    };
    const ACCOUNTS: Table = Table {
        name: "accounts",
        keys: ScopeKeys::Tenant,
    };
    const ID: Column = Column("note_id");
    const BODY: Column = Column("body");
    const READ: &[Column] = &[ID, BODY];

    #[test]
    fn the_scope_opens_the_where_and_only_named_columns_are_read() {
        let built = Select::from(NOTES, READ).build();

        assert_eq!(
            built.sql,
            "SELECT note_id, body FROM notes WHERE tenant_id = $1 AND realm_id = $2"
        );
        assert_eq!(
            built.count_values(),
            0,
            "the keys come from the unit of work"
        );
    }

    #[test]
    fn a_table_keyed_by_the_tenant_alone_is_read_under_it_alone() {
        let built = Select::from(ACCOUNTS, READ).build();

        assert_eq!(
            built.sql,
            "SELECT note_id, body FROM accounts WHERE tenant_id = $1"
        );
    }

    #[test]
    fn criteria_order_and_limit_follow_the_scope_and_are_bound_in_turn() {
        let built = Select::from(NOTES, READ)
            .filter(Criteria::new().where_greater(ID, &3_i64))
            .sorted_by(ID, SortDirection::Ascending)
            .limited_to(&50_i64)
            .build();

        assert_eq!(
            built.sql,
            "SELECT note_id, body FROM notes WHERE tenant_id = $1 AND realm_id = $2 \
             AND note_id > $3 ORDER BY note_id ASC LIMIT $4"
        );
        assert_eq!(built.count_values(), 2, "the criterion, then the limit");
    }

    #[test]
    fn under_the_tenant_alone_the_first_criterion_takes_the_second_placeholder() {
        let built = Select::from(ACCOUNTS, READ)
            .filter(Criteria::new().where_greater(ID, &3_i64))
            .limited_to(&50_i64)
            .build();

        assert_eq!(
            built.sql,
            "SELECT note_id, body FROM accounts WHERE tenant_id = $1 AND note_id > $2 LIMIT $3"
        );
    }
}
