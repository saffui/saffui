use std::fmt::Write as _;

use super::bind::Built;
use super::ident::{Column, Table};

/// A read of named columns. There is no way to ask for every column: a row
/// read whole carries sealed values nobody asked for, and a statement
/// prepared on `*` fails after the migration that changes the table.
pub(crate) struct Select {
    table: Table,
    columns: &'static [Column],
}

impl Select {
    pub(crate) fn from(table: Table, columns: &'static [Column]) -> Self {
        Self { table, columns }
    }

    pub(crate) fn build(self) -> Built<'static> {
        let mut sql = String::from("SELECT ");
        write_columns(&mut sql, self.columns);
        let _ = write!(sql, " FROM {}", self.table.name);
        sql.push_str(self.table.keys.predicate());
        Built::new(sql, self.table.keys, Vec::new())
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
    use super::Select;
    use crate::query::ident::{Column, ScopeKeys, Table};

    const NOTES: Table = Table {
        name: "notes",
        keys: ScopeKeys::TenantAndRealm,
    };
    const ACCOUNTS: Table = Table {
        name: "accounts",
        keys: ScopeKeys::Tenant,
    };
    const READ: &[Column] = &[Column("note_id"), Column("body")];

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
}
