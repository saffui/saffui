use super::bind::{Bind, Built, Value};
use super::ident::Table;

/// An insert of the pairs it is given. The keys of the scope are written
/// from the scope: a row cannot be inserted for another tenant or realm
/// than the one of the unit of work.
pub(crate) struct Insert<'a> {
    table: Table,
    assignments: Vec<Bind<'a>>,
}

impl<'a> Insert<'a> {
    pub(crate) fn into(table: Table, assignments: Vec<Bind<'a>>) -> Self {
        Self { table, assignments }
    }

    pub(crate) fn build(self) -> Built<'a> {
        let keys = self.table.keys.count();
        let mut names = String::from(self.table.keys.names());
        for bind in &self.assignments {
            names.push_str(", ");
            names.push_str(bind.column.0);
        }
        let placeholders: Vec<String> = (1..=keys + self.assignments.len())
            .map(|position| format!("${position}"))
            .collect();
        let values: Vec<Value<'a>> = self.assignments.iter().map(|bind| bind.value).collect();
        Built::new(
            format!(
                "INSERT INTO {} ({names}) VALUES ({})",
                self.table.name,
                placeholders.join(", ")
            ),
            self.table.keys,
            values,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Insert;
    use crate::query::bind::col;
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

    #[test]
    fn an_insert_writes_the_keys_of_the_scope_before_anything_else() {
        let built = Insert::into(NOTES, vec![col(ID, &7_i32), col(BODY, &"hello")]).build();

        assert_eq!(
            built.sql,
            "INSERT INTO notes (tenant_id, realm_id, note_id, body) VALUES ($1, $2, $3, $4)"
        );
        assert_eq!(
            built.count_values(),
            2,
            "the scope keys come from the unit of work"
        );
    }

    #[test]
    fn a_table_keyed_by_the_tenant_alone_takes_one_scope_parameter() {
        let built = Insert::into(ACCOUNTS, vec![col(BODY, &"hello")]).build();

        assert_eq!(
            built.sql,
            "INSERT INTO accounts (tenant_id, body) VALUES ($1, $2)"
        );
    }
}
