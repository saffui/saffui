use super::bind::{Bind, BuildError, Built, Value};
use super::criteria::Criteria;
use super::ident::Table;

/// An update of the pairs it is given, on the rows its criteria select.
/// Both halves in one call: what is set and what selects the rows are
/// never two lists matched by eye.
pub(crate) struct Update<'a> {
    table: Table,
    assignments: Vec<Bind<'a>>,
    criteria: Criteria<'a>,
}

impl<'a> Update<'a> {
    pub(crate) fn table(table: Table, assignments: Vec<Bind<'a>>, criteria: Criteria<'a>) -> Self {
        Self {
            table,
            assignments,
            criteria,
        }
    }

    /// The placeholders of the criteria continue after those of the
    /// assignments, which is the order the values are handed over in.
    ///
    /// Without a criterion the update would reach every row of the scope,
    /// and without a pair it would write nothing: neither builds.
    pub(crate) fn build(self) -> Result<Built<'a>, BuildError> {
        if self.assignments.is_empty() {
            return Err(BuildError::NothingToWrite);
        }
        if self.criteria.is_empty() {
            return Err(BuildError::Unfiltered);
        }
        let keys = self.table.keys.count();
        let assignments: Vec<String> = self
            .assignments
            .iter()
            .enumerate()
            .map(|(position, bind)| format!("{} = ${}", bind.column.0, keys + position + 1))
            .collect();
        let mut sql = format!("UPDATE {} SET {}", self.table.name, assignments.join(", "));
        sql.push_str(self.table.keys.predicate());
        let mut values: Vec<Value<'a>> = self.assignments.iter().map(|bind| bind.value).collect();
        let next = keys + values.len() + 1;
        values.extend(self.criteria.write(&mut sql, next));
        Ok(Built::new(sql, self.table.keys, values))
    }
}

#[cfg(test)]
mod tests {
    use super::Update;
    use crate::query::bind::{BuildError, col};
    use crate::query::criteria::Criteria;
    use crate::query::ident::{Column, ScopeKeys, Table};

    const NOTES: Table = Table {
        name: "notes",
        keys: ScopeKeys::TenantAndRealm,
    };
    const ID: Column = Column("note_id");
    const BODY: Column = Column("body");
    const EDITED: Column = Column("edited");

    #[test]
    fn an_update_numbers_what_it_writes_before_what_it_filters_on() {
        let criteria = Criteria::new()
            .where_equal(ID, &7_i32)
            .where_equal(EDITED, &false);

        let built = Update::table(NOTES, vec![col(BODY, &"edited")], criteria)
            .build()
            .expect("a filtered update");

        assert_eq!(
            built.sql,
            "UPDATE notes SET body = $3 WHERE tenant_id = $1 AND realm_id = $2 \
             AND note_id = $4 AND edited = $5"
        );
        assert_eq!(built.count_values(), 3);
    }

    #[test]
    fn an_update_that_names_no_row_or_writes_no_column_does_not_build() {
        let unfiltered = Update::table(NOTES, vec![col(BODY, &"edited")], Criteria::new())
            .build()
            .map(|built| built.sql);
        let empty = Update::table(NOTES, Vec::new(), Criteria::new().where_equal(ID, &7_i32))
            .build()
            .map(|built| built.sql);

        assert_eq!(unfiltered, Err(BuildError::Unfiltered));
        assert_eq!(empty, Err(BuildError::NothingToWrite));
    }
}
