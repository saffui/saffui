//! A column and the value going into it, kept together.
//!
//! # The mistake this makes unwritable
//!
//! A write names its columns in one place and binds its values in another. The
//! driver's binds are positional and untyped, so nothing relates the two lists.
//! Add a column and forget its value, or add it in the wrong position, and the
//! code compiles clean and writes the wrong value into the wrong column.
//!
//! The database catches only the arity half of that, and only if something
//! actually runs the write. A path with no caller is never checked at all, and
//! adding one column to a table means hand-editing every bind list that touches
//! it with the build staying green throughout.
//!
//! # The shape
//!
//! One expression yields both. A [`WriteSet`] is a list of pairs, and the column
//! list handed to the builder and the values handed to the driver are both
//! derived from it. There is no second list to drift.
//!
//! The filter is part of the same set, deliberately. Its values are bound
//! positionally too, numbered after the assignments, so modelling only the
//! assignments would leave half the statement open to the same mistake.

use postgres_types::ToSql;

/// One column and the value going into it.
///
/// Built only through [`col`], so a column name never exists without the value
/// that goes with it.
pub struct Bind<'a> {
    column: &'static str,
    value: &'a (dyn ToSql + Sync),
}

impl<'a> Bind<'a> {
    pub fn column(&self) -> &'static str {
        self.column
    }

    pub fn value(&self) -> &'a (dyn ToSql + Sync) {
        self.value
    }
}

/// Pair a column with its value.
///
/// The name is a compile time string on purpose. A column is part of the schema
/// and known when the code is written, and accepting an owned string would let a
/// computed name in, which in a write is either a mistake or an injection.
pub fn col<'a>(column: &'static str, value: &'a (dyn ToSql + Sync)) -> Bind<'a> {
    Bind { column, value }
}

/// Everything one statement writes, and what it writes it to.
///
/// The order is the statement's order: assignments first, then the values the
/// filter keys on, which is how the placeholders are numbered.
pub struct WriteSet<'a> {
    assignments: Vec<Bind<'a>>,
    filter: Vec<Bind<'a>>,
}

impl<'a> WriteSet<'a> {
    /// An insert: columns and values, nothing to key on.
    pub fn insert(assignments: Vec<Bind<'a>>) -> Self {
        WriteSet {
            assignments,
            filter: Vec::new(),
        }
    }

    /// An update: what to set, and the columns that select the rows.
    ///
    /// Both halves in one call. Splitting them into a builder step and a
    /// separate argument is the very separation this removes.
    pub fn update(assignments: Vec<Bind<'a>>, filter: Vec<Bind<'a>>) -> Self {
        WriteSet {
            assignments,
            filter,
        }
    }

    /// The columns being assigned.
    pub fn columns(&self) -> Vec<&'static str> {
        self.assignments.iter().map(Bind::column).collect()
    }

    /// The columns the filter keys on, in placeholder order.
    pub fn filter_columns(&self) -> Vec<&'static str> {
        self.filter.iter().map(Bind::column).collect()
    }

    /// Every value, in the order the statement numbers its placeholders.
    ///
    /// This is the whole point: what is handed to the driver is computed from
    /// the same pairs the column list is computed from, so the two cannot
    /// disagree because there is nothing to keep in step.
    pub fn params(&self) -> Vec<&'a (dyn ToSql + Sync)> {
        self.assignments
            .iter()
            .chain(self.filter.iter())
            .map(Bind::value)
            .collect()
    }

    /// How many placeholders the statement carries.
    pub fn len(&self) -> usize {
        self.assignments.len() + self.filter.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(value: &(dyn ToSql + Sync)) -> String {
        format!("{value:?}")
    }

    /// The columns and the values come from one list, so they agree by
    /// construction rather than by anyone remembering.
    #[test]
    fn the_columns_and_the_values_come_from_one_list() {
        let tenant = "acme".to_owned();
        let name = "ada".to_owned();
        let count: i32 = 30;

        let set = WriteSet::insert(vec![
            col("tenant", &tenant),
            col("name", &name),
            col("count", &count),
        ]);

        assert_eq!(set.columns(), vec!["tenant", "name", "count"]);
        assert_eq!(set.params().len(), set.columns().len());
        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());

        // And in the same order, which is what the placeholders count on.
        let values: Vec<String> = set.params().iter().map(|v| rendered(*v)).collect();
        assert_eq!(
            values,
            vec![rendered(&tenant), rendered(&name), rendered(&count)]
        );
    }

    /// An update numbers its filter after its assignments, because that is the
    /// order the generated statement places them in.
    #[test]
    fn an_update_numbers_its_filter_after_its_assignments() {
        let display = "Ada".to_owned();
        let tenant = "acme".to_owned();
        let id = "user-1".to_owned();

        let set = WriteSet::update(
            vec![col("display_name", &display)],
            vec![col("tenant", &tenant), col("user_id", &id)],
        );

        assert_eq!(set.columns(), vec!["display_name"]);
        assert_eq!(set.filter_columns(), vec!["tenant", "user_id"]);
        assert_eq!(set.len(), 3, "every placeholder is counted, both halves");

        let values: Vec<String> = set.params().iter().map(|v| rendered(*v)).collect();
        assert_eq!(
            values,
            vec![rendered(&display), rendered(&tenant), rendered(&id)],
            "the assignment comes first and the filter follows"
        );
    }

    /// An insert keys on nothing, so its values are its assignments and no more.
    #[test]
    fn an_insert_keys_on_nothing() {
        let tenant = "acme".to_owned();
        let set = WriteSet::insert(vec![col("tenant", &tenant)]);

        assert!(set.filter_columns().is_empty());
        assert_eq!(set.len(), 1);
        assert_eq!(set.params().len(), 1);
    }

    /// A set with nothing in it says so, since a statement built from one would
    /// assign nothing and key on nothing.
    #[test]
    fn an_empty_set_says_so() {
        let empty = WriteSet::insert(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.columns().is_empty());
        assert!(empty.params().is_empty());

        let filter_only = WriteSet::update(Vec::new(), Vec::new());
        assert!(filter_only.is_empty());
    }
}
