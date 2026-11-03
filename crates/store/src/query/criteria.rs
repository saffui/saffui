//! The tests a row must pass. A column is a constant, a test is one of a
//! closed list, and a value is bound: nothing of a criterion is text a
//! caller wrote. A test is added here the day a statement needs it.

use super::bind::Value;
use super::ident::Column;

enum Test<'a> {
    Equal(Value<'a>),
    Greater(Value<'a>),
}

/// The tests of one statement, after the scope.
#[derive(Default)]
pub(crate) struct Criteria<'a> {
    tests: Vec<(Column, Test<'a>)>,
}

impl<'a> Criteria<'a> {
    pub(crate) fn new() -> Self {
        Self { tests: Vec::new() }
    }

    /// Keeps the rows where the column holds the value.
    pub(crate) fn where_equal(mut self, column: Column, value: Value<'a>) -> Self {
        self.tests.push((column, Test::Equal(value)));
        self
    }

    /// Keeps the rows where the column holds more than the value.
    pub(crate) fn where_greater(mut self, column: Column, value: Value<'a>) -> Self {
        self.tests.push((column, Test::Greater(value)));
        self
    }

    /// Writes each test after the scope predicate, numbering placeholders
    /// from `next`, and returns what they bind, in that order.
    pub(super) fn write(&self, sql: &mut String, next: usize) -> Vec<Value<'a>> {
        let mut bound = Vec::new();
        for (column, test) in &self.tests {
            sql.push_str(" AND ");
            sql.push_str(column.0);
            let (operator, value) = match test {
                Test::Equal(value) => (" = $", value),
                Test::Greater(value) => (" > $", value),
            };
            sql.push_str(operator);
            sql.push_str(&(next + bound.len()).to_string());
            bound.push(*value);
        }
        bound
    }
}

#[cfg(test)]
mod tests {
    use super::Criteria;
    use crate::query::ident::Column;

    const SEQ: Column = Column("seq");
    const EXPIRES_AT: Column = Column("expires_at");
    const CLIENT_ID: Column = Column("client_id");

    #[test]
    fn each_test_takes_the_next_placeholder_after_the_scope() {
        let mut sql = String::new();
        let criteria = Criteria::new()
            .where_greater(SEQ, &3_i64)
            .where_equal(CLIENT_ID, &"billing")
            .where_greater(EXPIRES_AT, &7_i64);

        let bound = criteria.write(&mut sql, 3);

        assert_eq!(sql, " AND seq > $3 AND client_id = $4 AND expires_at > $5");
        assert_eq!(bound.len(), 3);
    }
}
