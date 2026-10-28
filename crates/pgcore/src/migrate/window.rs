//! Which schema versions a binary can serve. During a rolling upgrade old and
//! new nodes run together: a node whose schema moved past what it knows must
//! stop taking traffic, because a peer now writes what it cannot read.

use super::Migration;

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct SchemaWindow {
    /// The oldest schema this binary still reads and writes correctly.
    pub oldest: i32,
    /// The newest schema this binary knows: its last embedded migration.
    pub newest: i32,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum SchemaStanding {
    Within,
    /// Migrations this binary needs have not been applied.
    Behind,
    /// Migrations this binary does not know have been applied.
    Ahead,
}

impl SchemaWindow {
    /// The window of a binary that reads exactly the schema it embeds.
    #[must_use]
    pub fn of_exactly(migrations: &[Migration]) -> Self {
        let newest = migrations.last().map_or(0, |last| last.version);
        Self {
            oldest: newest,
            newest,
        }
    }

    #[must_use]
    pub fn judge(self, version: i32) -> SchemaStanding {
        if version < self.oldest {
            SchemaStanding::Behind
        } else if version > self.newest {
            SchemaStanding::Ahead
        } else {
            SchemaStanding::Within
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SchemaStanding, SchemaWindow};

    #[test]
    fn a_version_is_judged_against_both_ends_of_the_window() {
        let window = SchemaWindow {
            oldest: 3,
            newest: 5,
        };

        assert_eq!(window.judge(2), SchemaStanding::Behind);
        assert_eq!(window.judge(3), SchemaStanding::Within);
        assert_eq!(window.judge(5), SchemaStanding::Within);
        assert_eq!(window.judge(6), SchemaStanding::Ahead);
    }
}
