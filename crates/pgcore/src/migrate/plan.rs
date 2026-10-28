//! What is left to apply. The applied history must be a prefix of what the
//! binary embeds, byte for byte: anything else is refused, never repaired.

/// A migration as the plan sees it: its version and the digest of its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub version: i32,
    pub checksum: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("the embedded migrations are not numbered 1, 2, 3 and so on")]
    EmbeddedOutOfOrder,
    #[error("migration {version} was applied with another text than the one embedded here")]
    Drift { version: i32 },
    #[error("migration {version} is applied but unknown to this binary: the schema is ahead")]
    Ahead { version: i32 },
    #[error("the applied history skips migration {version}")]
    Gap { version: i32 },
}

/// Returns the versions still to apply, in order.
///
/// # Errors
///
/// Returns why the history and the embedded set cannot be reconciled.
pub fn plan_pending(
    embedded: &[Fingerprint],
    applied: &[Fingerprint],
) -> Result<Vec<i32>, PlanError> {
    for (position, migration) in embedded.iter().enumerate() {
        if i32::try_from(position + 1) != Ok(migration.version) {
            return Err(PlanError::EmbeddedOutOfOrder);
        }
    }
    for (position, done) in applied.iter().enumerate() {
        let Some(known) = embedded.get(position) else {
            return Err(PlanError::Ahead {
                version: done.version,
            });
        };
        if done.version != known.version {
            return Err(PlanError::Gap {
                version: known.version,
            });
        }
        if done.checksum != known.checksum {
            return Err(PlanError::Drift {
                version: done.version,
            });
        }
    }
    Ok(embedded
        .iter()
        .skip(applied.len())
        .map(|migration| migration.version)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{Fingerprint, PlanError, plan_pending};

    fn print(version: i32, text: &str) -> Fingerprint {
        Fingerprint {
            version,
            checksum: text.as_bytes().to_vec(),
        }
    }

    #[test]
    fn an_empty_history_leaves_everything_to_apply() {
        let embedded = [print(1, "a"), print(2, "b")];
        assert_eq!(plan_pending(&embedded, &[]), Ok(vec![1, 2]));
    }

    #[test]
    fn an_applied_prefix_leaves_the_rest() {
        let embedded = [print(1, "a"), print(2, "b"), print(3, "c")];
        assert_eq!(plan_pending(&embedded, &[print(1, "a")]), Ok(vec![2, 3]));
        assert_eq!(plan_pending(&embedded, &embedded), Ok(vec![]));
    }

    #[test]
    fn a_migration_whose_text_changed_after_it_was_applied_is_refused() {
        let embedded = [print(1, "a"), print(2, "b")];
        let applied = [print(1, "a"), print(2, "edited")];
        assert_eq!(
            plan_pending(&embedded, &applied),
            Err(PlanError::Drift { version: 2 })
        );
    }

    #[test]
    fn a_history_longer_than_the_embedded_set_is_ahead() {
        let embedded = [print(1, "a")];
        let applied = [print(1, "a"), print(2, "b")];
        assert_eq!(
            plan_pending(&embedded, &applied),
            Err(PlanError::Ahead { version: 2 })
        );
    }

    #[test]
    fn a_history_that_skips_a_version_is_refused() {
        let embedded = [print(1, "a"), print(2, "b"), print(3, "c")];
        let applied = [print(1, "a"), print(3, "c")];
        assert_eq!(
            plan_pending(&embedded, &applied),
            Err(PlanError::Gap { version: 2 })
        );
    }

    #[test]
    fn an_embedded_set_that_is_not_numbered_from_one_is_refused() {
        assert_eq!(
            plan_pending(&[print(2, "b")], &[]),
            Err(PlanError::EmbeddedOutOfOrder)
        );
        assert_eq!(
            plan_pending(&[print(1, "a"), print(3, "c")], &[]),
            Err(PlanError::EmbeddedOutOfOrder)
        );
    }
}
