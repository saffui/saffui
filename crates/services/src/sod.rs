use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use store::providers::sod::{SodException, SodRule};

/// One toxic combination actually reached: the rule, and the members of
/// its set this person holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Offence {
    pub rule_id: String,
    pub held: Vec<String>,
}

/// Every enabled rule whose threshold this set of roles reaches. Members
/// are role identifiers, the same the effective set is read in, so a held
/// role counts once and the count is exact; a disabled rule weighs nothing.
pub fn offences(rules: &[SodRule], effective: &[String]) -> Vec<Offence> {
    rules
        .iter()
        .filter(|rule| rule.enabled)
        .filter_map(|rule| {
            let held: Vec<String> = rule
                .roles
                .iter()
                .filter(|member| effective.iter().any(|role| role == *member))
                .cloned()
                .collect();
            (held.len() >= rule.min_conflicting.max(0) as usize).then(|| Offence {
                rule_id: rule.rule_id.clone(),
                held,
            })
        })
        .collect()
}

/// Whether a standing exception excuses this offence: same rule, still
/// valid, and covering every role of the combination reached. A set the
/// exception does not wholly cover re-arms the block.
pub fn excused(offence: &Offence, exceptions: &[SodException], now: DateTime<Utc>) -> bool {
    exceptions.iter().any(|exception| {
        exception.rule_id == offence.rule_id
            && exception.valid_until > now
            && offence
                .held
                .iter()
                .all(|role| exception.covered_roles.contains(role))
    })
}

/// The refusal, in the operator's words.
pub fn words(offence: &Offence) -> String {
    format!(
        "rule {} forbids holding {} in one pair of hands",
        offence.rule_id,
        offence.held.join(", ")
    )
}

pub enum Toxic {
    Refused(String),
    Backend,
}

/// Weigh a person's roles as they now stand, inside the transaction that
/// changed them: an offence no exception covers aborts the change. Callers
/// take the per-person hold first, so two halves of a pair cannot each
/// weigh a world without the other.
pub async fn weigh(transaction: &Transaction<'_>, user_id: &str) -> Result<(), Toxic> {
    let rules = store::providers::sod::rules(transaction)
        .await
        .map_err(|_| Toxic::Backend)?;
    weigh_against(transaction, &rules, user_id).await
}

/// Weigh everyone a change to many people at once reaches, inside the
/// transaction that made it: a role given to a group, a role placed under
/// another, a group moved under a new parent. The caller holds the realm first.
///
/// `arriving` is every role the change can newly put in somebody's hands. When
/// no enabled rule names one of them, the change cannot have brought an offence
/// about, and nobody is weighed: that is the common case, and it costs one read.
pub async fn weigh_everyone(
    transaction: &Transaction<'_>,
    people: &[String],
    arriving: &[String],
) -> Result<(), Toxic> {
    let rules = store::providers::sod::rules(transaction)
        .await
        .map_err(|_| Toxic::Backend)?;
    let named = |role: &String| {
        rules
            .iter()
            .filter(|rule| rule.enabled)
            .any(|rule| rule.roles.contains(role))
    };
    if !arriving.iter().any(named) {
        return Ok(());
    }
    for person in people {
        weigh_against(transaction, &rules, person)
            .await
            .map_err(|toxic| match toxic {
                Toxic::Refused(said) => Toxic::Refused(format!("{said}, for {person}")),
                Toxic::Backend => Toxic::Backend,
            })?;
    }
    Ok(())
}

async fn weigh_against(
    transaction: &Transaction<'_>,
    rules: &[SodRule],
    user_id: &str,
) -> Result<(), Toxic> {
    if !rules.iter().any(|rule| rule.enabled) {
        return Ok(());
    }
    let effective: Vec<String> = store::providers::roles::effective_roles(transaction, user_id)
        .await
        .map_err(|_| Toxic::Backend)?
        .into_iter()
        .map(|role| role.role_id)
        .collect();
    let reached = offences(rules, &effective);
    if reached.is_empty() {
        return Ok(());
    }
    let standing = store::providers::sod::exceptions_of(transaction, user_id)
        .await
        .map_err(|_| Toxic::Backend)?;
    let now = Utc::now();
    match reached
        .into_iter()
        .find(|offence| !excused(offence, &standing, now))
    {
        Some(offence) => Err(Toxic::Refused(words(&offence))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, roles: &[&str], min: i32, enabled: bool) -> SodRule {
        SodRule {
            rule_id: id.into(),
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            min_conflicting: min,
            enabled,
        }
    }

    fn held(roles: &[&str]) -> Vec<String> {
        roles.iter().map(|role| (*role).to_owned()).collect()
    }

    fn exception(rule_id: &str, covered: &[&str], hours_left: i64) -> SodException {
        SodException {
            rule_id: rule_id.into(),
            user_id: "ada".into(),
            covered_roles: covered.iter().map(|role| (*role).to_owned()).collect(),
            justification: "audit season".into(),
            granted_by: "root".into(),
            valid_until: Utc::now() + chrono::Duration::hours(hours_left),
        }
    }

    #[test]
    fn the_threshold_counts_exactly_and_a_disabled_rule_weighs_nothing() {
        let rules = [
            rule("payments", &["payer", "approver", "auditor"], 2, true),
            rule("dormant", &["payer", "approver"], 2, false),
        ];
        assert!(offences(&rules, &held(&["payer"])).is_empty());
        assert!(offences(&rules, &held(&["payer", "unrelated"])).is_empty());

        let reached = offences(&rules, &held(&["approver", "payer"]));
        assert_eq!(reached.len(), 1, "the disabled twin stays silent");
        assert_eq!(reached[0].rule_id, "payments");
        assert_eq!(
            reached[0].held,
            held(&["payer", "approver"]),
            "held members answer in the rule's order"
        );

        let all_three = offences(&rules, &held(&["auditor", "approver", "payer"]));
        assert_eq!(all_three[0].held.len(), 3);
    }

    #[test]
    fn an_exception_excuses_its_exact_combination_and_no_wider_one() {
        let offence = Offence {
            rule_id: "payments".into(),
            held: held(&["payer", "approver"]),
        };
        let now = Utc::now();

        assert!(excused(
            &offence,
            &[exception("payments", &["payer", "approver"], 24)],
            now
        ));
        assert!(
            !excused(
                &offence,
                &[exception("payments", &["payer", "auditor"], 24)],
                now
            ),
            "a different combination under the same rule stays blocked"
        );
        let wider = Offence {
            rule_id: "payments".into(),
            held: held(&["payer", "approver", "auditor"]),
        };
        assert!(
            !excused(
                &wider,
                &[exception("payments", &["payer", "approver"], 24)],
                now
            ),
            "the set grew past what was excused, so the block re-arms"
        );
        assert!(
            !excused(
                &offence,
                &[exception("payments", &["payer", "approver"], -1)],
                now
            ),
            "a lapsed exception excuses nothing"
        );
        assert!(!excused(
            &offence,
            &[exception("elsewhere", &["payer", "approver"], 24)],
            now
        ));
    }
}
