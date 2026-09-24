//! The engine's rules as an administrator writes them: birthright rules and
//! the grants they hold, grants written by hand with an end, and separation
//! of duties with its exceptions.

use chrono::{DateTime, Utc};
use store::providers::directory::{roles, users};
use store::providers::governance::birthright::{self, BirthrightRule};
use store::providers::governance::sod::{self, SodException, SodRule};
use store::query::list_query::ListQuery;
use store::tenancy::UnitOfWork;

use crate::governance::sod::{Toxic, excused, offences, weigh};

/// Why a change to the rules was not made, or they could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unruled {
    /// In words the administrator is meant to read.
    #[error("{0}")]
    Invalid(String),
    #[error("no such user")]
    NoSuchUser,
    #[error("no such rule")]
    NoSuchRule,
    #[error("the store could not be read or written")]
    Backend,
}

fn invalid(said: &str) -> Unruled {
    Unruled::Invalid(said.to_owned())
}

/// A role granted by the ledger: the role, the rule that holds it when a rule
/// does, and the end of a grant written by hand.
pub type Held = (String, Option<String>, Option<DateTime<Utc>>);

/// A combination a separation refuses, standing now, and whether an
/// exception excuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub user_id: String,
    pub user_name: String,
    pub rule_id: String,
    pub roles: Vec<String>,
    pub excused: bool,
}

pub async fn birthright_rules(transaction: &UnitOfWork) -> Result<Vec<BirthrightRule>, Unruled> {
    birthright::rules(transaction)
        .await
        .map_err(|_| Unruled::Backend)
}

/// A birthright rule as asked for, held to the shape the engine reads: an
/// expression is the whole condition, or an attribute names who with a value
/// to equal. Pure, so a malformed rule is refused before anything is opened.
pub fn shaped_birthright_rule(
    rule_id: &str,
    when_attribute: Option<&str>,
    when_value: &str,
    when_expr: Option<&str>,
    roles: Option<Vec<String>>,
    priority: i32,
    enabled: Option<bool>,
) -> Result<BirthrightRule, Unruled> {
    let when_expr = when_expr
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .map(str::to_owned);
    if let Some(expr) = when_expr.as_deref()
        && !crate::governance::lifecycle::expr_parses(expr)
    {
        return Err(invalid(
            "when_expr is name=value or name!=value terms joined by &&",
        ));
    }
    let when_attribute = match (
        when_expr.is_some(),
        when_attribute
            .map(str::trim)
            .filter(|held| !held.is_empty()),
    ) {
        // The expression is the whole condition; the pair beside it is
        // decoration nothing reads, so it is refused rather than kept.
        (true, Some(_)) => {
            return Err(invalid(
                "when_expr is the whole condition: drop when_attribute",
            ));
        }
        (true, None) => "*",
        (false, Some(named)) => named,
        (false, None) => {
            return Err(invalid(
                "when_attribute names an attribute, or * for everybody",
            ));
        }
    };
    if when_expr.is_none() && when_attribute != "*" && when_value.trim().is_empty() {
        return Err(invalid("when_value names what the attribute must equal"));
    }
    let Some(roles) =
        roles.filter(|held| !held.is_empty() && held.iter().all(|role| !role.trim().is_empty()))
    else {
        return Err(invalid("roles names what the rule grants"));
    };
    Ok(BirthrightRule {
        rule_id: rule_id.to_owned(),
        when_attribute: when_attribute.to_owned(),
        when_value: when_value.trim().to_owned(),
        when_expr,
        roles,
        priority,
        enabled: enabled.unwrap_or(true),
    })
}

/// Keep a birthright rule whose every role exists.
pub async fn keep_birthright_rule(
    transaction: &UnitOfWork,
    rule: &BirthrightRule,
    by: &str,
) -> Result<(), Unruled> {
    refuse_roles_nobody_holds(transaction, &rule.roles).await?;
    birthright::keep_rule(transaction, rule, by)
        .await
        .map_err(|_| Unruled::Backend)
}

pub async fn drop_birthright_rule(transaction: &UnitOfWork, rule_id: &str) -> Result<(), Unruled> {
    birthright::drop_rule(transaction, rule_id)
        .await
        .map_err(|_| Unruled::Backend)?
        .then_some(())
        .ok_or(Unruled::NoSuchRule)
}

/// Grant a role until an instant, by hand: the engine takes it back then.
/// Weighed against the separations like every other grant, so a hand cannot
/// write what a rule refuses. Answers with the person's identifier.
pub async fn grant_until(
    transaction: &UnitOfWork,
    user: &str,
    role_id: &str,
    by: &str,
    expires_at: DateTime<Utc>,
) -> Result<String, Unruled> {
    let user_id = crate::admin::users::identified(transaction, user)
        .await
        .map(|held| held.user_id)
        .map_err(|_| invalid("no user answers to that name"))?;
    if roles::load(transaction, role_id)
        .await
        .map_err(|_| Unruled::Backend)?
        .is_none()
    {
        return Err(invalid("no role answers to that name"));
    }
    sod::hold_person(transaction, &user_id)
        .await
        .map_err(|_| Unruled::Backend)?;
    roles::grant_to_user(transaction, &user_id, role_id)
        .await
        .map_err(|_| Unruled::Backend)?;
    match weigh(transaction, &user_id).await {
        Ok(()) => {}
        Err(Toxic::Refused(said)) => return Err(Unruled::Invalid(said)),
        Err(Toxic::Backend) => return Err(Unruled::Backend),
    }
    birthright::record_timed_grant(transaction, &user_id, role_id, by, expires_at)
        .await
        .map_err(|_| Unruled::Backend)?;
    Ok(user_id)
}

/// What the engine holds for one person, from rules and from hands.
pub async fn ledger_of(transaction: &UnitOfWork, user_id: &str) -> Result<Vec<Held>, Unruled> {
    birthright::ledger_of(transaction, user_id)
        .await
        .map_err(|_| Unruled::Backend)
}

/// Take a grant written by hand back before its end.
pub async fn take_back_grant(
    transaction: &UnitOfWork,
    user_id: &str,
    role_id: &str,
) -> Result<(), Unruled> {
    roles::revoke_from_user(transaction, user_id, role_id)
        .await
        .map_err(|_| Unruled::Backend)?;
    birthright::erase_grant(transaction, user_id, role_id)
        .await
        .map_err(|_| Unruled::Backend)?;
    Ok(())
}

pub async fn sod_rules(transaction: &UnitOfWork) -> Result<Vec<SodRule>, Unruled> {
    sod::rules(transaction).await.map_err(|_| Unruled::Backend)
}

/// A separation as asked for: at least two roles, each named once, and a
/// threshold between two and all of them, the whole set when none is said.
pub fn shaped_sod_rule(
    rule_id: &str,
    roles: Option<Vec<String>>,
    min_conflicting: Option<i32>,
    enabled: Option<bool>,
) -> Result<SodRule, Unruled> {
    let roles: Vec<String> = roles
        .unwrap_or_default()
        .iter()
        .map(|role| role.trim().to_owned())
        .filter(|role| !role.is_empty())
        .collect();
    if roles.len() < 2 {
        return Err(invalid("a separation needs at least two roles to separate"));
    }
    if roles
        .iter()
        .enumerate()
        .any(|(at, role)| roles[..at].contains(role))
    {
        return Err(invalid("each role is named once"));
    }
    let min_conflicting = min_conflicting.unwrap_or(roles.len() as i32);
    if min_conflicting < 2 || min_conflicting as usize > roles.len() {
        return Err(invalid(
            "min_conflicting is between 2 and the number of roles named",
        ));
    }
    Ok(SodRule {
        rule_id: rule_id.to_owned(),
        roles,
        min_conflicting,
        enabled: enabled.unwrap_or(true),
    })
}

/// Keep a separation whose every role exists.
pub async fn keep_sod_rule(
    transaction: &UnitOfWork,
    rule: &SodRule,
    by: &str,
) -> Result<(), Unruled> {
    refuse_roles_nobody_holds(transaction, &rule.roles).await?;
    sod::keep_rule(transaction, rule, by)
        .await
        .map_err(|_| Unruled::Backend)
}

pub async fn drop_sod_rule(transaction: &UnitOfWork, rule_id: &str) -> Result<(), Unruled> {
    sod::drop_rule(transaction, rule_id)
        .await
        .map_err(|_| Unruled::Backend)?
        .then_some(())
        .ok_or(Unruled::NoSuchRule)
}

/// Every combination a separation refuses standing right now, weighed where
/// it is read: nothing here is stored, so nothing here can be stale. Excused
/// ones are listed too, marked; an auditor wants the excuse visible, not the
/// fact gone.
pub async fn standing_violations(
    transaction: &UnitOfWork,
    now: DateTime<Utc>,
) -> Result<Vec<Violation>, Unruled> {
    let rules = sod::rules(transaction)
        .await
        .map_err(|_| Unruled::Backend)?;
    let mut found = Vec::new();
    if !rules.iter().any(|rule| rule.enabled) {
        return Ok(found);
    }
    let mut first: i64 = 0;
    loop {
        let query = ListQuery::new(models::paging::Window {
            first,
            max: 200,
            clamped: false,
        });
        let page = users::list(transaction, &query, false)
            .await
            .map_err(|_| Unruled::Backend)?;
        if page.items.is_empty() {
            break;
        }
        first += page.items.len() as i64;
        for person in &page.items {
            let effective: Vec<String> = roles::effective_roles(transaction, &person.user_id)
                .await
                .map_err(|_| Unruled::Backend)?
                .into_iter()
                .map(|role| role.role_id)
                .collect();
            let reached = offences(&rules, &effective);
            if reached.is_empty() {
                continue;
            }
            let standing = sod::exceptions_of(transaction, &person.user_id)
                .await
                .map_err(|_| Unruled::Backend)?;
            for offence in reached {
                found.push(Violation {
                    user_id: person.user_id.clone(),
                    user_name: person.user_name.clone(),
                    rule_id: offence.rule_id.clone(),
                    excused: excused(&offence, &standing, now),
                    roles: offence.held,
                });
            }
        }
    }
    Ok(found)
}

pub async fn sod_exceptions(transaction: &UnitOfWork) -> Result<Vec<SodException>, Unruled> {
    sod::exceptions(transaction)
        .await
        .map_err(|_| Unruled::Backend)
}

/// Excuse one person from one separation until an instant. The rule is read
/// first, then the person, then the roles covered, which must be ones the rule
/// separates and at least as many as it takes to be refused: fewer excuse
/// nothing. Answers with the person's identifier.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one exception"
)]
pub async fn keep_sod_exception(
    transaction: &UnitOfWork,
    rule_id: &str,
    user: &str,
    covered_roles: Option<Vec<String>>,
    justification: &str,
    valid_until: DateTime<Utc>,
    by: &str,
) -> Result<(String, Vec<String>), Unruled> {
    let rule = sod::rules(transaction)
        .await
        .map_err(|_| Unruled::Backend)?
        .into_iter()
        .find(|rule| rule.rule_id == rule_id)
        .ok_or_else(|| invalid("no separation rule answers to that name"))?;
    let user_id = crate::admin::users::identified(transaction, user)
        .await
        .map(|held| held.user_id)
        .map_err(|_| Unruled::NoSuchUser)?;

    let covered: Vec<String> = covered_roles
        .unwrap_or_default()
        .iter()
        .map(|role| role.trim().to_owned())
        .filter(|role| !role.is_empty())
        .collect();
    if covered.iter().any(|role| !rule.roles.contains(role)) {
        return Err(invalid("covered_roles only names roles the rule separates"));
    }
    if (covered.len() as i32) < rule.min_conflicting {
        return Err(invalid(
            "covered_roles names a combination the rule would refuse: fewer roles than \
             min_conflicting excuse nothing",
        ));
    }
    sod::keep_exception(
        transaction,
        &SodException {
            rule_id: rule_id.to_owned(),
            user_id: user_id.clone(),
            covered_roles: covered.clone(),
            justification: justification.to_owned(),
            granted_by: by.to_owned(),
            valid_until,
        },
    )
    .await
    .map_err(|_| Unruled::Backend)?;
    Ok((user_id, covered))
}

pub async fn drop_sod_exception(
    transaction: &UnitOfWork,
    rule_id: &str,
    user_id: &str,
) -> Result<(), Unruled> {
    sod::drop_exception(transaction, rule_id, user_id)
        .await
        .map_err(|_| Unruled::Backend)?
        .then_some(())
        .ok_or(Unruled::NoSuchRule)
}

/// Refuse the first named role that nobody holds, in words.
async fn refuse_roles_nobody_holds(
    transaction: &UnitOfWork,
    named: &[String],
) -> Result<(), Unruled> {
    for role in named {
        if roles::load(transaction, role)
            .await
            .map_err(|_| Unruled::Backend)?
            .is_none()
        {
            return Err(Unruled::Invalid(format!("no role answers to {role}")));
        }
    }
    Ok(())
}
