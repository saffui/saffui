use models::entities::attributes::AttributeValue;
use models::entities::user::UserModel;
use store::providers::birthright::BirthrightRule;

/// The roles this person should hold under the rules: the union of every
/// enabled rule whose predicate matches. Pure, and the whole of joiner,
/// mover and repair; leaver is the case where the person is switched off
/// and the answer is empty.
pub fn desired(rules: &[BirthrightRule], person: &UserModel) -> Vec<(String, String)> {
    if !person.enabled {
        return Vec::new();
    }
    let mut wanted: Vec<(String, String)> = Vec::new();
    for rule in rules.iter().filter(|rule| rule.enabled) {
        if !matches(rule, person) {
            continue;
        }
        for role in &rule.roles {
            if !wanted.iter().any(|(held, _)| held == role) {
                wanted.push((role.clone(), rule.rule_id.clone()));
            }
        }
    }
    wanted
}

fn matches(rule: &BirthrightRule, person: &UserModel) -> bool {
    if let Some(expr) = rule.when_expr.as_deref() {
        return matches_expr(expr, person).unwrap_or(false);
    }
    if rule.when_attribute == "*" {
        return true;
    }
    held_value(person, &rule.when_attribute).as_deref() == Some(rule.when_value.as_str())
}

/// What the predicate may read: the person's attributes, and the two names
/// every person carries without one.
fn held_value(person: &UserModel, named: &str) -> Option<String> {
    match named {
        "user_name" => Some(person.user_name.clone()),
        "email" => Some(person.email.clone()),
        _ => person
            .attributes
            .as_ref()
            .and_then(|bag| bag.get(named))
            .and_then(AttributeValue::as_str)
            .map(str::to_owned),
    }
}

/// A composed predicate: `name=value` and `name!=value` terms joined by
/// `&&`, every term of which must hold. Absence is inequality: a person
/// without the attribute fails `=` and passes `!=`, which is what "everyone
/// but the contractors" has to mean for someone with no employment type.
///
/// Returns nothing for an expression that does not parse, and the caller
/// reads that as no match: a rule whose condition cannot be read grants
/// nothing rather than everything.
pub fn matches_expr(expr: &str, person: &UserModel) -> Option<bool> {
    for term in expr.split("&&") {
        let term = term.trim();
        if term.is_empty() {
            return None;
        }
        let (named, wanted, negated) = if let Some((named, wanted)) = term.split_once("!=") {
            (named.trim(), wanted.trim(), true)
        } else if let Some((named, wanted)) = term.split_once('=') {
            (named.trim(), wanted.trim(), false)
        } else {
            return None;
        };
        if named.is_empty() || wanted.is_empty() {
            return None;
        }
        let holds = held_value(person, named).as_deref() == Some(wanted);
        if holds == negated {
            return Some(false);
        }
    }
    Some(true)
}

/// Whether an expression is one the engine will be able to read, for the
/// door that accepts rules to refuse what would silently grant nothing.
pub fn expr_parses(expr: &str) -> bool {
    !expr.trim().is_empty()
        && expr.split("&&").all(|term| {
            let term = term.trim();
            let split = term.split_once("!=").or_else(|| term.split_once('='));
            split.is_some_and(|(named, wanted)| {
                !named.trim().is_empty() && !wanted.trim().is_empty()
            })
        })
}

/// What must change to make the ledger match the due set.
pub struct Diff {
    pub grant: Vec<(String, String)>,
    pub revoke: Vec<String>,
}

pub fn diff(desired: &[(String, String)], governed: &[(String, String)]) -> Diff {
    Diff {
        grant: desired
            .iter()
            .filter(|(role, _)| !governed.iter().any(|(held, _)| held == role))
            .cloned()
            .collect(),
        revoke: governed
            .iter()
            .filter(|(role, _)| !desired.iter().any(|(wanted, _)| wanted == role))
            .map(|(role, _)| role.clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributesMap;

    fn person(enabled: bool, bag: &[(&str, &str)]) -> UserModel {
        UserModel {
            user_id: "ada".into(),
            realm_id: "main".into(),
            user_name: "ada".into(),
            enabled,
            email: String::new(),
            email_verified: None,
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            attributes: Some(
                bag.iter()
                    .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).into())))
                    .collect::<AttributesMap>(),
            ),
            is_service_account: None,
            service_account_client_link: None,
            metadata: AuditableModel::from_creator("acme".into(), "root".into()),
        }
    }

    fn rule(id: &str, attribute: &str, value: &str, roles: &[&str]) -> BirthrightRule {
        BirthrightRule {
            rule_id: id.into(),
            when_attribute: attribute.into(),
            when_value: value.into(),
            when_expr: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            priority: 0,
            enabled: true,
        }
    }

    #[test]
    fn a_composed_predicate_reads_every_term_or_nothing() {
        let engineer = person(true, &[("department", "eng"), ("employment", "staff")]);
        let contractor = person(true, &[("department", "eng"), ("employment", "contractor")]);
        let unlabelled = person(true, &[("department", "eng")]);

        let expr = "department=eng && employment!=contractor";
        assert_eq!(matches_expr(expr, &engineer), Some(true));
        assert_eq!(matches_expr(expr, &contractor), Some(false));
        assert_eq!(
            matches_expr(expr, &unlabelled),
            Some(true),
            "absence passes an inequality"
        );
        assert_eq!(
            matches_expr("department=sales", &unlabelled),
            Some(false),
            "the wrong value fails an equality"
        );
        assert_eq!(matches_expr("user_name=ada", &engineer), Some(true));

        for broken in ["", "department", "=eng", "department= && x=y"] {
            assert_eq!(matches_expr(broken, &engineer), None, "{broken:?}");
            assert!(!expr_parses(broken), "{broken:?}");
        }
        assert!(expr_parses("a=b && c!=d"));

        let mut ruled = rule("r", "*", "", &["all-hands"]);
        ruled.when_expr = Some("department=eng && employment!=contractor".into());
        assert_eq!(
            desired(&[ruled.clone()], &engineer),
            vec![("all-hands".to_owned(), "r".to_owned())]
        );
        assert!(desired(&[ruled], &contractor).is_empty());
    }

    #[test]
    fn the_due_set_is_a_function_of_who_they_are() {
        let rules = [
            rule("everyone", "*", "", &["staff"]),
            rule("eng", "department", "engineering", &["engineers", "staff"]),
            rule("hrteam", "department", "hr", &["hr-readers"]),
        ];
        let due = desired(&rules, &person(true, &[("department", "engineering")]));
        assert_eq!(
            due.iter()
                .map(|(role, _)| role.as_str())
                .collect::<Vec<_>>(),
            vec!["staff", "engineers"],
            "union, first rule keeps a disputed role"
        );
        assert_eq!(
            desired(&rules, &person(false, &[("department", "engineering")])),
            Vec::new(),
            "a switched-off person is due nothing"
        );

        let moved = diff(
            &desired(&rules, &person(true, &[("department", "hr")])),
            &[
                ("staff".into(), "everyone".into()),
                ("engineers".into(), "eng".into()),
            ],
        );
        assert_eq!(
            moved
                .grant
                .iter()
                .map(|(role, _)| role.as_str())
                .collect::<Vec<_>>(),
            vec!["hr-readers"]
        );
        assert_eq!(moved.revoke, vec!["engineers"]);

        let steady = diff(
            &desired(&rules, &person(true, &[("department", "hr")])),
            &[
                ("staff".into(), "everyone".into()),
                ("hr-readers".into(), "hrteam".into()),
            ],
        );
        assert!(
            steady.grant.is_empty() && steady.revoke.is_empty(),
            "convergence is idempotent"
        );
    }
}
