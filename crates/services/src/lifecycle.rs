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
    if rule.when_attribute == "*" {
        return true;
    }
    person
        .attributes
        .as_ref()
        .and_then(|bag| bag.get(&rule.when_attribute))
        .and_then(AttributeValue::as_str)
        == Some(rule.when_value.as_str())
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
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            priority: 0,
            enabled: true,
        }
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
