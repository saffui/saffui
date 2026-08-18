//! What the evaluator answers, arm by arm and guarantee by guarantee.
//!
//! The tests that matter most here are the ones with no permit in them. A
//! policy layer is not hard to make grant when it should; it is hard to stop
//! granting when it cannot tell, and every arm below is asked what it does with
//! a fact nobody could establish.

use std::collections::BTreeSet;

use authz::{
    Caller, Declared, Evaluable, Membership, Presented, Reason, Request, Resolved, Target, Through,
};
use chrono::{DateTime, Utc};
use models::auditable::AuditableModel;
use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::authz::{
    Comparison, Decision, DecisionLogic, DecisionStrategy, FactSource, Operand,
    PolicyEnforcementMode, PolicyRule, PolicyTerms, PolicyType, ReportedDecision,
    ResourceServerModel, ResourceServerMutationModel, StoredPolicy, TimeWindow,
};

fn ids(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn owned(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// The instant every window in these tests is read against.
fn instant() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-18T14:30:00Z")
        .expect("an instant")
        .with_timezone(&Utc)
}

/// Everything a caller is, owned so a request can borrow it.
///
/// One of these is built per test and the request is derived from it, so a test
/// that wants one dimension unknown says only that: `Request { roles:
/// Resolved::Unknown, ..facts.request() }`.
struct Facts {
    roles: BTreeSet<String>,
    groups: BTreeSet<String>,
    client_scopes: BTreeSet<String>,
    claims: AttributesMap,
    attributes: AttributesMap,
}

impl Facts {
    fn new() -> Self {
        Facts {
            roles: ids(&["editor"]),
            groups: ids(&["staff"]),
            client_scopes: ids(&["profile"]),
            claims: AttributesMap::new(),
            attributes: AttributesMap::new(),
        }
    }

    fn claiming(name: &str, value: AttributeValue) -> Self {
        let mut facts = Self::new();
        facts.claims.insert(name.to_owned(), value);
        facts
    }

    fn request(&self) -> Request<'_> {
        Request {
            caller: Caller::User {
                user_id: "ada",
                through: Through::Client(Presented {
                    client_id: "app",
                    client_scopes: &self.client_scopes,
                }),
            },
            roles: Resolved::Known(&self.roles),
            groups: Resolved::Known(&self.groups),
            token_claims: Resolved::Known(&self.claims),
            subject_attributes: Resolved::Known(&self.attributes),
            membership: Membership::RealmWide,
            now: instant(),
        }
    }
}

fn terms(name: &str, rule: PolicyRule) -> PolicyTerms {
    PolicyTerms {
        name: name.to_owned(),
        description: String::new(),
        decision: DecisionStrategy::Unanimous,
        logic: DecisionLogic::Positive,
        policy_owner: "ada".to_owned(),
        policies: Vec::new(),
        resources: Vec::new(),
        scopes: Vec::new(),
        rule,
    }
}

fn stored(id: &str, terms: PolicyTerms) -> StoredPolicy {
    StoredPolicy::Read(terms.into_model(
        id.to_owned(),
        "app".to_owned(),
        "main".to_owned(),
        None,
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    ))
}

fn one(id: &str, rule: PolicyRule) -> StoredPolicy {
    stored(id, terms(id, rule))
}

fn answer(policies: &[StoredPolicy], id: &str, request: Request<'_>) -> Decision {
    authz::policy(&Evaluable::index(policies), id, request).0
}

fn answer_with(
    policies: &[StoredPolicy],
    id: &str,
    request: Request<'_>,
) -> (Decision, Vec<Reason>) {
    authz::policy(&Evaluable::index(policies), id, request)
}

fn server(mode: PolicyEnforcementMode, strategy: DecisionStrategy) -> ResourceServerModel {
    ResourceServerMutationModel {
        enforcement_mode: mode,
        decision_strategy: strategy,
        remote_resource_management: false,
        user_managed_access: false,
    }
    .into_model(
        "app".to_owned(),
        "main".to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    )
}

/// Any of the roles named, on identifiers rather than names, since a name is
/// what an administrator edits and an identifier is what a binding keeps.
#[test]
fn a_role_policy_answers_on_what_the_caller_holds() {
    let facts = Facts::new();
    let held = one(
        "p",
        PolicyRule::Role {
            roles: owned(&["editor", "auditor"]),
        },
    );
    assert_eq!(answer(&[held], "p", facts.request()), Decision::Permit);

    let other = one(
        "p",
        PolicyRule::Role {
            roles: owned(&["auditor"]),
        },
    );
    assert_eq!(answer(&[other], "p", facts.request()), Decision::Deny);
}

/// Membership only. The model carries no parent, so nothing here traverses and
/// a child group does not satisfy an entry naming its parent.
#[test]
fn a_group_policy_reads_membership_and_nothing_else() {
    let facts = Facts::new();
    let member = one(
        "p",
        PolicyRule::Group {
            groups: owned(&["staff"]),
        },
    );
    assert_eq!(answer(&[member], "p", facts.request()), Decision::Permit);

    let other = one(
        "p",
        PolicyRule::Group {
            groups: owned(&["board"]),
        },
    );
    assert_eq!(answer(&[other], "p", facts.request()), Decision::Deny);
}

/// A client is established and is definitively none of the users named, so the
/// arm answers rather than withholding. Under negative logic "anybody but these
/// three" then admits it, which is what the rule says.
#[test]
fn a_user_policy_answers_about_a_client_rather_than_withholding() {
    let facts = Facts::new();
    let policy = one(
        "p",
        PolicyRule::User {
            users: owned(&["ada"]),
        },
    );
    assert_eq!(answer(&[policy], "p", facts.request()), Decision::Permit);

    let as_client = Request {
        caller: Caller::Client {
            presented: Presented {
                client_id: "batch",
                client_scopes: &facts.client_scopes,
            },
        },
        ..facts.request()
    };
    let policy = one(
        "p",
        PolicyRule::User {
            users: owned(&["ada"]),
        },
    );
    assert_eq!(answer(&[policy], "p", as_client), Decision::Deny);
}

/// A client acting for itself is its own presenter, so a rule about clients
/// reads one identity and the journal records the same one.
#[test]
fn a_client_policy_reads_the_client_that_presented_the_call() {
    let facts = Facts::new();
    let policy = one(
        "p",
        PolicyRule::Client {
            clients: owned(&["app"]),
        },
    );
    assert_eq!(answer(&[policy], "p", facts.request()), Decision::Permit);

    let itself = Request {
        caller: Caller::Client {
            presented: Presented {
                client_id: "app",
                client_scopes: &facts.client_scopes,
            },
        },
        ..facts.request()
    };
    let policy = one(
        "p",
        PolicyRule::Client {
            clients: owned(&["app"]),
        },
    );
    assert_eq!(answer(&[policy], "p", itself), Decision::Permit);
}

#[test]
fn a_client_scope_policy_reads_what_the_token_carries() {
    let facts = Facts::new();
    let carried = one(
        "p",
        PolicyRule::ClientScope {
            client_scopes: owned(&["profile", "email"]),
        },
    );
    assert_eq!(answer(&[carried], "p", facts.request()), Decision::Permit);

    let absent = one(
        "p",
        PolicyRule::ClientScope {
            client_scopes: owned(&["email"]),
        },
    );
    assert_eq!(answer(&[absent], "p", facts.request()), Decision::Deny);
}

/// The bounds are read against the instant the request carries, so the answer
/// is the same on two machines and a recorded decision replays to itself.
#[test]
fn a_time_policy_reads_the_instant_it_was_given() {
    let facts = Facts::new();
    let window = |hour, hour_end| TimeWindow {
        hour: Some(hour),
        hour_end: Some(hour_end),
        ..TimeWindow::default()
    };

    let inside = one("p", PolicyRule::Time(window(9, 17)));
    assert_eq!(answer(&[inside], "p", facts.request()), Decision::Permit);

    let outside = one("p", PolicyRule::Time(window(18, 23)));
    assert_eq!(answer(&[outside], "p", facts.request()), Decision::Deny);
}

/// A window no instant can satisfy is not a policy that never grants. Under
/// negative logic it is one that always does, so it answers nothing at all.
#[test]
fn a_window_no_instant_could_satisfy_answers_nothing() {
    let facts = Facts::new();
    let unusable = [
        // Bounds nothing.
        TimeWindow::default(),
        // One end of a range, which reads as an exact value to one reader and
        // as an open range to another.
        TimeWindow {
            hour: Some(9),
            ..TimeWindow::default()
        },
        // Ends before it starts.
        TimeWindow {
            hour: Some(17),
            hour_end: Some(9),
            ..TimeWindow::default()
        },
        // Outside what the field can take.
        TimeWindow {
            month: Some(0),
            month_end: Some(13),
            ..TimeWindow::default()
        },
        // A day no month in the range has.
        TimeWindow {
            month: Some(2),
            month_end: Some(2),
            day_of_month: Some(30),
            day_of_month_end: Some(31),
            ..TimeWindow::default()
        },
    ];

    for window in unusable {
        let policy = one("p", PolicyRule::Time(window));
        let (decision, reasons) = answer_with(&[policy], "p", facts.request());
        assert_eq!(decision, Decision::Indeterminate, "{window:?}");
        assert!(
            matches!(reasons.as_slice(), [Reason::WindowUnusable { .. }]),
            "{window:?} gave {reasons:?}"
        );

        // And negating it does not turn the inability into a grant.
        let negated = stored(
            "p",
            PolicyTerms {
                logic: DecisionLogic::Negative,
                ..terms("p", PolicyRule::Time(window))
            },
        );
        assert_eq!(
            answer(&[negated], "p", facts.request()),
            Decision::Indeterminate
        );
    }
}

/// Unanchored, because the anchors are the author's vocabulary. Anchoring here
/// would change what every stored pattern means without editing one of them.
#[test]
fn a_regex_policy_matches_a_claim_as_it_was_written() {
    let facts = Facts::claiming("email", AttributeValue::Str("ada@example.test".to_owned()));
    let matching = one(
        "p",
        PolicyRule::Regex {
            target_claim: "email".to_owned(),
            target_regex: r"@example\.test$".to_owned(),
        },
    );
    assert_eq!(answer(&[matching], "p", facts.request()), Decision::Permit);

    let elsewhere = one(
        "p",
        PolicyRule::Regex {
            target_claim: "email".to_owned(),
            target_regex: r"@elsewhere\.test$".to_owned(),
        },
    );
    assert_eq!(answer(&[elsewhere], "p", facts.request()), Decision::Deny);
}

/// Three ways a pattern policy cannot answer, none of which is a non-match.
#[test]
fn a_pattern_policy_withholds_rather_than_failing_to_match() {
    let facts = Facts::claiming("age", AttributeValue::Int(30));

    let uncompilable = one(
        "p",
        PolicyRule::Regex {
            target_claim: "age".to_owned(),
            target_regex: "([a-z".to_owned(),
        },
    );
    let (decision, reasons) = answer_with(&[uncompilable], "p", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(
        reasons.as_slice(),
        [Reason::PatternUnusable { .. }]
    ));

    // A number is not text, and rendering it into text to match would match
    // against a rendering nobody chose.
    let wrong_shape = one(
        "p",
        PolicyRule::Regex {
            target_claim: "age".to_owned(),
            target_regex: "^30$".to_owned(),
        },
    );
    let (decision, reasons) = answer_with(&[wrong_shape], "p", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(reasons.as_slice(), [Reason::Uncomparable { .. }]));

    let absent = one(
        "p",
        PolicyRule::Regex {
            target_claim: "nothing".to_owned(),
            target_regex: "^.*$".to_owned(),
        },
    );
    let (decision, reasons) = answer_with(&[absent], "p", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(reasons.as_slice(), [Reason::ClaimAbsent { .. }]));
}

fn claim(name: &str) -> Operand {
    Operand::Claim {
        source: FactSource::Token,
        name: name.to_owned(),
    }
}

fn attribute(test: Comparison) -> StoredPolicy {
    one(
        "p",
        PolicyRule::Attribute {
            left: claim("fact"),
            test,
        },
    )
}

/// Every operator, on a pair it can answer and a pair it cannot. A pair the
/// operator has no answer for withholds one: false is invertible into a grant,
/// and "these two are not comparable" says nothing about the caller.
#[test]
fn the_operator_table_answers_every_row() {
    let text = Facts::claiming("fact", AttributeValue::Str("gold".to_owned()));
    let number = Facts::claiming("fact", AttributeValue::Int(30));
    let flag = Facts::claiming("fact", AttributeValue::Bool(true));

    let value = |v: AttributeValue| Operand::Value(v);
    let word = |s: &str| value(AttributeValue::Str(s.to_owned()));

    // Comparable, and the comparison holds or does not.
    let holding: &[(&Facts, Comparison, Decision)] = &[
        (&text, Comparison::Equals(word("gold")), Decision::Permit),
        (&text, Comparison::Equals(word("silver")), Decision::Deny),
        (&text, Comparison::Contains(word("ol")), Decision::Permit),
        (&text, Comparison::Contains(word("xx")), Decision::Deny),
        (&text, Comparison::StartsWith(word("go")), Decision::Permit),
        (&text, Comparison::StartsWith(word("ld")), Decision::Deny),
        (&text, Comparison::EndsWith(word("ld")), Decision::Permit),
        (&text, Comparison::EndsWith(word("go")), Decision::Deny),
        (
            &text,
            Comparison::In(value(AttributeValue::ListStr(owned(&["gold", "silver"])))),
            Decision::Permit,
        ),
        (
            &number,
            Comparison::In(value(AttributeValue::ListStr(owned(&["30", "40"])))),
            Decision::Permit,
        ),
        // A lone string on the right is a list of one, which is the model's own
        // widening rule rather than a second one written here.
        (&text, Comparison::In(word("gold")), Decision::Permit),
        (&text, Comparison::In(word("silver")), Decision::Deny),
        (
            &number,
            Comparison::Gt(value(AttributeValue::Int(18))),
            Decision::Permit,
        ),
        (
            &number,
            Comparison::Gte(value(AttributeValue::Int(30))),
            Decision::Permit,
        ),
        (
            &number,
            Comparison::Lt(value(AttributeValue::Int(18))),
            Decision::Deny,
        ),
        (
            &number,
            Comparison::Lte(value(AttributeValue::Int(30))),
            Decision::Permit,
        ),
        (&text, Comparison::Present, Decision::Permit),
    ];

    for (facts, test, expected) in holding {
        assert_eq!(
            answer(&[attribute(test.clone())], "p", facts.request()),
            *expected,
            "{test:?}"
        );
    }

    // Not comparable under the operator asked of them.
    let uncomparable: &[(&Facts, Comparison)] = &[
        // Equality is typed, and two shapes are not a finding that they differ:
        // read as one, a claim that changes shape flips every negative equality
        // policy in the realm on the day of the change.
        (&text, Comparison::Equals(value(AttributeValue::Int(30)))),
        (&number, Comparison::Contains(word("3"))),
        (&flag, Comparison::Gt(value(AttributeValue::Int(1)))),
        (&text, Comparison::Gt(value(AttributeValue::Int(1)))),
        (
            &flag,
            Comparison::In(value(AttributeValue::ListStr(owned(&["true"])))),
        ),
    ];

    for (facts, test) in uncomparable {
        assert_eq!(
            answer(&[attribute(test.clone())], "p", facts.request()),
            Decision::Indeterminate,
            "{test:?}"
        );
    }
}

/// The one operator whose business is absence answers on it; the other nine are
/// being asked about a value there is none of.
#[test]
fn only_a_presence_test_answers_on_an_absent_fact() {
    let facts = Facts::new();
    assert_eq!(
        answer(&[attribute(Comparison::Present)], "p", facts.request()),
        Decision::Deny
    );

    let (decision, reasons) = answer_with(
        &[attribute(Comparison::Equals(Operand::Value(
            AttributeValue::Str("gold".to_owned()),
        )))],
        "p",
        facts.request(),
    );
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(reasons.as_slice(), [Reason::ClaimAbsent { .. }]));
}

/// A source nobody could read is not an absent fact, so even the presence test
/// withholds. Answering that the fact was not there would let negation grant on
/// a subject nobody looked up.
#[test]
fn an_unreadable_source_withholds_from_every_operator() {
    let facts = Facts::new();
    let unread = Request {
        subject_attributes: Resolved::Unknown,
        ..facts.request()
    };
    let policy = one(
        "p",
        PolicyRule::Attribute {
            left: Operand::Claim {
                source: FactSource::Subject,
                name: "fact".to_owned(),
            },
            test: Comparison::Present,
        },
    );

    let (decision, reasons) = answer_with(&[policy], "p", unread);
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(
        reasons.as_slice(),
        [Reason::SourceUnavailable {
            source: FactSource::Subject,
            ..
        }]
    ));
}

/// A test every value passes reads nothing about the caller, whichever side the
/// constant sits on.
#[test]
fn a_test_every_value_passes_is_not_a_test() {
    let facts = Facts::claiming("fact", AttributeValue::Str("gold".to_owned()));

    let literal_left = one(
        "p",
        PolicyRule::Attribute {
            left: Operand::Value(AttributeValue::Str("gold".to_owned())),
            test: Comparison::Equals(Operand::Value(AttributeValue::Str("gold".to_owned()))),
        },
    );
    let (decision, reasons) = answer_with(&[literal_left], "p", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(
        reasons.as_slice(),
        [Reason::ConstantCondition { .. }]
    ));

    // Every string contains the empty string, starts with it and ends with it.
    for test in [
        Comparison::Contains(Operand::Value(AttributeValue::Str(String::new()))),
        Comparison::StartsWith(Operand::Value(AttributeValue::Str(String::new()))),
        Comparison::EndsWith(Operand::Value(AttributeValue::Str(String::new()))),
    ] {
        let (decision, reasons) = answer_with(&[attribute(test.clone())], "p", facts.request());
        assert_eq!(decision, Decision::Indeterminate, "{test:?}");
        assert!(matches!(
            reasons.as_slice(),
            [Reason::ConstantCondition { .. }]
        ));
    }
}

/// An aggregate folds under its own strategy, and each condition's own logic is
/// applied to its own answer before it is counted.
#[test]
fn an_aggregate_folds_its_conditions_under_its_own_strategy() {
    let facts = Facts::new();
    let permits = one(
        "yes",
        PolicyRule::Role {
            roles: owned(&["editor"]),
        },
    );
    let refuses = one(
        "no",
        PolicyRule::Role {
            roles: owned(&["auditor"]),
        },
    );

    let unanimous = stored(
        "agg",
        PolicyTerms {
            policies: owned(&["yes", "no"]),
            decision: DecisionStrategy::Unanimous,
            ..terms("agg", PolicyRule::Aggregated)
        },
    );
    let set = [permits.clone(), refuses.clone(), unanimous];
    assert_eq!(answer(&set, "agg", facts.request()), Decision::Deny);

    let affirmative = stored(
        "agg",
        PolicyTerms {
            policies: owned(&["yes", "no"]),
            decision: DecisionStrategy::Affirmative,
            ..terms("agg", PolicyRule::Aggregated)
        },
    );
    let set = [permits, refuses, affirmative];
    assert_eq!(answer(&set, "agg", facts.request()), Decision::Permit);
}

/// A policy conditioned on something that leads back to it answers nothing,
/// rather than answering after a while or not at all.
#[test]
fn a_cycle_is_unanswerable_rather_than_unending() {
    let facts = Facts::new();
    let first = stored(
        "first",
        PolicyTerms {
            policies: owned(&["second"]),
            ..terms("first", PolicyRule::Aggregated)
        },
    );
    let second = stored(
        "second",
        PolicyTerms {
            policies: owned(&["first"]),
            ..terms("second", PolicyRule::Aggregated)
        },
    );

    let (decision, reasons) = answer_with(&[first, second], "first", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(
        reasons
            .iter()
            .any(|reason| matches!(reason, Reason::AggregationCycle { .. })),
        "{reasons:?}"
    );
}

/// A condition the set does not hold withholds and is named. Folding without it
/// would let a deletion elsewhere narrow a unanimous policy into a grant.
#[test]
fn a_condition_the_set_does_not_hold_withholds() {
    let facts = Facts::new();
    let aggregate = stored(
        "agg",
        PolicyTerms {
            policies: owned(&["gone"]),
            ..terms("agg", PolicyRule::Aggregated)
        },
    );

    let (decision, reasons) = answer_with(&[aggregate], "agg", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(
        reasons.as_slice(),
        [Reason::DanglingCondition { .. }]
    ));
}

/// A row nobody can read is named and withholds. Skipping it would make a
/// policy nobody can read look like a policy nobody wrote, and under a strategy
/// where one permit is enough those two differ.
#[test]
fn a_row_nothing_can_read_withholds_and_is_named() {
    let facts = Facts::new();
    let adrift = StoredPolicy::Unreadable {
        policy_id: "adrift".to_owned(),
    };
    let aggregate = stored(
        "agg",
        PolicyTerms {
            policies: owned(&["adrift"]),
            decision: DecisionStrategy::Affirmative,
            ..terms("agg", PolicyRule::Aggregated)
        },
    );

    let (decision, reasons) = answer_with(&[adrift, aggregate], "agg", facts.request());
    assert_eq!(decision, Decision::Indeterminate);
    assert!(matches!(reasons.as_slice(), [Reason::Quarantined { .. }]));
}

/// The property the whole crate exists for, asked of every dimension: a fact
/// nobody could establish never becomes a grant, not even under negation.
#[test]
fn a_fact_nobody_established_never_becomes_a_grant() {
    let facts = Facts::new();
    let negative = |rule: PolicyRule| {
        stored(
            "p",
            PolicyTerms {
                logic: DecisionLogic::Negative,
                ..terms("p", rule)
            },
        )
    };

    let unknown: &[(&str, Request<'_>, PolicyRule)] = &[
        (
            "roles",
            Request {
                roles: Resolved::Unknown,
                ..facts.request()
            },
            PolicyRule::Role {
                roles: owned(&["editor"]),
            },
        ),
        (
            "groups",
            Request {
                groups: Resolved::Unknown,
                ..facts.request()
            },
            PolicyRule::Group {
                groups: owned(&["staff"]),
            },
        ),
        (
            "token claims",
            Request {
                token_claims: Resolved::Unknown,
                ..facts.request()
            },
            PolicyRule::Attribute {
                left: claim("fact"),
                test: Comparison::Present,
            },
        ),
        (
            "the presenting client",
            Request {
                caller: Caller::User {
                    user_id: "ada",
                    through: Through::Unestablished,
                },
                ..facts.request()
            },
            PolicyRule::Client {
                clients: owned(&["app"]),
            },
        ),
    ];

    for (dimension, request, rule) in unknown {
        assert_eq!(
            answer(&[negative(rule.clone())], "p", *request),
            Decision::Indeterminate,
            "{dimension} nobody established was inverted into a grant"
        );
    }
}

/// A binding a deletion elsewhere emptied is not a caller who matched none of
/// them. The rows cascade, so this is reachable without anybody having written
/// the policy that way.
#[test]
fn a_binding_that_was_emptied_never_becomes_a_grant() {
    let facts = Facts::new();
    let emptied = [
        (PolicyType::Role, PolicyRule::Role { roles: Vec::new() }),
        (PolicyType::Group, PolicyRule::Group { groups: Vec::new() }),
        (PolicyType::User, PolicyRule::User { users: Vec::new() }),
        (
            PolicyType::Client,
            PolicyRule::Client {
                clients: Vec::new(),
            },
        ),
        (
            PolicyType::ClientScope,
            PolicyRule::ClientScope {
                client_scopes: Vec::new(),
            },
        ),
        (PolicyType::Aggregated, PolicyRule::Aggregated),
    ];

    for (kind, rule) in emptied {
        for logic in [DecisionLogic::Positive, DecisionLogic::Negative] {
            let policy = stored(
                "p",
                PolicyTerms {
                    logic,
                    ..terms("p", rule.clone())
                },
            );
            let (decision, reasons) = answer_with(&[policy], "p", facts.request());
            assert_eq!(
                decision,
                Decision::Indeterminate,
                "{kind:?} under {logic:?}"
            );
            assert!(
                matches!(reasons.as_slice(), [Reason::EmptyBinding { .. }]),
                "{kind:?} gave {reasons:?}"
            );
        }
    }
}

/// A policy narrowed to an organization is silent for callers outside it and
/// withholds for a caller whose own could not be established.
#[test]
fn a_confined_policy_does_not_decide_outside_its_organization() {
    let facts = Facts::new();
    let confined = StoredPolicy::Read(
        terms(
            "p",
            PolicyRule::Role {
                roles: owned(&["editor"]),
            },
        )
        .into_model(
            "p".to_owned(),
            "app".to_owned(),
            "main".to_owned(),
            Some("north".to_owned()),
            AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
        ),
    );

    let north = ids(&["north"]);
    let inside = Request {
        membership: Membership::In(&north),
        ..facts.request()
    };
    assert_eq!(
        answer(std::slice::from_ref(&confined), "p", inside),
        Decision::Permit
    );

    // And a caller in several is placed by any one of them, so belonging to a
    // second organization does not lose the policies of the first.
    let both = ids(&["north", "south"]);
    let in_both = Request {
        membership: Membership::In(&both),
        ..facts.request()
    };
    assert_eq!(
        answer(std::slice::from_ref(&confined), "p", in_both),
        Decision::Permit,
        "a caller in two organizations lost the policies of one of them"
    );

    let south = ids(&["south"]);
    for elsewhere in [
        Membership::In(&south),
        Membership::RealmWide,
        Membership::Unknown,
    ] {
        let request = Request {
            membership: elsewhere,
            ..facts.request()
        };
        let (decision, reasons) = answer_with(std::slice::from_ref(&confined), "p", request);
        assert_eq!(decision, Decision::Indeterminate, "{elsewhere:?}");
        assert!(matches!(reasons.as_slice(), [Reason::Confined { .. }]));
    }
}

fn target<'a>(scope_id: &'a str, declared: &'a BTreeSet<String>) -> Target<'a> {
    Target {
        server_id: "app",
        resource_id: "doc",
        resource_type: "urn:doc",
        scope_id,
        declared_scopes: Declared::Verbs(declared),
    }
}

fn permission(id: &str, rule: PolicyRule, resources: &[&str], scopes: &[&str]) -> StoredPolicy {
    stored(
        id,
        PolicyTerms {
            policies: owned(&["condition"]),
            resources: owned(resources),
            scopes: owned(scopes),
            ..terms(id, rule)
        },
    )
}

/// A permission bound to something else is about something else, so it is
/// silent rather than withholding. Withholding would let one permission about
/// another resource stop every answer on the application.
#[test]
fn a_permission_answers_only_about_what_it_names() {
    let facts = Facts::new();
    let declared = ids(&["read", "delete"]);
    let condition = one(
        "condition",
        PolicyRule::Role {
            roles: owned(&["editor"]),
        },
    );

    let reads = permission(
        "reads",
        PolicyRule::ScopePermission {
            resource_type: String::new(),
        },
        &["doc"],
        &["read"],
    );
    let set = [condition.clone(), reads];
    let server = server(
        PolicyEnforcementMode::Enforcing,
        DecisionStrategy::Unanimous,
    );

    let verdict = authz::permission(
        &server,
        &Evaluable::index(&set),
        target("read", &declared),
        facts.request(),
    );
    assert_eq!(verdict.reported, ReportedDecision::Permit);
    assert_eq!(verdict.computed, Decision::Permit);

    // The same permission says nothing about deleting, and nothing else does
    // either, so the application refuses and says which empty set it was.
    let verdict = authz::permission(
        &server,
        &Evaluable::index(&set),
        target("delete", &declared),
        facts.request(),
    );
    assert_eq!(verdict.computed, Decision::Deny);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|reason| matches!(reason, Reason::NothingGoverns { .. })),
        "{:?}",
        verdict.reasons
    );
}

/// A resource permission covers every verb the resource declares, and it binds
/// no scopes at all, so an empty list there cannot be produced by a deletion.
#[test]
fn a_resource_permission_covers_every_verb_of_what_it_names() {
    let facts = Facts::new();
    let declared = ids(&["read", "delete"]);
    let condition = one(
        "condition",
        PolicyRule::Role {
            roles: owned(&["editor"]),
        },
    );
    let all_verbs = permission(
        "all",
        PolicyRule::ResourcePermission {
            resource_type: String::new(),
        },
        &["doc"],
        &[],
    );
    let set = [condition, all_verbs];
    let server = server(
        PolicyEnforcementMode::Enforcing,
        DecisionStrategy::Unanimous,
    );

    for verb in ["read", "delete"] {
        let verdict = authz::permission(
            &server,
            &Evaluable::index(&set),
            target(verb, &declared),
            facts.request(),
        );
        assert_eq!(verdict.computed, Decision::Permit, "{verb}");
    }
}

/// The verbs a resource declares are what may be done to it. Declaring none is
/// an answer; not having read them is not, and the two may not read as one.
#[test]
fn a_verb_the_resource_does_not_declare_is_refused_before_any_policy() {
    let facts = Facts::new();
    let declared = ids(&["read"]);
    let condition = one(
        "condition",
        PolicyRule::Role {
            roles: owned(&["editor"]),
        },
    );
    let anything = permission(
        "all",
        PolicyRule::ResourcePermission {
            resource_type: String::new(),
        },
        &["doc"],
        &[],
    );
    let set = [condition, anything];
    let server = server(
        PolicyEnforcementMode::Enforcing,
        DecisionStrategy::Unanimous,
    );

    let verdict = authz::permission(
        &server,
        &Evaluable::index(&set),
        target("delete", &declared),
        facts.request(),
    );
    assert_eq!(verdict.computed, Decision::Deny);
    assert!(matches!(
        verdict.reasons.as_slice(),
        [Reason::VerbNotDeclared { .. }]
    ));

    let unread = Target {
        declared_scopes: Declared::NotLoaded,
        ..target("read", &declared)
    };
    let verdict = authz::permission(&server, &Evaluable::index(&set), unread, facts.request());
    assert_eq!(verdict.computed, Decision::Indeterminate);
    assert_eq!(
        verdict.reported,
        ReportedDecision::Deny,
        "an unread verb list was reported as an answer"
    );
}

/// The mode changes what a caller is told, never which policies apply, and both
/// answers are kept so a masked refusal is still there to be found.
#[test]
fn the_mode_changes_what_is_reported_and_not_what_applies() {
    let facts = Facts::new();
    let declared = ids(&["read"]);
    let refuses = one(
        "condition",
        PolicyRule::Role {
            roles: owned(&["auditor"]),
        },
    );
    let reads = permission(
        "reads",
        PolicyRule::ScopePermission {
            resource_type: String::new(),
        },
        &["doc"],
        &["read"],
    );
    let set = [refuses, reads];

    let enforcing = authz::permission(
        &server(
            PolicyEnforcementMode::Enforcing,
            DecisionStrategy::Unanimous,
        ),
        &Evaluable::index(&set),
        target("read", &declared),
        facts.request(),
    );
    assert_eq!(enforcing.reported, ReportedDecision::Deny);
    assert_eq!(enforcing.computed, Decision::Deny);

    let permissive = authz::permission(
        &server(
            PolicyEnforcementMode::Permissive,
            DecisionStrategy::Unanimous,
        ),
        &Evaluable::index(&set),
        target("read", &declared),
        facts.request(),
    );
    assert_eq!(permissive.reported, ReportedDecision::Permit);
    assert_eq!(
        permissive.computed,
        Decision::Deny,
        "the refusal that was masked was not kept"
    );
    assert!(permissive.reasons.contains(&Reason::Masked));

    let disabled = authz::permission(
        &server(PolicyEnforcementMode::Disabled, DecisionStrategy::Unanimous),
        &Evaluable::index(&set),
        target("read", &declared),
        facts.request(),
    );
    assert_eq!(disabled.reported, ReportedDecision::Permit);
    assert_eq!(
        disabled.computed,
        Decision::Indeterminate,
        "a server that evaluates nothing recorded an evaluation"
    );
    assert_eq!(disabled.reasons, vec![Reason::EnforcementDisabled]);
}

/// A resource one application protects, named alongside another application.
///
/// Refused before the mode is read, which is the whole point: a mode belongs to
/// the application that owns the resource. Read from the application a caller
/// named instead, a permissive or disabled one would answer for a resource it
/// does not protect, and naming it would be enough to reach somebody else's.
#[test]
fn an_application_answers_only_for_the_resources_it_protects() {
    let facts = Facts::new();
    let declared = ids(&["read"]);
    let elsewhere = Target {
        server_id: "another-app",
        ..target("read", &declared)
    };

    for mode in PolicyEnforcementMode::ALL {
        let verdict = authz::permission(
            &server(*mode, DecisionStrategy::Affirmative),
            &Evaluable::index(&[]),
            elsewhere,
            facts.request(),
        );
        assert_eq!(
            verdict.reported,
            ReportedDecision::Deny,
            "a {mode:?} application answered for a resource of another one"
        );
        assert_eq!(verdict.computed, Decision::Deny);
        assert!(matches!(
            verdict.reasons.as_slice(),
            [Reason::NotThisApplication { .. }]
        ));
    }
}
