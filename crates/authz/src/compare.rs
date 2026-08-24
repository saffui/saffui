use models::entities::attributes::AttributeValue;
use models::entities::authz::Decision;
use models::entities::authz::{Comparison, FactSource, Operand};

use crate::fold::holds;
use crate::request::Request;
use crate::verdict::Reason;

/// What resolving an operand found.
enum Found<'a> {
    Value(&'a AttributeValue),
    /// The named source could not be read at all.
    SourceUnavailable(FactSource),
    /// The source was read and the fact was not in it.
    Absent(&'a str),
}

/// Compare one fact with another.
pub(crate) fn attribute(
    policy_id: &str,
    left: &Operand,
    test: &Comparison,
    request: &Request<'_>,
    reasons: &mut Vec<Reason>,
) -> Decision {
    // A literal on the left reads nothing about the caller, so the rule answers
    // the same for everybody. That is an unconditional grant wearing the shape
    // of a test, and it is refused rather than evaluated.
    let Operand::Claim { .. } = left else {
        return unable(
            reasons,
            Reason::ConstantCondition {
                policy_id: policy_id.to_owned(),
            },
        );
    };

    let value = match resolve(left, request) {
        Found::SourceUnavailable(source) => {
            return unable(
                reasons,
                Reason::SourceUnavailable {
                    policy_id: policy_id.to_owned(),
                    source,
                },
            );
        }
        // The one operator whose business is absence answers on it. Every other
        // one is being asked about a value there is none of.
        Found::Absent(claim) => {
            return match test {
                Comparison::Present => holds(false),
                _ => unable(
                    reasons,
                    Reason::ClaimAbsent {
                        policy_id: policy_id.to_owned(),
                        claim: claim.to_owned(),
                    },
                ),
            };
        }
        Found::Value(value) => value,
    };

    let Some(right) = right_of(test) else {
        // `Present`, and the fact is there.
        return holds(true);
    };

    let right = match resolve(right, request) {
        Found::SourceUnavailable(source) => {
            return unable(
                reasons,
                Reason::SourceUnavailable {
                    policy_id: policy_id.to_owned(),
                    source,
                },
            );
        }
        Found::Absent(claim) => {
            return unable(
                reasons,
                Reason::ClaimAbsent {
                    policy_id: policy_id.to_owned(),
                    claim: claim.to_owned(),
                },
            );
        }
        Found::Value(right) => right,
    };

    // Every string contains the empty string, starts with it and ends with it,
    // so these three degenerate into a presence test that reads as a
    // restriction. Same fault as a literal on the left, same answer.
    if is_substring_test(test) && right.as_str() == Some("") {
        return unable(
            reasons,
            Reason::ConstantCondition {
                policy_id: policy_id.to_owned(),
            },
        );
    }

    match compares(value, test, right) {
        Some(matched) => holds(matched),
        None => unable(
            reasons,
            Reason::Uncomparable {
                policy_id: policy_id.to_owned(),
            },
        ),
    }
}

/// Record why nothing could be decided, and answer that.
fn unable(reasons: &mut Vec<Reason>, reason: Reason) -> Decision {
    reasons.push(reason);
    Decision::Indeterminate
}

fn resolve<'a>(operand: &'a Operand, request: &Request<'a>) -> Found<'a> {
    match operand {
        Operand::Value(value) => Found::Value(value),
        Operand::Claim { source, name } => {
            let bag = match source {
                FactSource::Token => request.token_claims,
                FactSource::Subject => request.subject_attributes,
            };
            match bag.known() {
                None => Found::SourceUnavailable(*source),
                Some(bag) => match bag.get(name) {
                    Some(value) => Found::Value(value),
                    None => Found::Absent(name),
                },
            }
        }
    }
}

/// The operand a comparison carries, where it carries one.
///
/// Exhaustive, so an eleventh operator has to say here whether it takes a right
/// hand side rather than silently being read as one that does not.
fn right_of(test: &Comparison) -> Option<&Operand> {
    match test {
        Comparison::Equals(right)
        | Comparison::Contains(right)
        | Comparison::StartsWith(right)
        | Comparison::EndsWith(right)
        | Comparison::In(right)
        | Comparison::Gt(right)
        | Comparison::Gte(right)
        | Comparison::Lt(right)
        | Comparison::Lte(right) => Some(right),
        Comparison::Present => None,
    }
}

fn is_substring_test(test: &Comparison) -> bool {
    matches!(
        test,
        Comparison::Contains(_) | Comparison::StartsWith(_) | Comparison::EndsWith(_)
    )
}

/// Whether the comparison holds, or `None` when the pair cannot answer it.
fn compares(left: &AttributeValue, test: &Comparison, right: &AttributeValue) -> Option<bool> {
    match test {
        // Typed, and refused across shapes rather than answered. Two values
        // stored differently are not a finding that they differ: read as one,
        // a claim that changes shape flips every negative equality policy in
        // the realm into an unconditional grant on the day of the change.
        Comparison::Equals(_) => {
            if std::mem::discriminant(left) == std::mem::discriminant(right) {
                Some(left == right)
            } else {
                None
            }
        }
        Comparison::Contains(_) => text(left, right).map(|(l, r)| l.contains(r)),
        Comparison::StartsWith(_) => text(left, right).map(|(l, r)| l.starts_with(r)),
        Comparison::EndsWith(_) => text(left, right).map(|(l, r)| l.ends_with(r)),
        // The list is the only plural shape, so an integer on the left is
        // compared by its rendering. That sits oddly beside typed equality and
        // is the only reading under which a numeric identifier can be looked up
        // in a list at all.
        Comparison::In(_) => {
            let members = right.as_list()?;
            let needle = match left {
                AttributeValue::Str(value) => value.clone(),
                AttributeValue::Int(value) => value.to_string(),
                AttributeValue::Bool(_) | AttributeValue::ListStr(_) => return None,
            };
            Some(members.contains(&needle))
        }
        Comparison::Gt(_) => number(left, right).map(|(l, r)| l > r),
        Comparison::Gte(_) => number(left, right).map(|(l, r)| l >= r),
        Comparison::Lt(_) => number(left, right).map(|(l, r)| l < r),
        Comparison::Lte(_) => number(left, right).map(|(l, r)| l <= r),
        // Answered before this point, where the absence of the fact is the
        // whole question.
        Comparison::Present => Some(true),
    }
}

fn text<'a>(left: &'a AttributeValue, right: &'a AttributeValue) -> Option<(&'a str, &'a str)> {
    Some((left.as_str()?, right.as_str()?))
}

/// Both sides as numbers, which is the one place a value is coerced.
///
/// Text that is not a finite number is not a number: `as_f64` filters the
/// infinities and `NaN`, either of which read out of an open map defeats every
/// comparison made with it.
fn number(left: &AttributeValue, right: &AttributeValue) -> Option<(f64, f64)> {
    Some((left.as_f64()?, right.as_f64()?))
}
