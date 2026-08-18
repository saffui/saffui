//! Everything a decision is asked about, stated rather than defaulted.
//!
//! The shape here is the crate's main defence, and it is a shape rather than a
//! check: a fact that could not be established has an arm of its own, so the
//! caller has to say which of the two it is. A bare `&BTreeSet` would let a
//! caller who failed to load the subject's roles pass an empty one, and every
//! role policy would then answer that the subject holds none of them, which
//! negative logic turns into a grant for a subject nobody looked up.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use models::entities::attributes::AttributesMap;

/// A fact the caller established, or could not.
///
/// One shape for the four dimensions that have it, so the distinction is made
/// the same way every time and a reader who has understood it once has
/// understood all four.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved<'a, T: ?Sized> {
    Known(&'a T),
    /// Nobody could read it. Every rule that reads it is unevaluable, which is
    /// not the same answer as a rule that read it and found nothing.
    Unknown,
}

// Written out rather than derived. A derive would ask the fact itself to be
// copyable, and what is copied here is a borrow of it.
impl<T: ?Sized> Clone for Resolved<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for Resolved<'_, T> {}

impl<'a, T: ?Sized> Resolved<'a, T> {
    pub fn known(self) -> Option<&'a T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown => None,
        }
    }
}

/// The client that presented the token, and the scopes the token carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presented<'a> {
    pub client_id: &'a str,
    /// Client scope identifiers, resolved once from the token's scope string,
    /// because an identifier is what a policy names.
    pub client_scopes: &'a BTreeSet<String>,
}

/// The client a user's call came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Through<'a> {
    Client(Presented<'a>),
    /// No client established itself. Audience is not a substitute: audience is
    /// who a token is for, not who presented it.
    Unestablished,
}

/// Who is asking.
///
/// A client acting for itself carries its presentation here and nowhere else.
/// Two fields for one client identity would let a request name one principal in
/// the rule and another in the journal, and a replay of that record would not
/// be a replay of that decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller<'a> {
    User {
        user_id: &'a str,
        through: Through<'a>,
    },
    Client {
        presented: Presented<'a>,
    },
}

impl<'a> Caller<'a> {
    /// The identifier the journal records, whichever kind of caller this is.
    pub fn subject_id(self) -> &'a str {
        match self {
            Self::User { user_id, .. } => user_id,
            Self::Client { presented } => presented.client_id,
        }
    }

    /// The value the journal's subject column takes. One producer, so two call
    /// sites cannot spell it two ways.
    pub fn subject_type(self) -> &'static str {
        match self {
            Self::User { .. } => "user",
            Self::Client { .. } => "client",
        }
    }

    /// The client that presented the call, if one did.
    pub fn presented(self) -> Option<Presented<'a>> {
        match self {
            Self::User {
                through: Through::Client(presented),
                ..
            } => Some(presented),
            Self::User {
                through: Through::Unestablished,
                ..
            } => None,
            Self::Client { presented } => Some(presented),
        }
    }
}

/// The organization a caller acts in.
///
/// Not a policy kind but a predicate over every decision, which is why it sits
/// on the request rather than in a rule: a policy confined to an organization
/// has to be silent for callers outside it, whatever the policy decides on.
///
/// The membership is a set and not one organization, because a caller may
/// belong to several while a policy is confined to one: collapsing to a single
/// organization silences every confined policy of the others, and a confined
/// policy silenced is a policy that stops refusing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Membership<'a> {
    /// The organizations the caller belongs to, by identifier.
    In(&'a BTreeSet<String>),
    /// Acting at realm level, in no organization at all.
    RealmWide,
    /// It could not be established, so a confined policy cannot be placed.
    Unknown,
}

/// Everything a policy may read about a caller.
///
/// Borrowed throughout, and one of these is built per decision, so every policy
/// in a fold reads the same caller. Two fact sets in one decision would be two
/// callers, and the fold would combine answers about different people.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub caller: Caller<'a>,
    /// Role identifiers held, directly and through groups, collected for a
    /// client subject exactly as for a user.
    pub roles: Resolved<'a, BTreeSet<String>>,
    /// Group identifiers the subject belongs to. Membership only: the model
    /// carries no parent, so no entry is satisfied by a child group.
    pub groups: Resolved<'a, BTreeSet<String>>,
    /// The verified token's claims, projected into the four stored shapes.
    pub token_claims: Resolved<'a, AttributesMap>,
    /// The stored subject's own attributes, whichever kind of subject it is.
    pub subject_attributes: Resolved<'a, AttributesMap>,
    pub membership: Membership<'a>,
    /// The one instant every window is read against. An argument, so a test
    /// pins it and a recorded decision replays against the same moment.
    pub now: DateTime<Utc>,
}

/// What the resource says may be done to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declared<'a> {
    /// The verbs it declares, by identifier. Empty means it declares none,
    /// which is an answer.
    Verbs(&'a BTreeSet<String>),
    /// They were not read, which is not an answer.
    NotLoaded,
}

/// The resource and the verb a permission question is about.
///
/// There is no unresolved arm. A resource that resolved to nothing never
/// becomes a `Target`, so "an unknown resource is refused before any policy is
/// folded" is held by the type rather than by a check somebody may skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target<'a> {
    /// The application the resource belongs to, so the engine can refuse a
    /// target the passed server does not own.
    pub server_id: &'a str,
    pub resource_id: &'a str,
    pub resource_type: &'a str,
    /// The verb being attempted, by scope identifier, resolved from its name
    /// once upstream so a name cannot match another resource's identifier.
    pub scope_id: &'a str,
    pub declared_scopes: Declared<'a>,
}
