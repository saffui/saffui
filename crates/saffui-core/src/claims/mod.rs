//! What tokens and the userinfo answer say of a person. One evaluator
//! writes the access token, the identity token and the userinfo answer, so
//! that the three never disagree; what it reads is gathered apart.

pub mod attributes;
pub mod gather;
pub mod manage;
pub mod rules;
pub mod store;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::authz::capability::Capability;
use crate::authz::grants::HeldRole;

/// Where a claim is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimTarget {
    AccessToken,
    IdToken,
    Userinfo,
}

impl ClaimTarget {
    pub const ALL: [Self; 3] = [Self::AccessToken, Self::IdToken, Self::Userinfo];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::IdToken => "id_token",
            Self::Userinfo => "userinfo",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|target| target.name() == name)
    }
}

/// A property every person has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonProperty {
    Id,
    Username,
    Email,
    EmailVerified,
    DisplayName,
}

/// What a mapper writes. Six kinds, and no expression: a mapper never runs
/// what an administrator typed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MapperKind {
    Property {
        property: PersonProperty,
    },
    /// An attribute of the person, as it is kept.
    Attribute {
        attribute: String,
    },
    /// `given_name` and `family_name`, or the display name without them.
    FullName,
    RealmRoles,
    /// The roles of one client of the realm, by name.
    ClientRoles {
        client_id: String,
    },
    /// One more audience of the access token.
    Audience {
        audience: String,
    },
}

/// A mapper of a client: what its tokens say beyond what their scopes say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapper {
    pub id: Uuid,
    /// The client whose tokens it writes.
    pub client_id: String,
    pub name: String,
    pub kind: MapperKind,
    /// The claim it writes. An audience mapper writes `aud` and names none.
    pub claim: Option<String>,
    pub targets: Vec<ClaimTarget>,
    /// The scope a grant must carry for it to apply. An audience without one
    /// applies to every grant; a mapper about the person names one, or says nothing.
    pub scope: Option<String>,
    pub created_at: OffsetDateTime,
}

/// What a writer of the mappers of a client reads of it, under its lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedClient {
    /// The scopes it may be given.
    pub scopes: Vec<String>,
    pub capabilities: Vec<Capability>,
}

/// A mapper to give a client.
pub struct NewMapper<'a> {
    pub name: &'a str,
    pub kind: MapperKind,
    pub claim: Option<&'a str>,
    pub targets: &'a [ClaimTarget],
    pub scope: Option<&'a str>,
}

/// What the evaluator reads of one grant, gathered before it runs.
#[derive(Clone, Debug, Default)]
pub struct ClaimInputs {
    /// The mappers of the client the grant is for.
    pub mappers: Vec<Mapper>,
    pub attributes: Map<String, Value>,
    /// The roles the person holds now, each way they hold it.
    pub held: Vec<HeldRole>,
}
