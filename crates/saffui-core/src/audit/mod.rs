//! The audit chain. Every event of a realm is linked to the one before by a
//! hash, so that none can be removed, altered or reordered without the chain
//! saying so. An event is appended in the transaction of the change it
//! records: there is no change without its event, and no event without its
//! change.

pub mod append;
pub mod canonical;
pub mod store;
pub mod verify;

use crate::ports::crypto::Digester;

/// What happened, by a name that never changes once written in a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    RealmCreated,
    SigningKeyCreated,
    ClientCreated,
    TokenIssued,
    PersonCreated,
    PersonUnlocked,
    SessionOpened,
    SessionEnded,
    TokenRevoked,
    AuthenticatorEnrolled,
    AuthenticatorRemoved,
    CodesSuspended,
    CodesResumed,
    KeyCopySuspected,
    RoleCreated,
    RoleDeleted,
    GroupCreated,
    GroupDeleted,
    RoleGranted,
    RoleRevoked,
    MemberAdded,
    MemberRemoved,
    RelationSchemaWritten,
    RelationWritten,
    RelationDeleted,
    RelationGuardWritten,
    RelationGuardDeleted,
    PolicyCreated,
    PolicyDeleted,
    ConsentGranted,
    ConsentWithdrawn,
    MapperCreated,
    MapperDeleted,
    PersonAttributesWritten,
}

impl EventKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RealmCreated => "realm.created",
            Self::SigningKeyCreated => "key.created",
            Self::ClientCreated => "client.created",
            Self::TokenIssued => "token.issued",
            Self::PersonCreated => "person.created",
            Self::PersonUnlocked => "person.unlocked",
            Self::SessionOpened => "session.opened",
            Self::SessionEnded => "session.ended",
            Self::TokenRevoked => "token.revoked",
            Self::AuthenticatorEnrolled => "authenticator.enrolled",
            Self::AuthenticatorRemoved => "authenticator.removed",
            Self::CodesSuspended => "authenticator.codes_suspended",
            Self::CodesResumed => "authenticator.codes_resumed",
            Self::KeyCopySuspected => "authenticator.key_copy_suspected",
            Self::RoleCreated => "role.created",
            Self::RoleDeleted => "role.deleted",
            Self::GroupCreated => "group.created",
            Self::GroupDeleted => "group.deleted",
            Self::RoleGranted => "role.granted",
            Self::RoleRevoked => "role.revoked",
            Self::MemberAdded => "group.member_added",
            Self::MemberRemoved => "group.member_removed",
            Self::RelationSchemaWritten => "relation.schema_written",
            Self::RelationWritten => "relation.written",
            Self::RelationDeleted => "relation.deleted",
            Self::RelationGuardWritten => "relation.guard_written",
            Self::RelationGuardDeleted => "relation.guard_deleted",
            Self::PolicyCreated => "policy.created",
            Self::PolicyDeleted => "policy.deleted",
            Self::ConsentGranted => "consent.granted",
            Self::ConsentWithdrawn => "consent.withdrawn",
            Self::MapperCreated => "client.mapper_created",
            Self::MapperDeleted => "client.mapper_deleted",
            Self::PersonAttributesWritten => "person.attributes_written",
        }
    }
}

/// The hash of the first link: there is nothing before it.
pub const GENESIS_HASH: [u8; 32] = [0; 32];

/// The hash that links an event to the chain: the previous hash, the
/// sequence number on 8 big-endian bytes, then the stored bytes of the
/// envelope, exactly as stored.
#[must_use]
pub fn hash_link(digester: &dyn Digester, previous: &[u8], seq: i64, envelope: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(previous.len() + 8 + envelope.len());
    preimage.extend_from_slice(previous);
    preimage.extend_from_slice(&seq.to_be_bytes());
    preimage.extend_from_slice(envelope);
    digester.sha256(&preimage)
}
