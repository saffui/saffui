//! A realm's identity records, one per line.
//!
//! Everything in the configuration document is bounded by configuration: a realm
//! has tens of clients and hundreds of roles however popular it becomes. Users
//! are not, so they are streamed and never assembled, which keeps an exporter's
//! memory flat on exactly the deployments where an export matters most.

use serde::{Deserialize, Serialize};

use crate::entities::credentials::CredentialModel;
use crate::entities::organization::OrgMembershipType;
use crate::entities::user::UserModel;
use crate::export::realm_document::SecretHandling;
use crate::str_enum::str_enum;

/// The stream format this build writes and reads.
///
/// A reader refuses a section it does not know, so a newer stream is not
/// readable by an older build, which is what a version is for.
pub const FORMAT_VERSION: u32 = 1;

str_enum! {
    /// A section of the stream, one per relation and named for it.
    ///
    /// The declaration order is the order sections are written and the order an
    /// import replays them in: a record never appears before the thing it
    /// references.
    ///
    /// The order has to be right here because the database only partly enforces
    /// it. Roles and groups carry a constraint back to the user, so those fail
    /// loudly on a bad order, but the policy, membership and passkey rows
    /// reference their user with a bare column, so replaying those out of order
    /// produces rows pointing at nobody, silently.
    ///
    /// One table, so the wire name is the wire name. Deriving these names from
    /// the variant instead gets one of them wrong: a variant named for the
    /// singular of a plural relation serialises to a word no stream ever
    /// contained, and nothing notices while the enum is only ever written
    /// through a hand-written accessor.
    pub enum IdentitySection {
        Users => "users",
        /// Which kinds of authenticator each user held.
        ///
        /// A projection rather than a relation, and the only section that maps
        /// to no table. It exists because redaction removes credential material
        /// and, without this, the fact along with it. A restore that cannot tell
        /// "had a password, redacted away" from "never had one" cannot decide
        /// what a user has to enrol again, and guessing from an absence of rows
        /// is no substitute: a first factor that stores nothing at all makes
        /// every user look credential-less whether or not they ever were.
        ///
        /// Carried under both handlings. The kind is not the material.
        UsersAuthenticators => "users_authenticators",
        UsersCredentials => "users_credentials",
        WebauthnCredentials => "webauthn_credentials",
        UsersRoles => "users_roles",
        UsersGroups => "users_groups",
        UsersPolicies => "users_policies",
        OrganizationsMembers => "organizations_members",
        OrganizationsMembersRoles => "organizations_members_roles",
        /// Last: a tuple can name a user, a group or an organization on either
        /// side of a relation, so everything it might reference is already out.
        RebacTuples => "rebac_tuples",
    }
}

impl IdentitySection {
    /// The relation this section carries, or nothing for a projection.
    ///
    /// Only the authenticator shadow answers nothing, and that is what keeps the
    /// stream and a table inventory honest about each other: one enumerates
    /// tables, the other sections, and they agree on everything that is a table.
    pub fn table(self) -> Option<&'static str> {
        match self {
            Self::UsersAuthenticators => None,
            other => Some(other.as_str()),
        }
    }

    /// Whether this section carries authentication material, and so is written
    /// only when the caller asked for secrets.
    ///
    /// A passkey counts. What is stored is a public key, so it is not a secret
    /// the way a password record is, but it is still the binding that lets one
    /// authenticator sign in as this user. Same class of thing, and the
    /// conservative call is to gate it the same way.
    pub fn is_secret_material(self) -> bool {
        matches!(self, Self::UsersCredentials | Self::WebauthnCredentials)
    }

    /// Where this section falls in the write and replay order.
    pub fn position(self) -> usize {
        Self::ALL
            .iter()
            .position(|section| *section == self)
            .expect("every section is in the order")
    }
}

/// One kind of authenticator a user held.
///
/// The kind is a string rather than the closed credential catalogue. A stream is
/// read by a build that is not the one that wrote it, and refusing an unknown
/// kind would fail an entire import over a credential type this build merely has
/// no action for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAuthenticatorRecord {
    pub user_id: String,
    pub authenticator: String,
}

/// The kind standing for a passkey, which lives in its own relation rather than
/// among the credentials.
pub const WEBAUTHN_AUTHENTICATOR: &str = "webauthn";

/// A passkey.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebauthnCredentialRecord {
    pub user_id: String,
    /// base64url without padding, of the raw identifier. The encoding is the
    /// specification's own, so the exported value is one a reader recognises.
    pub credential_id_b64url: String,
    /// The passkey as the authenticator layer stores it.
    pub passkey: serde_json::Value,
    /// Carried because it cannot be reconstructed: the column defaults to now, so a
    /// passkey restored without it is stamped with the import date.
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A role granted directly to a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRoleRecord {
    pub user_id: String,
    pub role_id: String,
}

/// A user's membership of a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserGroupRecord {
    pub user_id: String,
    pub group_id: String,
}

/// A user named directly by an authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPolicyRecord {
    pub server_id: String,
    pub user_id: String,
    pub policy_id: String,
}

/// A user's membership of an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMemberRecord {
    pub org_id: String,
    pub user_id: String,
    pub membership_type: OrgMembershipType,
    pub joined_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A role granted to a member within an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMemberRoleRecord {
    pub org_id: String,
    pub user_id: String,
    pub role_id: String,
}

/// One relationship based authorization tuple.
///
/// Streamed rather than carried in the configuration document because this is
/// the one authorization relation with no ceiling: a realm expressing who can
/// see which document has a tuple per relationship, which grows with the data
/// the realm protects rather than with how the realm is configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebacTupleRecord {
    pub object_type: String,
    pub object_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    /// The subject's own relation, for a set of subjects rather than one. Absent
    /// when the subject is a single principal.
    pub subject_relation: Option<String>,
}

/// One record of the stream.
///
/// The tag is the section name, so a reader knows what a line is before it reads
/// what is in it. That name is asserted against the section catalogue rather than
/// derived from the variant: a variant named for the singular of a plural
/// relation would otherwise tag every record under a section marker that
/// disagrees with the marker itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "section", content = "data")]
pub enum IdentityRecord {
    #[serde(rename = "users")]
    Users(Box<UserModel>),
    #[serde(rename = "users_authenticators")]
    UsersAuthenticators(UserAuthenticatorRecord),
    #[serde(rename = "users_credentials")]
    UsersCredentials(Box<CredentialModel>),
    #[serde(rename = "webauthn_credentials")]
    WebauthnCredentials(WebauthnCredentialRecord),
    #[serde(rename = "users_roles")]
    UsersRoles(UserRoleRecord),
    #[serde(rename = "users_groups")]
    UsersGroups(UserGroupRecord),
    #[serde(rename = "users_policies")]
    UsersPolicies(UserPolicyRecord),
    #[serde(rename = "organizations_members")]
    OrganizationsMembers(OrganizationMemberRecord),
    #[serde(rename = "organizations_members_roles")]
    OrganizationsMembersRoles(OrganizationMemberRoleRecord),
    #[serde(rename = "rebac_tuples")]
    RebacTuples(RebacTupleRecord),
}

impl IdentityRecord {
    /// Which section this record belongs to.
    pub fn section(&self) -> IdentitySection {
        match self {
            Self::Users(_) => IdentitySection::Users,
            Self::UsersAuthenticators(_) => IdentitySection::UsersAuthenticators,
            Self::UsersCredentials(_) => IdentitySection::UsersCredentials,
            Self::WebauthnCredentials(_) => IdentitySection::WebauthnCredentials,
            Self::UsersRoles(_) => IdentitySection::UsersRoles,
            Self::UsersGroups(_) => IdentitySection::UsersGroups,
            Self::UsersPolicies(_) => IdentitySection::UsersPolicies,
            Self::OrganizationsMembers(_) => IdentitySection::OrganizationsMembers,
            Self::OrganizationsMembersRoles(_) => IdentitySection::OrganizationsMembersRoles,
            Self::RebacTuples(_) => IdentitySection::RebacTuples,
        }
    }
}

/// The stream's opening line: what this is, and what to expect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityManifest {
    pub format_version: u32,
    pub tenant: String,
    pub realm_id: String,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    /// Whether the material travelled. Under redaction the credential sections
    /// are absent from the list below entirely rather than present and empty.
    pub secret_handling: SecretHandling,
    /// The sections this stream contains, in order.
    pub sections: Vec<IdentitySection>,
}

/// How many records a section carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionCount {
    pub section: IdentitySection,
    pub records: u64,
}

/// The stream's closing line, and the only proof it is whole.
///
/// A stream that ends without one was truncated, however well formed everything
/// before it looked, and a reader has to treat it as failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityTrailer {
    /// Records per section, in the order written. A section that carried nothing
    /// appears with a zero, which is what tells empty from never written.
    pub counts: Vec<SectionCount>,
    /// Whether the exporter finished, so a reader checks something positive instead
    /// of inferring wholeness from the absence of an error.
    pub complete: bool,
}

impl IdentityTrailer {
    /// Records across every section.
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|count| count.records).sum()
    }

    /// What a section carried, or nothing if it was never written.
    pub fn count_of(&self, section: IdentitySection) -> Option<u64> {
        self.counts
            .iter()
            .find(|count| count.section == section)
            .map(|count| count.records)
    }
}

/// What an ingestion wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityIngestReport {
    pub sections: Vec<SectionCount>,
    /// Actions the import granted for authenticators the stream could not carry.
    /// Reported, since an operator needs to know who must enrol again.
    pub required_actions_granted: Vec<(String, u64)>,
}

impl IdentityIngestReport {
    /// Whether what was written matches what the exporter recorded.
    ///
    /// Compared section by section rather than on the total. Two sections whose
    /// errors cancel sum to the right number, and a restore that lost every
    /// group membership while gaining as many role grants is not a restore.
    pub fn agrees_with(&self, trailer: &IdentityTrailer) -> bool {
        let written = |section: IdentitySection| {
            self.sections
                .iter()
                .find(|count| count.section == section)
                .map(|count| count.records)
        };

        trailer
            .counts
            .iter()
            .all(|count| written(count.section) == Some(count.records))
            && self.sections.len() == trailer.counts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;
    use std::str::FromStr;

    fn record_of(section: IdentitySection) -> IdentityRecord {
        match section {
            IdentitySection::Users => IdentityRecord::Users(Box::new(user())),
            IdentitySection::UsersAuthenticators => {
                IdentityRecord::UsersAuthenticators(UserAuthenticatorRecord {
                    user_id: "ada".into(),
                    authenticator: "password".into(),
                })
            }
            IdentitySection::UsersCredentials => {
                IdentityRecord::UsersCredentials(Box::new(credential()))
            }
            IdentitySection::WebauthnCredentials => {
                IdentityRecord::WebauthnCredentials(WebauthnCredentialRecord {
                    user_id: "ada".into(),
                    credential_id_b64url: "aGk".into(),
                    passkey: serde_json::json!({}),
                    enrolled_at: None,
                })
            }
            IdentitySection::UsersRoles => IdentityRecord::UsersRoles(UserRoleRecord {
                user_id: "ada".into(),
                role_id: "role-1".into(),
            }),
            IdentitySection::UsersGroups => IdentityRecord::UsersGroups(UserGroupRecord {
                user_id: "ada".into(),
                group_id: "group-1".into(),
            }),
            IdentitySection::UsersPolicies => IdentityRecord::UsersPolicies(UserPolicyRecord {
                server_id: "server-1".into(),
                user_id: "ada".into(),
                policy_id: "policy-1".into(),
            }),
            IdentitySection::OrganizationsMembers => {
                IdentityRecord::OrganizationsMembers(OrganizationMemberRecord {
                    org_id: "org-1".into(),
                    user_id: "ada".into(),
                    membership_type: OrgMembershipType::Unmanaged,
                    joined_at: None,
                })
            }
            IdentitySection::OrganizationsMembersRoles => {
                IdentityRecord::OrganizationsMembersRoles(OrganizationMemberRoleRecord {
                    org_id: "org-1".into(),
                    user_id: "ada".into(),
                    role_id: "role-1".into(),
                })
            }
            IdentitySection::RebacTuples => IdentityRecord::RebacTuples(RebacTupleRecord {
                object_type: "document".into(),
                object_id: "doc-1".into(),
                relation: "editor".into(),
                subject_type: "user".into(),
                subject_id: "ada".into(),
                subject_relation: None,
            }),
        }
    }

    fn user() -> UserModel {
        use crate::auditable::AuditableModel;
        use crate::entities::user::UserCreateModel;

        UserCreateModel {
            user_name: "ada".into(),
            enabled: true,
            email: "ada@example.test".into(),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            attributes: None,
            is_service_account: None,
            service_account_client_link: None,
        }
        .into_model(
            "ada".into(),
            "realm-1".into(),
            AuditableModel::from_creator("acme".into(), "root".into()),
        )
    }

    fn credential() -> CredentialModel {
        use crate::auditable::AuditableModel;
        use crate::entities::credentials::{CredentialSecret, OtpAlgorithm, OtpParameters};

        CredentialModel::otp(
            "cred-1".into(),
            "realm-1".into(),
            "ada".into(),
            CredentialSecret::new("JBSWY3DPEHPK3PXP".into()),
            OtpAlgorithm::Sha1,
            OtpParameters::totp_default(),
            AuditableModel::from_creator("acme".into(), "ada".into()),
        )
    }

    #[test]
    fn the_sections_agree_with_their_own_spelling() {
        assert_eq!(IdentitySection::ALL.len(), 10);
        assert_round_trips(IdentitySection::ALL);
    }

    /// The one name a derivation from the variant would get wrong. A relation
    /// with a plural first word named by a singular variant serialises to a word
    /// no stream ever contained, and nothing notices while the enum is only ever
    /// written through an accessor.
    #[test]
    fn the_plural_relation_keeps_its_own_name() {
        assert_eq!(
            IdentitySection::UsersCredentials.as_str(),
            "users_credentials"
        );
        assert!(IdentitySection::from_str("user_credentials").is_err());
        assert_eq!(
            IdentitySection::from_str("users_credentials").unwrap(),
            IdentitySection::UsersCredentials
        );
    }

    /// A record's tag is its section's own name. Otherwise the marker opening a
    /// section and every record under it disagree, and a reader that trusted
    /// either would be right half the time.
    #[test]
    fn every_record_is_tagged_with_its_sections_name() {
        for section in IdentitySection::ALL {
            let record = record_of(*section);
            assert_eq!(record.section(), *section);

            let encoded = serde_json::to_value(&record).unwrap();
            assert_eq!(
                encoded.get("section").and_then(|v| v.as_str()),
                Some(section.as_str()),
                "the tag and the section name disagree for {section}"
            );
        }
    }

    /// The order is the write order and the replay order. It matters because the
    /// database only partly enforces it: some rows carry a constraint back to
    /// their user and fail loudly, while others reference it with a bare column
    /// and land pointing at nobody.
    #[test]
    fn the_order_puts_every_reference_after_what_it_names() {
        let users = IdentitySection::Users.position();
        for section in IdentitySection::ALL {
            if *section != IdentitySection::Users {
                assert!(
                    section.position() > users,
                    "{section} may name a user and comes before them"
                );
            }
        }

        assert!(
            IdentitySection::OrganizationsMembersRoles.position()
                > IdentitySection::OrganizationsMembers.position(),
            "a member's roles come after the membership"
        );
        assert_eq!(
            IdentitySection::RebacTuples.position(),
            IdentitySection::ALL.len() - 1,
            "a tuple may name anything, so it is last"
        );
        assert_eq!(
            IdentitySection::UsersAuthenticators.position(),
            1,
            "the shadow sits with the users it describes, before the material"
        );
    }

    /// Exactly one section is a projection, and exactly two carry material.
    /// Counted rather than asserted one by one, since the failure is a section
    /// nobody classified.
    #[test]
    fn the_projection_and_the_material_are_exactly_what_they_are() {
        assert_eq!(
            IdentitySection::ALL
                .iter()
                .filter(|s| s.table().is_none())
                .count(),
            1
        );
        assert_eq!(IdentitySection::UsersAuthenticators.table(), None);

        let material: Vec<&IdentitySection> = IdentitySection::ALL
            .iter()
            .filter(|s| s.is_secret_material())
            .collect();
        assert_eq!(
            material,
            vec![
                &IdentitySection::UsersCredentials,
                &IdentitySection::WebauthnCredentials
            ],
            "the passkey is gated with the password record"
        );

        // The shadow is not material and travels under both handlings, which is
        // its whole reason to exist.
        assert!(!IdentitySection::UsersAuthenticators.is_secret_material());
    }

    /// Every section that is a relation names it, and the name is its own.
    #[test]
    fn a_section_that_is_a_relation_names_it() {
        for section in IdentitySection::ALL {
            match section.table() {
                Some(table) => assert_eq!(table, section.as_str(), "{section}"),
                None => assert_eq!(*section, IdentitySection::UsersAuthenticators),
            }
        }
    }

    fn trailer() -> IdentityTrailer {
        IdentityTrailer {
            counts: vec![
                SectionCount {
                    section: IdentitySection::Users,
                    records: 3,
                },
                SectionCount {
                    section: IdentitySection::UsersRoles,
                    records: 0,
                },
            ],
            complete: true,
        }
    }

    /// A section that was opened and carried nothing is not a section that was
    /// never written, and only the trailer can tell them apart.
    #[test]
    fn an_empty_section_is_not_an_absent_one() {
        let trailer = trailer();
        assert_eq!(trailer.count_of(IdentitySection::UsersRoles), Some(0));
        assert_eq!(trailer.count_of(IdentitySection::UsersGroups), None);
        assert_eq!(trailer.total(), 3);
    }

    /// The counts are compared section by section. Two sections whose errors
    /// cancel sum to the right number, and a restore that lost every group
    /// membership while gaining as many role grants is not a restore.
    #[test]
    fn the_counts_are_compared_section_by_section() {
        let trailer = trailer();

        let faithful = IdentityIngestReport {
            sections: trailer.counts.clone(),
            ..IdentityIngestReport::default()
        };
        assert!(faithful.agrees_with(&trailer));

        let cancelling = IdentityIngestReport {
            sections: vec![
                SectionCount {
                    section: IdentitySection::Users,
                    records: 2,
                },
                SectionCount {
                    section: IdentitySection::UsersRoles,
                    records: 1,
                },
            ],
            ..IdentityIngestReport::default()
        };
        assert_eq!(
            cancelling.sections.iter().map(|c| c.records).sum::<u64>(),
            trailer.total(),
            "the totals agree"
        );
        assert!(!cancelling.agrees_with(&trailer), "and the sections do not");

        let short = IdentityIngestReport {
            sections: vec![SectionCount {
                section: IdentitySection::Users,
                records: 3,
            }],
            ..IdentityIngestReport::default()
        };
        assert!(
            !short.agrees_with(&trailer),
            "a section the stream carried and the import did not write"
        );

        // And the other way round: an import that wrote a section the stream
        // never carried has not replayed this stream, whatever the numbers say
        // about the ones it did.
        let extra = IdentityIngestReport {
            sections: {
                let mut counts = trailer.counts.clone();
                counts.push(SectionCount {
                    section: IdentitySection::UsersGroups,
                    records: 4,
                });
                counts
            },
            ..IdentityIngestReport::default()
        };
        assert!(!extra.agrees_with(&trailer));
    }

    /// The manifest carries typed sections and a typed handling, so a stream
    /// cannot announce a section this build has no name for.
    #[test]
    fn a_manifest_cannot_announce_a_section_nobody_defined() {
        let manifest = IdentityManifest {
            format_version: FORMAT_VERSION,
            tenant: "acme".into(),
            realm_id: "realm-1".into(),
            exported_at: chrono::DateTime::from_timestamp(1_000, 0).unwrap(),
            secret_handling: SecretHandling::Redact,
            sections: vec![IdentitySection::Users, IdentitySection::UsersAuthenticators],
        };

        let encoded = serde_json::to_string(&manifest).unwrap();
        assert!(encoded.contains("\"users_authenticators\""), "{encoded}");
        assert_eq!(
            serde_json::from_str::<IdentityManifest>(&encoded).unwrap(),
            manifest
        );

        let invented = encoded.replace("users_authenticators", "users_secrets");
        assert!(
            serde_json::from_str::<IdentityManifest>(&invented).is_err(),
            "a section nobody defined must not decode"
        );
    }

    /// A trailer that says the export stopped early reads back as saying so,
    /// rather than being indistinguishable from a whole one.
    #[test]
    fn a_trailer_can_say_the_export_stopped_early() {
        let partial = IdentityTrailer {
            complete: false,
            ..trailer()
        };
        let encoded = serde_json::to_string(&partial).unwrap();
        let decoded: IdentityTrailer = serde_json::from_str(&encoded).unwrap();
        assert!(!decoded.complete);
        assert_ne!(decoded, trailer());
    }
}
