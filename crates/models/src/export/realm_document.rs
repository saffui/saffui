use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entities::auth::{
    AuthenticationExecutionModel, AuthenticationFlowModel, AuthenticatorConfigModel,
    RequiredActionModel,
};
use crate::entities::authz::GroupModel;
use crate::entities::authz::{
    IdentityProviderModel, PolicyModel, ResourceModel, ResourceServerModel, RoleModel, ScopeModel,
};
use crate::entities::client::{ClientExport, ClientScopeModel, ProtocolMapperModel};
use crate::entities::keys::{KeyStatus, KeyUse, RealmSigningKey};
use crate::entities::organization::OrganizationModel;
use crate::entities::realm::RealmModel;
use crate::str_enum::str_enum;
use crypto::provider::SignAlg;

str_enum! {
    /// What a document says about the operator supplied values it carries.
    ///
    /// Authenticator and provider configurations are free form maps. Nothing
    /// here writes anything secret into them, but an operator does: mail
    /// passwords, captcha secrets and provider keys all live there. An exporter
    /// cannot look at a value and know, so the choice is explicit rather than
    /// implied by whatever was easy.
    pub enum SecretHandling {
        /// Replace values with a marker, keeping their keys. The shape of the
        /// configuration survives, so an import knows exactly what has to be
        /// re-supplied, and the document is safe to hand to someone who should
        /// not hold the secrets.
        Redact => "redact",
        /// Carry values as they are. For a migration between deployments of one
        /// operator, where the document is then handled as the secret material
        /// it contains.
        Include => "include",
    }
}

impl SecretHandling {
    /// What a redacted value reads as.
    ///
    /// Deliberately not an empty string. An importer has to be able to tell that
    /// the operator set nothing apart from this having been removed on the way
    /// out.
    pub const REDACTED: &'static str = "<redacted>";
}

str_enum! {
    /// The parts of a realm a document may carry.
    ///
    /// Named rather than listed as free text. A document declaring a section
    /// nobody defined reads as carrying it and answers nothing, and asking for
    /// one whose name is misspelled quietly says it is absent, which reads
    /// exactly like an export that left it out.
    pub enum Section {
        Realm => "realm",
        Theme => "theme",
        RequiredActions => "required-actions",
        Authentication => "authentication",
        Roles => "roles",
        Groups => "groups",
        ClientScopes => "client-scopes",
        ProtocolMappers => "protocol-mappers",
        Clients => "clients",
        IdentityProviders => "identity-providers",
        Organizations => "organizations",
        ResourceServers => "resource-servers",
        Policies => "policies",
        SigningKeys => "signing-keys",
        RebacSchema => "rebac-schema",
        IdentityStream => "identity-stream",
    }
}

/// A realm's compiled relationship schema as exported.
///
/// Both halves travel. The source is what an operator wrote and edits, the
/// compiled form is what the engine walks. Re-compiling on import is equivalent
/// only as long as the compiler never changes, and an export that silently
/// reinterprets an authorization schema is not one anybody should trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebacSchemaExport {
    pub version: i32,
    pub source: String,
    pub compiled: serde_json::Value,
}

/// A signing key as a document carries it, private material included.
///
/// A type of its own rather than the stored one, which deliberately cannot be
/// serialised at all. Putting a private key into a document is a deliberate act,
/// and this is what that act looks like: it cannot be reached by writing the
/// stored key into a list, and the name of the type says what is in it.
///
/// `Debug` is written rather than derived, for the reason it is on the stored
/// key: a log line that formats a document should not carry the realm's signing
/// identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExportedSigningKey {
    pub kid: String,
    pub realm_id: String,
    pub algorithm: SignAlg,
    pub key_use: KeyUse,
    pub status: KeyStatus,
    pub priority: i64,
    /// PEM encoded private key.
    pub private_pem: Vec<u8>,
    pub public_jwk: serde_json::Value,
    pub created_at: i64,
}

impl std::fmt::Debug for ExportedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedSigningKey")
            .field("kid", &self.kid)
            .field("realm_id", &self.realm_id)
            .field("algorithm", &self.algorithm)
            .field("key_use", &self.key_use)
            .field("status", &self.status)
            .field("priority", &self.priority)
            .field("private_pem", &"<redacted>")
            .field("public_jwk", &self.public_jwk)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl From<&RealmSigningKey> for ExportedSigningKey {
    fn from(key: &RealmSigningKey) -> Self {
        Self {
            kid: key.kid.clone(),
            realm_id: key.realm_id.clone(),
            algorithm: key.algorithm,
            key_use: key.key_use,
            status: key.status,
            priority: key.priority,
            private_pem: key.private_pem.clone(),
            public_jwk: key.public_jwk.clone(),
            created_at: key.created_at,
        }
    }
}

/// A join that lives in no model, carried by identifier.
///
/// The models these come from do not hold their attachments: a group is read
/// wherever a user's grants are assembled and a scope on the token issuance
/// path, where a join per row is paid on every request. An export is the one
/// reader that needs them all, so it carries them rather than making every other
/// reader pay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// What the attachment hangs off.
    pub owner_id: String,
    /// What is attached, by identifier.
    pub attached_ids: Vec<String>,
}

/// What a realm's identity records are called, alongside its configuration.
///
/// Part of the export contract rather than a detail of whoever serves it: the
/// document records this name, and any transport has to use the same one or the
/// two halves stop referring to each other.
///
/// The realm identifier is not used as it stands. Nothing constrains one, and
/// this name becomes a header value and, for a caller writing files, a path. An
/// identifier holding a quote, a slash or a newline would produce a header the
/// transport rejects, turning a valid export into a failure, or a file written
/// somewhere nobody intended. Anything outside a conservative set becomes an
/// underscore, which keeps this total: every identifier yields a usable name.
///
/// The mapping is deliberately not reversible. This is a label rather than an
/// identifier, and the authoritative one travels unaltered inside the stream.
pub fn identity_stream_filename(realm_id: &str) -> String {
    let safe: String = realm_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    // An identifier of nothing usable leaves nothing to name the file after, and
    // a leading dot would hide it or read as a path segment.
    let stem = safe.trim_matches('.');
    let stem = if stem.is_empty() { "realm" } else { stem };
    format!("{stem}-identity.ndjson")
}

/// A realm's configuration as one document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedRealm {
    /// The document format, so an importer can refuse what it cannot read.
    pub format_version: u32,
    pub exported_at: DateTime<Utc>,
    /// Which parts this document carries. A section not exported and one genuinely
    /// empty look identical otherwise.
    pub sections: Vec<Section>,
    /// How operator supplied values were treated, so a reader tells a redacted
    /// document from a complete one instead of importing markers as values.
    pub secret_handling: SecretHandling,

    pub realm: RealmModel,
    pub theme: Option<serde_json::Value>,
    /// Ordered by priority.
    pub required_actions: Vec<RequiredActionModel>,

    pub authentication_flows: Vec<AuthenticationFlowModel>,
    /// Listed before the steps referencing them. That reference has no constraint
    /// behind it, so the order is the only thing keeping it resolvable on replay.
    pub authenticator_configs: Vec<AuthenticatorConfigModel>,
    pub authentication_executions: Vec<AuthenticationExecutionModel>,

    /// Realm roles and client roles alike; the flag on each tells them apart,
    /// and every grant in the document points here.
    pub roles: Vec<RoleModel>,
    pub groups: Vec<GroupModel>,
    /// The roles granted to each group.
    pub group_roles: Vec<Attachment>,

    /// Every scope in the realm. One attached to nothing still travels, because
    /// it is part of the configuration whether or not a client uses it today.
    pub client_scopes: Vec<ClientScopeModel>,
    pub client_scope_roles: Vec<Attachment>,
    pub client_scope_protocol_mappers: Vec<Attachment>,
    pub protocol_mappers: Vec<ProtocolMapperModel>,

    /// Each client with what it is attached to. Those joins are recoverable from
    /// nowhere else, and without them a restored client emits no mapped claims.
    pub clients: Vec<ClientExport>,

    pub identity_providers: Vec<IdentityProviderModel>,
    pub organizations: Vec<OrganizationModel>,
    pub org_themes: Vec<(String, serde_json::Value)>,
    /// Which providers each organization is linked to.
    pub org_identity_providers: Vec<Attachment>,

    pub resource_servers: Vec<ResourceServerModel>,
    /// The verbs a resource server recognises, distinct from client scopes.
    pub authz_scopes: Vec<ScopeModel>,
    pub resources: Vec<ResourceModel>,
    /// Policies and permissions alike: one table backs both.
    pub policies: Vec<PolicyModel>,

    /// The realm's signing keys, private material included.
    ///
    /// Empty when values are redacted, and the section list says so. Redaction
    /// omits rather than masks here, and this is the clearest of the cases: a
    /// key without its private half is a key the realm cannot sign with, so
    /// masking imports a realm that believes it has one and cannot issue a
    /// single token.
    ///
    /// Unlike a password, a missing signing key costs nothing to recover. The
    /// realm mints a fresh one and carries on, where a missing password obliges
    /// every user to reset. That asymmetry makes omission the safe default and
    /// carrying them a deliberate act: whoever holds a document that includes
    /// them can mint tokens every relying party still trusting this realm will
    /// accept.
    #[serde(default)]
    pub realm_signing_keys: Vec<ExportedSigningKey>,

    #[serde(default)]
    pub rebac_schema: Option<RebacSchemaExport>,

    /// Where this realm's identity records live, when they were exported.
    ///
    /// Users are not in this document. Everything else here is bounded by
    /// configuration: a realm has tens of clients and hundreds of roles however
    /// popular it becomes. Users are not, so holding them here would make the
    /// exporter's memory grow with the realm and fail on exactly the deployments
    /// where an export matters most.
    ///
    /// A name means an identity stream accompanies this document. Absent means
    /// the export carries configuration only, and **not** that the realm has no
    /// users. Without that distinction a configuration-only export is
    /// indistinguishable from an empty realm, and an import would conclude there
    /// was nobody to restore.
    #[serde(default)]
    pub identity_stream: Option<String>,
}

impl ExportedRealm {
    /// The current document format.
    pub const FORMAT_VERSION: u32 = 1;

    /// Whether the document claims to carry `section`.
    pub fn has_section(&self, section: Section) -> bool {
        self.sections.contains(&section)
    }
}

/// Why an import was refused.
///
/// Named rather than collapsed into a message, because each one tells an
/// operator a different thing to do: a version mismatch needs a different build,
/// a foreign tenant needs a different caller, an existing realm needs a deletion
/// first.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportRejection {
    #[error("this build reads format {supported}, and the document is format {found}")]
    UnsupportedFormat { found: u32, supported: u32 },
    #[error("the document belongs to another tenant")]
    ForeignTenant,
    #[error("a realm named {name} already exists here")]
    RealmExists { name: String },
    #[error("the document carries no realm")]
    NoRealm,
    /// The document says its values were redacted, and the caller asked for an
    /// import that needs them.
    #[error("the document was exported with its values redacted")]
    ValuesRedacted,
}

/// What an import wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedRealm {
    pub realm_id: String,
    pub roles: usize,
    pub groups: usize,
    pub client_scopes: usize,
    pub clients: usize,
    pub identity_providers: usize,
    pub organizations: usize,
    pub resource_servers: usize,
    pub policies: usize,
    pub signing_keys: usize,
    /// Sections declared and not written. Reported rather than dropped, since an
    /// import that quietly skips one leaves a realm that looks restored.
    pub skipped: Vec<Section>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;
    use std::str::FromStr;

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(SecretHandling::ALL.len(), 2);
        assert_eq!(Section::ALL.len(), 16);
        assert_eq!(Section::RequiredActions.as_str(), "required-actions");
        assert_round_trips(SecretHandling::ALL);
        assert_round_trips(Section::ALL);
    }

    /// A section is named, so a document cannot claim one nobody defined and a
    /// reader cannot ask for one that is merely misspelled. Both read as absent
    /// otherwise, which is the same answer as an export that left it out.
    #[test]
    fn a_section_nobody_defined_cannot_be_named() {
        for undeclared in ["client-scope", "Clients", "users", "", "signing_keys"] {
            assert!(
                Section::from_str(undeclared).is_err(),
                "{undeclared:?} must not name a section"
            );
        }
        assert!(Section::from_str("signing-keys").is_ok());
    }

    /// A redacted value reads as something an importer can tell apart from a
    /// value nobody set.
    #[test]
    fn a_redacted_value_is_not_an_empty_one() {
        assert!(!SecretHandling::REDACTED.is_empty());
        assert_ne!(SecretHandling::REDACTED, "");
        assert_eq!(SecretHandling::Redact.as_str(), "redact");
        assert_eq!(SecretHandling::Include.as_str(), "include");
    }

    /// An identifier is a label here, and the function is total: every one of
    /// them yields a name that can be used as a header value and as a path.
    #[test]
    fn every_identifier_yields_a_usable_name() {
        assert_eq!(identity_stream_filename("acme"), "acme-identity.ndjson");
        assert_eq!(
            identity_stream_filename("acme-prod.eu"),
            "acme-prod.eu-identity.ndjson"
        );

        for hostile in [
            "a/b",
            "a\\b",
            "a\"b",
            "a\nb",
            "a b",
            "../etc/passwd",
            "a;b",
            "réalm",
        ] {
            let name = identity_stream_filename(hostile);
            assert!(
                name.ends_with("-identity.ndjson"),
                "{hostile:?} gave {name}"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
                "{hostile:?} gave {name}"
            );
            assert!(!name.starts_with('.'), "{hostile:?} gave {name}");
            assert!(!name.contains('/'), "{hostile:?} gave {name}");
        }
    }

    /// An identifier that leaves nothing behind still names a file, rather than
    /// producing one whose whole name is the suffix or one that starts with a
    /// dot and hides.
    ///
    /// Only an identifier that leaves nothing falls back. One made entirely of
    /// characters that map to underscores keeps them, since the result is a
    /// usable name and collapsing it would lose what little it says.
    #[test]
    fn an_identifier_that_leaves_nothing_still_names_a_file() {
        for nothing in ["", ".", "..."] {
            assert_eq!(
                identity_stream_filename(nothing),
                "realm-identity.ndjson",
                "{nothing:?}"
            );
        }

        assert_eq!(identity_stream_filename("///"), "___-identity.ndjson");
        assert_eq!(identity_stream_filename("\n"), "_-identity.ndjson");
    }

    /// Two identifiers can map to one name, which is why this is a label and
    /// the authoritative identifier travels inside the stream.
    #[test]
    fn the_mapping_is_not_reversible_and_says_so() {
        assert_eq!(
            identity_stream_filename("a/b"),
            identity_stream_filename("a b")
        );
    }

    /// Carrying a private key into a document is a deliberate act with a type of
    /// its own. The stored key cannot be serialised at all, so it cannot be
    /// written into a list by accident.
    #[test]
    fn a_signing_key_reaches_a_document_only_through_its_own_type() {
        let stored = RealmSigningKey {
            tenant: "acme".into(),
            realm_id: "realm-1".into(),
            kid: "kid-1".into(),
            algorithm: SignAlg::Es256,
            key_use: KeyUse::Sig,
            status: KeyStatus::Active,
            priority: 7,
            private_pem: b"-----BEGIN PRIVATE KEY-----secret".to_vec(),
            public_jwk: serde_json::json!({"kty": "EC"}),
            created_at: 42,
        };

        let exported = ExportedSigningKey::from(&stored);
        assert_eq!(exported.kid, stored.kid);
        assert_eq!(exported.algorithm, stored.algorithm);
        assert_eq!(
            exported.private_pem, stored.private_pem,
            "the whole point of this type is that it carries the key"
        );

        // And it still does not reach a log line by being formatted.
        let rendered = format!("{exported:?}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("kid-1"));
    }

    fn document(sections: Vec<Section>) -> ExportedRealm {
        use crate::auditable::AuditableModel;
        use crate::entities::realm::RealmCreateModel;

        ExportedRealm {
            format_version: ExportedRealm::FORMAT_VERSION,
            exported_at: DateTime::from_timestamp(1_000, 0).expect("a valid instant"),
            sections,
            secret_handling: SecretHandling::Redact,
            realm: RealmCreateModel {
                name: "acme".into(),
                display_name: "Acme".into(),
                enabled: true,
            }
            .into_model(
                "realm-1".into(),
                AuditableModel::from_creator("acme".into(), "root".into()),
            ),
            theme: None,
            required_actions: Vec::new(),
            authentication_flows: Vec::new(),
            authenticator_configs: Vec::new(),
            authentication_executions: Vec::new(),
            roles: Vec::new(),
            groups: Vec::new(),
            group_roles: Vec::new(),
            client_scopes: Vec::new(),
            client_scope_roles: Vec::new(),
            client_scope_protocol_mappers: Vec::new(),
            protocol_mappers: Vec::new(),
            clients: Vec::new(),
            identity_providers: Vec::new(),
            organizations: Vec::new(),
            org_themes: Vec::new(),
            org_identity_providers: Vec::new(),
            resource_servers: Vec::new(),
            authz_scopes: Vec::new(),
            resources: Vec::new(),
            policies: Vec::new(),
            realm_signing_keys: Vec::new(),
            rebac_schema: None,
            identity_stream: None,
        }
    }

    /// A reader consults the section list rather than inferring from an empty
    /// one. A section that was not exported and a section that is genuinely
    /// empty look identical otherwise, and only one of them means anything is
    /// missing.
    #[test]
    fn a_document_answers_only_for_the_sections_it_declares() {
        let declared = document(vec![Section::Realm, Section::Roles]);

        assert!(declared.has_section(Section::Realm));
        assert!(declared.has_section(Section::Roles));
        assert!(
            !declared.has_section(Section::Clients),
            "a section it never claimed"
        );
        assert!(
            !declared.has_section(Section::SigningKeys),
            "and the one that matters most"
        );
        assert!(
            declared.roles.is_empty(),
            "declared and empty is not absent"
        );

        assert!(
            !document(Vec::new()).has_section(Section::Realm),
            "a document declaring nothing carries nothing"
        );
    }

    /// A configuration-only export is not an empty realm, and the difference is
    /// a name rather than an absence anyone has to interpret.
    #[test]
    fn a_configuration_only_export_is_not_an_empty_realm() {
        let configuration_only = document(vec![Section::Realm]);
        assert_eq!(configuration_only.identity_stream, None);
        assert!(!configuration_only.has_section(Section::IdentityStream));

        let with_users = ExportedRealm {
            identity_stream: Some(identity_stream_filename("realm-1")),
            sections: vec![Section::Realm, Section::IdentityStream],
            ..document(vec![Section::Realm])
        };
        assert_eq!(
            with_users.identity_stream.as_deref(),
            Some("realm-1-identity.ndjson")
        );
        assert!(with_users.has_section(Section::IdentityStream));
    }

    /// The document survives its own encoding, sections and all.
    #[test]
    fn a_document_survives_its_own_encoding() {
        let original = document(vec![Section::Realm, Section::SigningKeys]);
        let encoded = serde_json::to_string(&original).unwrap();
        assert!(encoded.contains("\"signing-keys\""), "{encoded}");

        let decoded: ExportedRealm = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.sections, original.sections);
        assert_eq!(decoded.secret_handling, original.secret_handling);
        assert_eq!(decoded.realm.name, "acme");
        assert!(decoded.has_section(Section::SigningKeys));
    }

    /// A refusal names what to do about it, and two different refusals are two
    /// different values rather than two spellings of one message.
    #[test]
    fn a_refusal_names_what_to_do_about_it() {
        let stale = ImportRejection::UnsupportedFormat {
            found: 2,
            supported: ExportedRealm::FORMAT_VERSION,
        };
        assert_ne!(stale, ImportRejection::ForeignTenant);
        assert_ne!(
            ImportRejection::RealmExists {
                name: "acme".into()
            },
            ImportRejection::NoRealm
        );
        assert!(stale.to_string().contains('1'), "{stale}");
    }

    /// What an import skipped is reported. An import that quietly drops a
    /// section leaves a realm that looks restored.
    #[test]
    fn what_an_import_skipped_is_reported_rather_than_dropped() {
        let report = ImportedRealm {
            realm_id: "realm-1".into(),
            roles: 12,
            skipped: vec![Section::RebacSchema, Section::SigningKeys],
            ..ImportedRealm::default()
        };
        assert_eq!(report.skipped.len(), 2);
        assert!(report.skipped.contains(&Section::SigningKeys));

        let encoded = serde_json::to_string(&report).unwrap();
        assert!(encoded.contains("signing-keys"), "{encoded}");
        assert_eq!(
            serde_json::from_str::<ImportedRealm>(&encoded).unwrap(),
            report
        );

        assert!(
            ImportedRealm::default().skipped.is_empty(),
            "nothing skipped is the empty list, not a missing field"
        );
    }
}
