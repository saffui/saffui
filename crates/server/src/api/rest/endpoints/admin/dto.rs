//! What the administrative plane puts on the wire.
//!
//! A shape of its own wherever the stored record would say too much. Answering
//! with the row carries every switch an entity has, and adding a column then
//! widens a public response without anybody deciding to.

use serde::Serialize;

/// A realm as a listing shows it.
///
/// Its own shape rather than the stored record. A listing that answered with
/// the row would carry every switch a realm has, and adding a column to the
/// table would silently widen a public response.
#[derive(Debug, Serialize)]
pub struct RealmBrief {
    pub realm_id: String,
    pub name: String,
    pub display_name: String,
    pub enabled: bool,
}

impl From<models::entities::realm::RealmModel> for RealmBrief {
    fn from(realm: models::entities::realm::RealmModel) -> Self {
        RealmBrief {
            realm_id: realm.realm_id,
            name: realm.name,
            display_name: realm.display_name,
            enabled: realm.enabled,
        }
    }
}

/// A key as a listing shows it: enough to recognise and revoke, never the
/// stored credential. The public key stays home; a response is not an export.
#[derive(Debug, Serialize)]
pub struct KeyBrief {
    /// base64url without padding of the raw identifier, the spelling the
    /// export format and the revocation path both use.
    pub credential_id: String,
    pub label: String,
    pub enrolled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}
