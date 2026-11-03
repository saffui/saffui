//! What the administration API says and hears, written once. The server
//! answers with these types and the command line reads them: a field renamed
//! on one side alone does not compile on the other.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub issuer: String,
    pub enabled: bool,
    pub created_at: String,
}

/// The verdict on the audit chain of a realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReport {
    pub intact: bool,
    /// How many events were verified before the end or the break.
    pub events: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
