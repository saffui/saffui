use serde::{Deserialize, Serialize};

/// What is being asked about. Tagged, so a body naming neither arm is refused
/// by the parser rather than falling into whichever is written first.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Asked {
    /// May the caller do this to something an application protects?
    Permission {
        server: String,
        resource: String,
        scope: String,
    },
    /// Does the caller stand in this relation to this object?
    Relationship {
        object_type: String,
        object_id: String,
        relation: String,
    },
}

/// One question.
#[derive(Debug, Deserialize)]
pub struct Ask {
    #[serde(flatten)]
    pub about: Asked,
    /// A stable verb, as the record keeps it.
    pub action: String,
    /// Minted by the caller, since nothing below tells two decisions apart.
    pub decision_id: String,
    pub trace_id: Option<String>,
}

/// The reported answer and nothing else. A caller told which policy refused it
/// would read the realm's rules one refusal at a time.
#[derive(Debug, Serialize)]
pub struct Told {
    pub decision: &'static str,
}
