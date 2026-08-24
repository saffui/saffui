use serde::{Deserialize, Serialize};

/// **Brief by default, which inverts Keycloak.**
///
/// Keycloak returns full representations from collections; for an identity
/// server that is the wrong failure direction twice over. A list of twenty
/// subjects ships twenty of whatever the resource keeps, and what it keeps is
/// where deployments put national identifiers, phone numbers and internal keys.
/// Defaulting to full means a screen that lists names quietly discloses
/// everything else to anyone whose role lets them see the list at all.
///
/// So `briefRepresentation=false` is a deliberate opt-in, and an endpoint is
/// free to require its own capability for it.
#[derive(Debug, Default, Deserialize)]
pub struct RepresentationParams {
    /// Spelled as Keycloak spells it, for the same migration reason the paging
    /// parameters are. Absent means brief.
    #[serde(rename = "briefRepresentation")]
    pub brief_representation: Option<bool>,
}

impl RepresentationParams {
    /// Whether the caller asked for the full row.
    ///
    /// Only an explicit `false` opts in. Absent, malformed and `true` all mean
    /// brief, which is the direction a disclosure default has to fail in.
    pub fn wants_full(&self) -> bool {
        self.brief_representation == Some(false)
    }
}

/// One row of a collection, in whichever shape the caller asked for.
///
/// Untagged, so the wire carries the row itself rather than a wrapper naming
/// which variant it is — the client asked for a representation and knows which
/// one it asked for. A tag would change the shape of every row to describe a
/// choice the request already records.
///
/// Generic because the *decision* is uniform even though the projection is not:
/// every collection chooses brief or full the same way, and only the brief type
/// differs per resource. Each endpoint writes a `Brief` struct and a `From`
/// impl, and nothing else.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Representation<B, F> {
    Brief(B),
    /// Boxed because the full row is normally several times the size of the
    /// brief one, and an enum is as wide as its widest arm — unboxed, every
    /// brief row in a page would carry the full row's footprint.
    Full(Box<F>),
}

impl<B, F> Representation<B, F>
where
    B: From<F>,
{
    /// Project one row. `full` comes from [`RepresentationParams::wants_full`],
    /// so the default is brief wherever this is used.
    pub fn of(row: F, full: bool) -> Self {
        if full {
            Representation::Full(Box::new(row))
        } else {
            Representation::Brief(B::from(row))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize)]
    struct Full {
        name: String,
        national_id: String,
    }

    #[derive(Debug, Serialize)]
    struct Brief {
        name: String,
    }

    impl From<Full> for Brief {
        fn from(full: Full) -> Self {
            Brief { name: full.name }
        }
    }

    fn row() -> Full {
        Full {
            name: "ada".into(),
            national_id: "1234".into(),
        }
    }

    /// Brief unless asked, and only an explicit `false` asks.
    #[test]
    fn full_is_opt_in_and_everything_else_is_brief() {
        assert!(
            !RepresentationParams::default().wants_full(),
            "no parameter is brief, never full"
        );
        assert!(
            !RepresentationParams {
                brief_representation: Some(true)
            }
            .wants_full()
        );
        assert!(
            RepresentationParams {
                brief_representation: Some(false)
            }
            .wants_full()
        );
    }

    /// A brief row carries the brief projection and nothing more — the point of
    /// the default is what it leaves out.
    #[test]
    fn the_brief_projection_drops_what_it_does_not_name() {
        let brief = Representation::<Brief, Full>::of(row(), false);
        let json = serde_json::to_string(&brief).unwrap();
        assert_eq!(json, r#"{"name":"ada"}"#);
        assert!(!json.contains("1234"));
    }

    /// Untagged: the wire is the row, with no wrapper naming the variant.
    #[test]
    fn the_wire_carries_the_row_rather_than_the_choice() {
        let full = Representation::<Brief, Full>::of(row(), true);
        assert_eq!(
            serde_json::to_string(&full).unwrap(),
            r#"{"name":"ada","national_id":"1234"}"#
        );
    }
}
