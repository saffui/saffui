use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

/// A tab's login attempt is named by three things: the browser-wide root, the
/// tab, and the client it was started for.
///
/// All three are required. A shape holding them as optional lets an identifier
/// exist that names a tab of nothing, which cannot be looked up and cannot be
/// reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationSessionCompoundId {
    pub root_session_id: String,
    pub tab_id: String,
    pub client_id: String,
}

/// An encoded identifier that does not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a compound authentication session identifier")]
pub struct CompoundIdError;

impl AuthenticationSessionCompoundId {
    pub fn new(
        root_session_id: impl Into<String>,
        tab_id: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            root_session_id: root_session_id.into(),
            tab_id: tab_id.into(),
            client_id: client_id.into(),
        }
    }

    /// The single string form, for a URL or a cookie.
    ///
    /// Each part is encoded before the three are joined. Joining them raw on a
    /// separator only works while no part contains it, and a client identifier
    /// is routinely a hostname: `app.example.com` alone puts three extra
    /// separators in. The result is an identifier that splits into the wrong
    /// pieces, and the pieces still look like identifiers.
    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}",
            BASE64URL_NOPAD.encode(self.root_session_id.as_bytes()),
            BASE64URL_NOPAD.encode(self.tab_id.as_bytes()),
            BASE64URL_NOPAD.encode(self.client_id.as_bytes()),
        )
    }

    /// Read one back.
    ///
    /// Exactly three parts, each of which must decode. Anything else is refused
    /// rather than filled in: an identifier that arrives short names a session
    /// nobody minted.
    pub fn decode(encoded: &str) -> Result<Self, CompoundIdError> {
        let mut parts = encoded.split('.');
        let root_session_id = decode_part(parts.next())?;
        let tab_id = decode_part(parts.next())?;
        let client_id = decode_part(parts.next())?;
        if parts.next().is_some() {
            return Err(CompoundIdError);
        }
        Ok(Self {
            root_session_id,
            tab_id,
            client_id,
        })
    }
}

fn decode_part(part: Option<&str>) -> Result<String, CompoundIdError> {
    let part = part.ok_or(CompoundIdError)?;
    let bytes = BASE64URL_NOPAD
        .decode(part.as_bytes())
        .map_err(|_| CompoundIdError)?;
    String::from_utf8(bytes).map_err(|_| CompoundIdError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_survives_its_own_encoding() {
        let id = AuthenticationSessionCompoundId::new("root-1", "tab-1", "app");
        assert_eq!(
            AuthenticationSessionCompoundId::decode(&id.encode()).unwrap(),
            id
        );
    }

    /// The separator is what a client identifier is full of. Joining raw would
    /// split this into the wrong pieces, and the pieces would still look like
    /// identifiers.
    #[test]
    fn a_component_holding_the_separator_still_round_trips() {
        let id = AuthenticationSessionCompoundId::new("root.with.dots", "tab.1", "app.example.com");
        let encoded = id.encode();
        assert_eq!(
            encoded.matches('.').count(),
            2,
            "the encoding leaves exactly the two separators: {encoded}"
        );
        assert_eq!(
            AuthenticationSessionCompoundId::decode(&encoded).unwrap(),
            id
        );
    }

    /// Two different triples never encode alike. Raw joining collides: a root of
    /// `a` with a tab of `b.c` reads the same as a root of `a.b` with a tab of
    /// `c`, and one session then answers for another.
    #[test]
    fn two_different_identifiers_never_encode_alike() {
        let one = AuthenticationSessionCompoundId::new("a", "b.c", "client");
        let other = AuthenticationSessionCompoundId::new("a.b", "c", "client");
        assert_ne!(one.encode(), other.encode());
        assert_eq!(
            AuthenticationSessionCompoundId::decode(&one.encode()).unwrap(),
            one
        );
        assert_eq!(
            AuthenticationSessionCompoundId::decode(&other.encode()).unwrap(),
            other
        );
    }

    /// An identifier that does not decode is refused, not filled in.
    ///
    /// The four-part case is built from parts that each decode on their own, so
    /// it fails for having a fourth rather than for holding something
    /// unreadable.
    #[test]
    fn a_malformed_identifier_is_refused() {
        for bad in [
            "",
            "onlyone",
            "aGk.aGk",
            "aGk.aGk.aGk.aGk",
            "!!!.aGk.aGk",
            "aGk.aGk.!!!",
        ] {
            assert!(
                AuthenticationSessionCompoundId::decode(bad).is_err(),
                "{bad:?} must not decode"
            );
        }

        // The three-part version of the same parts decodes, so the rejection
        // above is about the count and not about what the parts hold.
        assert!(AuthenticationSessionCompoundId::decode("aGk.aGk.aGk").is_ok());
    }

    /// An empty component decodes to an empty string rather than being refused,
    /// so the check that matters is that it cannot be confused with a present
    /// one.
    #[test]
    fn an_empty_component_is_distinguishable_from_an_absent_one() {
        let empty_tab = AuthenticationSessionCompoundId::new("root", "", "app");
        let decoded = AuthenticationSessionCompoundId::decode(&empty_tab.encode()).unwrap();
        assert_eq!(decoded, empty_tab);
        assert!(decoded.tab_id.is_empty());
    }
}
