//! How sure a realm is of who a person is, as the `acr` claim says it: never
//! more than their sign-in reached, whatever a client asked.

use super::session::{Session, proves_second_factor};
use crate::claims::request::ClaimsRequest;

/// What a sign-in reached, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Assurance {
    OneFactor,
    TwoFactors,
}

impl Assurance {
    pub const ALL: [Self; 2] = [Self::OneFactor, Self::TwoFactors];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::OneFactor => "1",
            Self::TwoFactors => "2",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.name() == name)
    }

    /// What the sign-in behind a session reached: two factors when it was
    /// opened with a second one.
    #[must_use]
    pub fn reached_by(session: &Session) -> Self {
        if proves_second_factor(session) {
            Self::TwoFactors
        } else {
            Self::OneFactor
        }
    }
}

/// What a request requires of the level a sign-in reached: the `acr` it
/// names as essential (OpenID Connect Core 1.0, section 5.5.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequiredLevel {
    /// Nothing: whatever was reached answers.
    Any,
    /// One of these levels, weakest first: any of them answers, and so does
    /// whatever is stronger than one of them.
    OneOf(Vec<Assurance>),
    /// Levels the realm knows none of: nothing answers.
    Unknown,
}

impl RequiredLevel {
    /// Reads what a request requires, when it names claims.
    #[must_use]
    pub fn read(request: Option<&ClaimsRequest>) -> Self {
        let Some(values) = request.and_then(ClaimsRequest::read_essential_levels) else {
            return Self::Any;
        };
        let mut known: Vec<Assurance> = values
            .iter()
            .filter_map(|value| value.as_str().and_then(Assurance::parse))
            .collect();
        known.sort_unstable();
        known.dedup();
        if known.is_empty() {
            Self::Unknown
        } else {
            Self::OneOf(known)
        }
    }

    /// Whether a sign-in that reached `reached` answers.
    #[must_use]
    pub fn is_met_by(&self, reached: Assurance) -> bool {
        match self {
            Self::Any => true,
            Self::OneOf(levels) => levels.first().is_some_and(|weakest| reached >= *weakest),
            Self::Unknown => false,
        }
    }

    /// What a token says a sign-in that reached `reached` reached: the
    /// strongest of the required levels it meets, as the client must find
    /// one of the values it named; what it reached, when nothing is required.
    /// Never more than it reached.
    #[must_use]
    pub fn name_reached(&self, reached: Assurance) -> Assurance {
        match self {
            Self::OneOf(levels) => levels
                .iter()
                .rev()
                .find(|level| **level <= reached)
                .copied()
                .unwrap_or(reached),
            Self::Any | Self::Unknown => reached,
        }
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::Assurance;
    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};

    fn open_with(methods: &[AuthenticationMethod]) -> Session {
        Session {
            id: Uuid::from_u128(1),
            person: Uuid::from_u128(2),
            secret_digest: vec![1; 32],
            state: SessionState::Active,
            kind: SessionKind::Browser,
            methods: methods.to_vec(),
            authenticated_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_second_factor_raises_the_level_and_a_password_alone_does_not() {
        use AuthenticationMethod::{OneTimeCode, Password, SecurityKey};

        assert_eq!(
            Assurance::reached_by(&open_with(&[Password])),
            Assurance::OneFactor
        );
        for second in [OneTimeCode, SecurityKey] {
            assert_eq!(
                Assurance::reached_by(&open_with(&[Password, second])),
                Assurance::TwoFactors,
                "{second:?}"
            );
        }
        assert_eq!(
            Assurance::ALL.map(Assurance::name),
            ["1", "2"],
            "the names a token and the discovery document say"
        );
    }

    #[test]
    fn a_required_level_is_met_at_it_or_above_and_said_as_one_the_client_named() {
        use serde_json::{Value, json};

        use super::RequiredLevel;
        use crate::claims::request::read_claims_parameter;
        use Assurance::{OneFactor, TwoFactors};

        let required = |values: &[Value]| {
            let asked = json!({ "id_token": { "acr": { "essential": true, "values": values } } });
            RequiredLevel::read(read_claims_parameter(&asked.to_string()).as_ref())
        };

        let second = required(&[json!("2")]);
        assert!(!second.is_met_by(OneFactor));
        assert!(second.is_met_by(TwoFactors));

        let either = required(&[json!("2"), json!("1"), json!("gold")]);
        assert_eq!(either, RequiredLevel::OneOf(vec![OneFactor, TwoFactors]));
        assert!(either.is_met_by(OneFactor));
        assert_eq!(either.name_reached(TwoFactors), TwoFactors);

        let first = required(&[json!("1")]);
        assert!(first.is_met_by(TwoFactors), "more than asked answers");
        assert_eq!(
            first.name_reached(TwoFactors),
            OneFactor,
            "said as the value the client named, which was reached"
        );
        assert_eq!(second.name_reached(OneFactor), OneFactor, "never more");

        for unknown in [&[json!("gold")][..], &[json!(2)], &[json!("1 2")]] {
            let read = required(unknown);
            assert_eq!(read, RequiredLevel::Unknown, "{unknown:?}");
            assert!(!read.is_met_by(TwoFactors));
        }
        assert_eq!(RequiredLevel::read(None), RequiredLevel::Any);
        let voluntary = read_claims_parameter(r#"{"id_token": {"acr": {"values": ["2"]}}}"#);
        assert_eq!(
            RequiredLevel::read(voluntary.as_ref()),
            RequiredLevel::Any,
            "a level asked for voluntarily is a hint"
        );
        assert!(RequiredLevel::Any.is_met_by(OneFactor));
        assert_eq!(RequiredLevel::Any.name_reached(TwoFactors), TwoFactors);
    }
}
