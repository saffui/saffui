//! How sure a realm is of who a person is, as the `acr` claim says it: what
//! their sign-in reached, never what a client asked.

use super::session::{Session, proves_second_factor};

/// What a sign-in reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}
