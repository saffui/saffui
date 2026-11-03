//! Sessions. A session is known by an identifier, which appears in tokens,
//! and proven by a secret, which appears only in the cookie of the browser
//! that signed in. The identifier alone opens nothing.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;

/// How long a session lasts, whatever is done with it.
pub const SESSION_LIFETIME: Duration = Duration::hours(12);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Ended,
}

impl SessionState {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ended => "ended",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Active, Self::Ended]
            .into_iter()
            .find(|state| state.name() == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub person: Uuid,
    pub secret_digest: Vec<u8>,
    pub state: SessionState,
    /// When the person proved who they are. Never moved by later requests.
    pub authenticated_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// What the browser holds: the identifier of the session and its secret.
#[derive(Debug)]
pub struct SessionTicket {
    pub session: Uuid,
    pub secret: Secret,
}

impl SessionTicket {
    /// The value of the cookie.
    #[must_use]
    pub fn write(&self) -> String {
        format!(
            "{}.{}",
            self.session,
            URL_SAFE_NO_PAD.encode(self.secret.expose())
        )
    }

    /// Reads the value of a cookie. Anything else than an identifier, a dot
    /// and 32 bytes of secret is no ticket.
    #[must_use]
    pub fn parse(cookie: &str) -> Option<Self> {
        let (session, secret) = cookie.split_once('.')?;
        let secret = URL_SAFE_NO_PAD.decode(secret).ok()?;
        (secret.len() == 32).then_some(())?;
        Some(Self {
            session: Uuid::parse_str(session).ok()?,
            secret: Secret::new(secret),
        })
    }
}

/// Opens a session for a person who just proved who they are.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`] or the storage failure.
pub async fn open_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    person: Uuid,
) -> Result<(Session, SessionTicket), Failure> {
    let mut secret = vec![0_u8; 32];
    app.random
        .fill(&mut secret)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let now = app.now();
    let session = Session {
        id: mint_id(app)?,
        person,
        secret_digest: app.digester.sha256(&secret).to_vec(),
        state: SessionState::Active,
        authenticated_at: now,
        expires_at: now + SESSION_LIFETIME,
    };
    work.insert_session(&session).await?;
    let ticket = SessionTicket {
        session: session.id,
        secret: Secret::new(secret),
    };
    Ok((session, ticket))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::SessionTicket;
    use crate::secret::Secret;

    #[test]
    fn a_ticket_is_read_back_from_the_cookie_it_wrote() {
        let ticket = SessionTicket {
            session: Uuid::from_u128(7),
            secret: Secret::new(vec![9; 32]),
        };

        let read = SessionTicket::parse(&ticket.write()).expect("a ticket");

        assert_eq!(read.session, ticket.session);
        assert_eq!(read.secret.expose(), ticket.secret.expose());
    }

    #[test]
    fn an_identifier_alone_or_a_secret_of_another_length_is_no_ticket() {
        let identifier = Uuid::from_u128(7).to_string();
        for cookie in [
            identifier.clone(),
            format!("{identifier}."),
            format!("{identifier}.c2hvcnQ"),
            "not-a-uuid.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            String::new(),
        ] {
            assert!(SessionTicket::parse(&cookie).is_none(), "{cookie:?}");
        }
    }
}
