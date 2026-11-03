//! Sessions. A session is known by an identifier, which appears in tokens,
//! and proven by a secret, which appears only in the cookie of the browser
//! that signed in. The identifier alone opens nothing.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use serde_json::json;

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::Person;
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

/// What proved who a person is, named as a token names it (RFC 8176 and
/// the IANA registry of these names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticationMethod {
    Password,
    OneTimeCode,
    /// Named `pop`, the holding of a key: no attestation is asked, so nothing
    /// says the key is hardware (`hwk`) rather than synced from an account.
    SecurityKey,
}

impl AuthenticationMethod {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::OneTimeCode => "otp",
            Self::SecurityKey => "pop",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Password, Self::OneTimeCode, Self::SecurityKey]
            .into_iter()
            .find(|method| method.name() == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub person: Uuid,
    pub secret_digest: Vec<u8>,
    pub state: SessionState,
    /// What the person proved themselves with, in the order they did.
    pub methods: Vec<AuthenticationMethod>,
    /// When the person proved who they are. Never moved by later requests.
    pub authenticated_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A session as it is read, with what its person holds at that instant:
/// what tells whether a session of the password alone still answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadSession {
    pub session: Session,
    /// A confirmed authenticator application, or a security key. Read with
    /// the session, in the same statement.
    pub person_holds_factor: bool,
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
    methods: &[AuthenticationMethod],
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
        methods: methods.to_vec(),
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

/// Reads the live session a ticket proves, if there is one.
async fn read_proven_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    ticket: &SessionTicket,
) -> Result<Option<ReadSession>, Failure> {
    let read = work.read_session(ticket.session).await?;
    let presented = app.digester.sha256(ticket.secret.expose());
    // Compared even when there is no session, against a digest nothing matches.
    let expected = read.as_ref().map_or(&[0_u8; 32][..], |known| {
        known.session.secret_digest.as_slice()
    });
    let proven = app.digester.equal_in_constant_time(&presented, expected);
    Ok(read.filter(|known| {
        proven
            && known.session.state == SessionState::Active
            && known.session.expires_at > app.now()
    }))
}

/// Finds the live session a ticket proves, if there is one.
///
/// # Errors
///
/// Returns the storage failure. A ticket that proves nothing is `Ok(None)`.
pub async fn find_live_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    ticket: &SessionTicket,
) -> Result<Option<Session>, Failure> {
    Ok(read_proven_session(app, work, ticket)
        .await?
        .map(|read| read.session))
}

/// Whether a session was opened with a second factor.
pub(crate) fn proves_second_factor(session: &Session) -> bool {
    session
        .methods
        .iter()
        .any(|method| *method != AuthenticationMethod::Password)
}

/// Whether a session still answers for its person. One the password alone
/// opened stops answering once the person holds a second factor, whenever
/// it was opened and whoever kept it: the password alone would not open it
/// any more.
pub(crate) fn answers_for_its_person(read: &ReadSession) -> bool {
    proves_second_factor(&read.session) || !read.person_holds_factor
}

/// Finds the live session a ticket proves, when it still answers for its
/// person: what a client may be given a code from.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn find_answering_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    ticket: &SessionTicket,
) -> Result<Option<Session>, Failure> {
    Ok(read_proven_session(app, work, ticket)
        .await?
        .filter(answers_for_its_person)
        .map(|read| read.session))
}

/// Reads the session a code names and its person, when both still stand:
/// the session active, not expired and answering for its person, the person
/// enabled. A code whose session ended gives nothing.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn read_live_subject(
    app: &App,
    work: &mut dyn UnitOfWork,
    session: Uuid,
) -> Result<Option<(Session, Person)>, Failure> {
    let now = app.now();
    let Some(read) = work.read_session(session).await?.filter(|known| {
        known.session.state == SessionState::Active
            && known.session.expires_at > now
            && answers_for_its_person(known)
    }) else {
        return Ok(None);
    };
    let person = work
        .read_person(read.session.person)
        .await?
        .filter(|person| person.enabled);
    Ok(person.map(|person| (read.session, person)))
}

/// Ends a session, and with it every refresh token it gave. A session
/// another request ended meanwhile is left to it: it was said ended once.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn close_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    session: &Session,
) -> Result<(), Failure> {
    if !work.end_session(session.id).await? {
        return Ok(());
    }
    let revoked = work
        .revoke_refresh_tokens_of_session(session.id, app.now())
        .await?;
    let ended = json!({
        "person_id": session.person.to_string(),
        "refresh_tokens_revoked": revoked,
        "session_id": session.id.to_string(),
    });
    record_event(app, work, EventKind::SessionEnded, ended).await
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
