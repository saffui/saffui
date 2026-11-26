use async_trait::async_trait;
use saffui_core::login::session::{
    AuthenticationMethod, ReadSession, Session, SessionKind, SessionState,
};
use saffui_core::login::store::{ServedClient, ServedClients, ServedRecord, SessionStore};
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::insert::Insert;
use crate::query::update::Update;
use crate::schema::sessions;
use crate::work::PgUnitOfWork;

/// Constant SQL: one statement reads the session, and writes the line only
/// while it is active and unexpired. Shared until the commit, it waits for
/// an ending in flight, then reads the session again as it committed: of an
/// answer and an ending, either the ending reads the line or the answer is
/// refused. The line keeps the expiry of the session it read. It answers
/// whether the session was live, and whether a line was written.
const RECORD_SERVED_CLIENT: &str = "
    WITH live AS (
        SELECT session_id, expires_at FROM sessions
        WHERE tenant_id = $1 AND realm_id = $2 AND session_id = $3
          AND state = $6 AND expires_at > $5
        FOR SHARE),
    written AS (
        INSERT INTO session_clients
            (tenant_id, realm_id, session_id, client_id, first_served_at, expires_at)
        SELECT $1, $2, session_id, $4, $5, expires_at FROM live
        ON CONFLICT DO NOTHING
        RETURNING 1)
    SELECT EXISTS (SELECT 1 FROM live), EXISTS (SELECT 1 FROM written)";

/// Constant SQL: the lines of the session, found by the prefix of their key,
/// each joined to its client: one gone or disabled is left out. One row
/// however many there are: their count, then the first `$4` in one order,
/// their identifiers and their addresses side by side.
const LIST_SERVED_CLIENTS: &str = "
    WITH served AS (
        SELECT client.client_id, client.frontchannel_logout_uri, line.first_served_at
        FROM session_clients AS line
        JOIN clients AS client
          ON client.tenant_id = line.tenant_id AND client.realm_id = line.realm_id
         AND client.client_id = line.client_id
        WHERE line.tenant_id = $1 AND line.realm_id = $2 AND line.session_id = $3
          AND client.enabled),
    named AS (
        SELECT client_id, frontchannel_logout_uri, first_served_at FROM served
        ORDER BY first_served_at, client_id
        LIMIT $4)
    SELECT (SELECT count(*) FROM served),
           ARRAY(SELECT client_id FROM named ORDER BY first_served_at, client_id),
           ARRAY(SELECT frontchannel_logout_uri FROM named ORDER BY first_served_at, client_id)";

#[async_trait]
impl SessionStore for PgUnitOfWork {
    async fn insert_session(&mut self, session: &Session) -> Result<(), StorageError> {
        let state = session.state.name();
        let kind = session.kind.name();
        let methods: Vec<&str> = session.methods.iter().map(|method| method.name()).collect();
        let insert = Insert::into(
            sessions::TABLE,
            vec![
                col(sessions::SESSION_ID, &session.id),
                col(sessions::PERSON_ID, &session.person),
                col(sessions::SECRET_DIGEST, &session.secret_digest),
                col(sessions::STATE, &state),
                col(sessions::KIND, &kind),
                col(sessions::METHODS, &methods),
                col(sessions::AUTHENTICATED_AT, &session.authenticated_at),
                col(sessions::EXPIRES_AT, &session.expires_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_session(&mut self, id: Uuid) -> Result<Option<ReadSession>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // One statement: whether the person holds a factor is asked at each
        // use of a session, and costs no trip of its own.
        let rows = self
            .read_raw(
                "SELECT s.person_id, s.secret_digest, s.state, s.authenticated_at, s.expires_at,
                        s.methods, s.kind,
                        EXISTS (SELECT 1 FROM totp_authenticators AS t
                                WHERE t.tenant_id = $1 AND t.realm_id = $2
                                  AND t.person_id = s.person_id AND t.confirmed_at IS NOT NULL)
                        OR EXISTS (SELECT 1 FROM security_keys AS k
                                   WHERE k.tenant_id = $1 AND k.realm_id = $2
                                     AND k.person_id = s.person_id)
                 FROM sessions AS s
                 WHERE s.tenant_id = $1 AND s.realm_id = $2 AND s.session_id = $3",
                &[&tenant, &realm, &id],
            )
            .await?;
        rows.first()
            .map(|row| {
                let state: String = row.get(2);
                let methods: Vec<String> = row.get(5);
                let kind: String = row.get(6);
                let session = Session {
                    id,
                    person: row.get(0),
                    secret_digest: row.get(1),
                    // The schema holds the same list: a name unknown here was not written by this binary.
                    state: SessionState::parse(&state).ok_or(StorageError::Failed)?,
                    kind: SessionKind::parse(&kind).ok_or(StorageError::Failed)?,
                    methods: methods
                        .iter()
                        .map(|name| AuthenticationMethod::parse(name).ok_or(StorageError::Failed))
                        .collect::<Result<_, _>>()?,
                    authenticated_at: row.get(3),
                    expires_at: row.get(4),
                };
                Ok(ReadSession {
                    session,
                    person_holds_factor: row.get(7),
                })
            })
            .transpose()
    }

    async fn end_session(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let (ended, active) = (SessionState::Ended.name(), SessionState::Active.name());
        // Of two endings at once, the second waits for the first, then finds
        // the session ended and matches no row.
        let update = Update::table(
            sessions::TABLE,
            vec![col(sessions::STATE, &ended)],
            Criteria::new()
                .where_equal(sessions::SESSION_ID, &id)
                .where_equal(sessions::STATE, &active),
        )
        .build()
        .map_err(|_| StorageError::Failed)?;
        Ok(self.execute(&update).await? == 1)
    }

    async fn end_sessions_proven_only_by(
        &mut self,
        person: Uuid,
        methods: &[AuthenticationMethod],
        kept: Option<Uuid>,
    ) -> Result<Vec<Uuid>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let (active, ended) = (SessionState::Active.name(), SessionState::Ended.name());
        let methods: Vec<&str> = methods.iter().map(|method| method.name()).collect();
        let rows = self
            .read_raw(
                "UPDATE sessions SET state = $5
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3
                   AND state = $4 AND methods = $6
                   AND session_id IS DISTINCT FROM $7
                 RETURNING session_id",
                &[&tenant, &realm, &person, &active, &ended, &methods, &kept],
            )
            .await?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    async fn record_served_client(
        &mut self,
        session: Uuid,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<ServedRecord, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let active = SessionState::Active.name();
        let rows = self
            .read_raw(
                RECORD_SERVED_CLIENT,
                &[&tenant, &realm, &session, &client_id, &now, &active],
            )
            .await?;
        let row = rows.first().ok_or(StorageError::Failed)?;
        Ok(match (row.get(0), row.get(1)) {
            (false, _) => ServedRecord::SessionEnded,
            (true, true) => ServedRecord::Written,
            (true, false) => ServedRecord::AlreadyWritten,
        })
    }

    async fn list_served_clients(
        &mut self,
        session: Uuid,
        most: u32,
    ) -> Result<ServedClients, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let limit = i64::from(most);
        let rows = self
            .read_raw(LIST_SERVED_CLIENTS, &[&tenant, &realm, &session, &limit])
            .await?;
        let row = rows.first().ok_or(StorageError::Failed)?;
        let (counted, identifiers, addresses): (i64, Vec<String>, Vec<Option<String>>) =
            (row.get(0), row.get(1), row.get(2));
        Ok(ServedClients {
            first: identifiers
                .into_iter()
                .zip(addresses)
                .map(|(client_id, frontchannel_logout_uri)| ServedClient {
                    client_id,
                    frontchannel_logout_uri,
                })
                .collect(),
            count: u64::try_from(counted).map_err(|_| StorageError::Failed)?,
        })
    }
}
