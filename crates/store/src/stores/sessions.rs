use async_trait::async_trait;
use saffui_core::login::session::{AuthenticationMethod, Session, SessionState};
use saffui_core::login::store::SessionStore;
use saffui_core::ports::storage::StorageError;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::select::Select;
use crate::query::update::Update;
use crate::schema::sessions;
use crate::work::PgUnitOfWork;

const SESSION: &[Column] = &[
    sessions::PERSON_ID,
    sessions::SECRET_DIGEST,
    sessions::STATE,
    sessions::AUTHENTICATED_AT,
    sessions::EXPIRES_AT,
    sessions::METHODS,
];

#[async_trait]
impl SessionStore for PgUnitOfWork {
    async fn insert_session(&mut self, session: &Session) -> Result<(), StorageError> {
        let state = session.state.name();
        let methods: Vec<&str> = session.methods.iter().map(|method| method.name()).collect();
        let insert = Insert::into(
            sessions::TABLE,
            vec![
                col(sessions::SESSION_ID, &session.id),
                col(sessions::PERSON_ID, &session.person),
                col(sessions::SECRET_DIGEST, &session.secret_digest),
                col(sessions::STATE, &state),
                col(sessions::METHODS, &methods),
                col(sessions::AUTHENTICATED_AT, &session.authenticated_at),
                col(sessions::EXPIRES_AT, &session.expires_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_session(&mut self, id: Uuid) -> Result<Option<Session>, StorageError> {
        let select = Select::from(sessions::TABLE, SESSION)
            .filter(Criteria::new().where_equal(sessions::SESSION_ID, &id))
            .build();
        self.read_one(&select)
            .await?
            .map(|row| {
                let state: String = row.get(2);
                let methods: Vec<String> = row.get(5);
                Ok(Session {
                    id,
                    person: row.get(0),
                    secret_digest: row.get(1),
                    // The schema holds the same list: a name unknown here was not written by this binary.
                    state: SessionState::parse(&state).ok_or(StorageError::Failed)?,
                    methods: methods
                        .iter()
                        .map(|name| AuthenticationMethod::parse(name).ok_or(StorageError::Failed))
                        .collect::<Result<_, _>>()?,
                    authenticated_at: row.get(3),
                    expires_at: row.get(4),
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
}
