use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::registration::InitialAccessToken;
use super::{Client, ClientAuthMethod, ClientStanding, KeptProof};
use crate::authz::capability::Capability;
use crate::ports::storage::StorageError;

/// A window on a list: where it starts and how many rows it holds at most.
/// Built by [`ListWindow::bound`], which holds the ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListWindow {
    pub first: u32,
    pub max: u32,
}

impl ListWindow {
    pub const DEFAULT_MAX: u32 = 100;
    pub const MAX_CEILING: u32 = 500;
    pub const FIRST_CEILING: u32 = 100_000;

    /// Bounds what a caller asked for. A page larger than the ceiling is cut
    /// to it, and the second value says so. An offset past its ceiling has
    /// no answer: `None`.
    #[must_use]
    pub fn bound(first: Option<u32>, max: Option<u32>) -> Option<(Self, bool)> {
        let first = first.unwrap_or(0);
        if first > Self::FIRST_CEILING {
            return None;
        }
        let asked = max.unwrap_or(Self::DEFAULT_MAX);
        let window = Self {
            first,
            max: asked.min(Self::MAX_CEILING),
        };
        Some((window, asked > Self::MAX_CEILING))
    }
}

#[async_trait]
pub trait ClientStore {
    /// Fails with `Taken("client identifier")` when the realm has a client
    /// of that identifier already, and fails for a proof that does not fit
    /// the method of the client, as the table refuses it.
    async fn insert_client(
        &mut self,
        client: &Client,
        proof: &KeptProof,
    ) -> Result<(), StorageError>;

    /// A client, without what proves it.
    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError>;

    /// As `read_client`, by one statement, and the row stays taken until the
    /// commit: another writer of the client waits, then reads what was kept.
    async fn read_client_for_update(
        &mut self,
        client_id: &str,
    ) -> Result<Option<Client>, StorageError>;

    /// As `read_client`, and the row stays shared until the commit: a
    /// writer of the client waits, and one that writes it meanwhile is
    /// waited for, then read as it wrote it.
    async fn read_client_for_share(
        &mut self,
        client_id: &str,
    ) -> Result<Option<Client>, StorageError>;

    /// Whether a client is enabled and whether it registered itself, and
    /// nothing else of it.
    async fn read_client_standing(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientStanding>, StorageError>;

    /// A client and what proves it, read by one statement: to identify it,
    /// and for nothing else.
    async fn read_client_with_proof(
        &mut self,
        client_id: &str,
    ) -> Result<Option<(Client, KeptProof)>, StorageError>;

    /// The clients of the realm in the order of their identifiers, within the window.
    async fn list_clients(&mut self, window: ListWindow) -> Result<Vec<Client>, StorageError>;

    /// How many clients the realm has. Asked for, never computed by default.
    async fn count_clients(&mut self) -> Result<u64, StorageError>;

    /// Replaces what a client may do on the administration plane. Answers
    /// whether the realm has that client.
    async fn write_client_capabilities(
        &mut self,
        client_id: &str,
        capabilities: &[Capability],
    ) -> Result<bool, StorageError>;

    /// Replaces the secret of a client, in the one form its method keeps it
    /// in: a digest, or sealed. A form the method does not keep fails, as
    /// the table refuses it. Answers whether the realm has that client.
    async fn write_client_secret(
        &mut self,
        client_id: &str,
        secret_digest: Option<&[u8]>,
        sealed_secret: Option<&[u8]>,
    ) -> Result<bool, StorageError>;

    /// Changes how a client presents its secret, between the Basic scheme
    /// and the form, and nothing else: any other change fails, as the table
    /// refuses it. Answers whether the realm has that client.
    async fn write_client_auth_method(
        &mut self,
        client_id: &str,
        method: ClientAuthMethod,
    ) -> Result<bool, StorageError>;

    /// Rewrites what a client that registered itself says of itself, while
    /// its registration lasts: its name, scopes, addresses, the algorithms of
    /// its identity tokens and of its assertions, and its keys. Nothing else
    /// of the client is written, whether it is enabled least of all, and no
    /// other client. Answers whether it did.
    async fn write_client_metadata(
        &mut self,
        client: &Client,
        jwks: Option<&serde_json::Value>,
    ) -> Result<bool, StorageError>;

    /// Disables a client, by one statement that reads nothing first.
    /// Answers whether it was enabled.
    async fn disable_client(&mut self, client_id: &str) -> Result<bool, StorageError>;

    /// Keeps the identifier of an assertion of a client until `kept_until`.
    /// Answers whether it was the first time: of two uses of one assertion,
    /// exactly one is first.
    async fn record_client_assertion(
        &mut self,
        client_id: &str,
        token_id: &str,
        kept_until: OffsetDateTime,
    ) -> Result<bool, StorageError>;
}

/// What registration through the protocol keeps (RFC 7591 and 7592): the
/// initial access tokens of the realm, and the token that manages each
/// registered client, both by their digest.
#[async_trait]
pub trait RegistrationStore {
    async fn insert_initial_access_token(
        &mut self,
        token: &InitialAccessToken,
        token_digest: &[u8],
    ) -> Result<(), StorageError>;

    /// How many tokens of the realm have a use left and have not expired at
    /// `now`. They stay taken until the commit: while one lives, of two
    /// administrators who make one each, the second counts the token of the
    /// first.
    async fn count_live_initial_access_tokens(
        &mut self,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError>;

    /// The initial access tokens of the realm, newest first, within the
    /// window, without their digests.
    async fn list_initial_access_tokens(
        &mut self,
        window: ListWindow,
    ) -> Result<Vec<InitialAccessToken>, StorageError>;

    /// Spends one use of the token of that digest, if it has one left and
    /// has not expired at `now`, in one statement: of two uses of its last
    /// use, one spends it. Returns the identifier of the token it spent.
    async fn spend_initial_access_token(
        &mut self,
        token_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StorageError>;

    /// The token of that digest, if it has a use left and has not expired
    /// at `now`. Nothing is spent.
    async fn find_live_initial_access_token(
        &mut self,
        token_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StorageError>;

    /// Removes an initial access token. Answers whether there was one.
    async fn delete_initial_access_token(&mut self, token_id: Uuid) -> Result<bool, StorageError>;

    /// Keeps the digest of the token that manages a registered client.
    async fn insert_client_registration(
        &mut self,
        client_id: &str,
        token_digest: &[u8],
        registered_at: OffsetDateTime,
    ) -> Result<(), StorageError>;

    /// Whether `presented_digest` is the digest kept for the registration
    /// of the client. Nothing is spent.
    async fn matches_registration_token(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
    ) -> Result<bool, StorageError>;

    /// Replaces the token of a registration by the next, when the one
    /// presented is the one kept, in one statement: of two requests that
    /// present it, one replaces it. Answers whether it did.
    async fn rotate_registration_token(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
        next_digest: &[u8],
    ) -> Result<bool, StorageError>;

    /// Ends the registration of a client at `now` when the token presented
    /// is the one kept, and takes its token away, in one statement: the
    /// registration stays, ended. Answers whether it did.
    async fn end_client_registration(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// As [`Self::end_client_registration`], for an administrator, who
    /// presents no token. Answers whether a registration of the client
    /// lasted until then.
    async fn end_client_registration_as_administrator(
        &mut self,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError>;

    /// How many clients of the realm a registration made, and how many of
    /// them registered at or after `since`, in one read.
    async fn count_registrations(
        &mut self,
        since: OffsetDateTime,
    ) -> Result<RegistrationCounts, StorageError>;
}

/// The registrations of a realm, as its bounds count them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistrationCounts {
    /// Every client a registration made, those whose registration ended
    /// included, until retention removes them.
    pub registered: u64,
    /// Those that registered at or after the instant asked for.
    pub since: u64,
}

#[cfg(test)]
mod tests {
    use super::ListWindow;

    #[test]
    fn a_window_defaults_to_100_rows_and_is_cut_to_500_with_a_word_about_it() {
        assert_eq!(
            ListWindow::bound(None, None),
            Some((ListWindow { first: 0, max: 100 }, false))
        );
        assert_eq!(
            ListWindow::bound(Some(40), Some(500)),
            Some((
                ListWindow {
                    first: 40,
                    max: 500
                },
                false
            ))
        );
        assert_eq!(
            ListWindow::bound(None, Some(501)),
            Some((ListWindow { first: 0, max: 500 }, true))
        );
    }

    #[test]
    fn an_offset_past_100000_has_no_answer() {
        assert!(ListWindow::bound(Some(100_000), None).is_some());
        assert_eq!(ListWindow::bound(Some(100_001), None), None);
    }
}
