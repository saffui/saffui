use async_trait::async_trait;
use time::OffsetDateTime;

use super::{Client, ClientAuthMethod, KeptProof};
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
