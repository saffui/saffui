use async_trait::async_trait;

use super::Client;
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
    /// of that identifier already.
    async fn insert_client(&mut self, client: &Client) -> Result<(), StorageError>;

    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError>;

    /// The clients of the realm in the order of their identifiers, within the window.
    async fn list_clients(&mut self, window: ListWindow) -> Result<Vec<Client>, StorageError>;

    /// How many clients the realm has. Asked for, never computed by default.
    async fn count_clients(&mut self) -> Result<u64, StorageError>;
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
