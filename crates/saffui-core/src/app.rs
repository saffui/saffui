use std::sync::Arc;

use crate::ports::storage::Storage;

/// Everything a use case can reach. the binary fills it once.
#[derive(Clone)]
pub struct App {
    pub storage: Arc<dyn Storage>,
}
