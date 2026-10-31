//! Identifiers. Time-ordered, so that rows written together sit together in
//! an index, and random enough that none can be guessed from another.

use uuid::{Builder, Uuid};

use crate::app::App;
use crate::error::{ErrorCode, Failure};

/// Mints an identifier from the clock and the random source of the application.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`] when the random source fails.
pub fn mint_id(app: &App) -> Result<Uuid, Failure> {
    let mut random = [0_u8; 10];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let milliseconds = app.clock.now().unix_timestamp_nanos() / 1_000_000;
    // A clock before 1970 would wrap: it mints from the epoch instead.
    let milliseconds = u64::try_from(milliseconds).unwrap_or(0);
    Ok(Builder::from_unix_timestamp_millis(milliseconds, &random).into_uuid())
}
