//! How often this node does the work no request asks for.

use std::time::Duration;

use crate::ConfigError;

const SWEEP: &str = "SWEEP_SECONDS";

/// Five minutes.
const DEFAULT: u64 = 300;

/// How often expired rows are swept. Zero turns the sweep off, rather than a
/// second flag an operator can leave on against a meaningless interval.
pub fn sweep_every() -> Result<Option<Duration>, ConfigError> {
    let seconds = crate::parse_or(SWEEP, DEFAULT)?;
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clear, env_guard, set};

    #[test]
    fn absent_means_the_default_and_zero_means_never() {
        let _guard = env_guard();

        clear(&[SWEEP]);
        assert_eq!(sweep_every().unwrap(), Some(Duration::from_secs(DEFAULT)));

        set(SWEEP, "60");
        assert_eq!(sweep_every().unwrap(), Some(Duration::from_secs(60)));

        set(SWEEP, "0");
        assert_eq!(sweep_every().unwrap(), None, "zero did not turn it off");

        // Set and unreadable is a refusal, not a silent fall back.
        set(SWEEP, "often");
        assert!(sweep_every().is_err());

        clear(&[SWEEP]);
    }
}
