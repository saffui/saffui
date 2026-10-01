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

/// How often federated shadows are walked against their directory. Zero
/// means never, and the resting value is never: a sync dials out, and a
/// deployment should say so before this server does.
const FEDERATION_SYNC: &str = "FEDERATION_SYNC_SECONDS";

pub fn federation_sync_every() -> Result<Option<Duration>, ConfigError> {
    let seconds = crate::parse_or(FEDERATION_SYNC, 0)?;
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

/// How often the outbox is walked. On by default: an outbox nobody walks is
/// a promise nobody keeps, and a realm with no connectors costs one cheap
/// query per pass.
const OUTBOX: &str = "OUTBOX_SECONDS";

pub fn outbox_every() -> Result<Option<Duration>, ConfigError> {
    let seconds = crate::parse_or(OUTBOX, 15)?;
    Ok((seconds > 0).then(|| Duration::from_secs(seconds)))
}

/// How often the status lists credentials cite are looked at for any that is
/// due to be read again. On by default where the wallet verifier runs: a list
/// nobody reads refuses every credential citing it. Zero means never.
const STATUS_LISTS: &str = "STATUS_LISTS_SECONDS";

pub fn status_lists_every() -> Result<Option<Duration>, ConfigError> {
    let seconds = crate::parse_or(STATUS_LISTS, 60)?;
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

        // The sync knob answers to its documented name. The constant once
        // carried the prefix a second time, so the variable an operator set
        // was never the one this read.
        clear(&[FEDERATION_SYNC]);
        assert_eq!(federation_sync_every().unwrap(), None);
        set(FEDERATION_SYNC, "900");
        assert_eq!(
            federation_sync_every().unwrap(),
            Some(Duration::from_secs(900))
        );
        clear(&[FEDERATION_SYNC]);

        clear(&[STATUS_LISTS]);
        assert_eq!(status_lists_every().unwrap(), Some(Duration::from_secs(60)));
        set(STATUS_LISTS, "0");
        assert_eq!(status_lists_every().unwrap(), None);
        clear(&[STATUS_LISTS]);
    }
}
