//! The realm's answer to one address guessing.
//!
//! Counted per address, and per address with each name typed, on every door
//! that verifies a password, so a password tried once against many names from
//! one place fills a count the lockout per person never sees. A count per
//! address shuts out that address and nobody else, which is why it is on in a
//! stock realm while the lockout per person is not. A browser that proves it
//! signed in under the typed name before is counted in place of its address,
//! so the people behind one address are not turned away together.
//!
//! Every refusal counts, whether or not the answer was looked at, and whether
//! or not anybody holds the name: a count that moved only for names somebody
//! holds would say which names those are. The one refusal not counted is the
//! throttle's own, or an address that kept knocking would never be let back.

use std::net::{IpAddr, Ipv6Addr};

use chrono::{DateTime, Utc};
use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::HEXLOWER;
use models::entities::realm::{RealmModel, SourceThrottle};
use store::providers::protocol::source_failures::{self, Counted, MINUTE};
use store::tenancy::UnitOfWork;

use crate::login::device::Device;

/// The address's own count, as opposed to one of a name typed from it.
const ADDRESS_ALONE: &str = "";

/// How much of an address that is not one is kept as its key.
const UNREAD_ADDRESS_LIMIT: usize = 64;

/// What a device's count is kept under, before its identifier. Capitalised:
/// every address is counted in lowercase, so none is ever counted as a device.
const DEVICE: &str = "Device:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the failures from this address could not be weighed")]
pub struct Unweighed;

/// Where an attempt came from, and the name typed with it, as they are
/// counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knock {
    source: Option<String>,
    named: Option<String>,
    /// Whether `source` is a browser that proved this name before, rather
    /// than an address.
    on_device: bool,
}

impl Knock {
    /// An attempt from `address`, naming `typed`. Nothing is counted for an
    /// attempt nobody can say the address of, and only the address is for one
    /// that typed no name.
    pub fn new(
        provider: &dyn CryptoProvider,
        address: Option<&str>,
        typed: Option<&str>,
    ) -> Result<Knock, Unweighed> {
        let named = match typed.map(counted_name).filter(|kept| !kept.is_empty()) {
            None => None,
            Some(kept) => Some(
                HEXLOWER.encode(
                    &provider
                        .digest()
                        .hash(HashAlg::Sha256, kept.as_bytes())
                        .map_err(|_| Unweighed)?,
                ),
            ),
        };
        Ok(Knock {
            source: address.map(counted_source).filter(|kept| !kept.is_empty()),
            named,
            on_device: false,
        })
    }

    /// An attempt from `address` under a name an earlier round already
    /// counted, as `counted_name` handed it out.
    pub fn counted_as(address: Option<&str>, counted: &str) -> Knock {
        Knock {
            source: address.map(counted_source).filter(|kept| !kept.is_empty()),
            named: Some(counted.to_owned()).filter(|held| !held.is_empty()),
            on_device: false,
        }
    }

    /// The digest the typed name is counted under, when a name was typed.
    pub fn counted_name(&self) -> Option<&str> {
        self.named.as_deref()
    }

    /// The same attempt, counted against the device that proved this name
    /// rather than against the address it shares. A device is one browser for
    /// one name, so an attempt naming nobody stays on its address.
    pub fn on_device(self, device: &Device) -> Knock {
        if self.named.is_none() {
            return self;
        }
        Knock {
            source: Some(format!("{DEVICE}{}", device.id())),
            on_device: true,
            ..self
        }
    }

    /// Whether the attempt is counted against a device.
    pub fn is_on_device(&self) -> bool {
        self.on_device
    }

    fn keys(&self) -> Vec<&str> {
        std::iter::once(ADDRESS_ALONE)
            .chain(self.named.as_deref())
            .collect()
    }
}

/// When this knock may be answered again, or nothing when it may be now.
///
/// Asked before anything is verified or even looked up, so a turned away
/// attempt costs one read and no password hash.
pub async fn until(
    transaction: &UnitOfWork,
    realm: &RealmModel,
    knock: &Knock,
    now: DateTime<Utc>,
) -> Result<Option<i64>, Unweighed> {
    let policy = realm.source_throttle;
    let Some(source) = knock.source.as_deref().filter(|_| policy.throttled) else {
        return Ok(None);
    };
    let since = now.timestamp() - i64::from(policy.window_seconds) - MINUTE;
    let counted = source_failures::counted_since(transaction, source, &knock.keys(), since)
        .await
        .map_err(|_| Unweighed)?;
    Ok(released_at(&counted, knock.named.as_deref(), policy))
}

/// Count one refused attempt.
pub async fn count(
    transaction: &UnitOfWork,
    realm: &RealmModel,
    knock: &Knock,
    now: DateTime<Utc>,
) -> Result<(), Unweighed> {
    let Some(source) = knock
        .source
        .as_deref()
        .filter(|_| realm.source_throttle.throttled)
    else {
        return Ok(());
    };
    let at = now.timestamp();
    source_failures::record(
        transaction,
        source,
        &knock.keys(),
        at - at.rem_euclid(MINUTE),
    )
    .await
    .map_err(|_| Unweighed)
}

/// When the counts fall back under the realm's thresholds, or nothing when
/// they are under now. Oldest minutes leave the window first, so the address
/// is let back once enough of them have left it.
fn released_at(counted: &[Counted], named: Option<&str>, policy: SourceThrottle) -> Option<i64> {
    let window = i64::from(policy.window_seconds);
    let release = |key: &str, most: i32| {
        let most = i64::from(most);
        let under = || counted.iter().filter(move |held| held.named == key);
        let mut left: i64 = under().map(|held| i64::from(held.failures)).sum();
        if left < most {
            return None;
        }
        under().find_map(|held| {
            left -= i64::from(held.failures);
            (left < most).then_some(held.minute + MINUTE + window)
        })
    };
    let alone = release(ADDRESS_ALONE, policy.max_failures);
    let with_name = named.and_then(|key| release(key, policy.max_name_failures));
    alone.max(with_name)
}

/// One IPv6 network of 64 bits is one subscriber, and an IPv4 address carried
/// in IPv6 is that IPv4 address. Anything else is not an address and is kept
/// as it came, cut to a length: it still counts, under a key of its own.
fn counted_source(address: &str) -> String {
    let address = address.trim();
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(held)) => held.to_string(),
        Ok(IpAddr::V6(held)) => match held.to_ipv4_mapped() {
            Some(carried) => carried.to_string(),
            None => {
                let [a, b, c, d, ..] = held.segments();
                format!("{}/64", Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
            }
        },
        Err(_) => address
            .chars()
            .take(UNREAD_ADDRESS_LIMIT)
            .collect::<String>()
            .to_lowercase(),
    }
}

/// A name the way every spelling of it counts alike: case and spacing left
/// out. Two names counted as one only makes the count stricter.
fn counted_name(typed: &str) -> String {
    typed
        .chars()
        .filter(|held| !held.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minute(named: &str, minute: i64, failures: i32) -> Counted {
        Counted {
            named: named.to_owned(),
            minute,
            failures,
        }
    }

    const POLICY: SourceThrottle = SourceThrottle {
        throttled: true,
        max_failures: 5,
        max_name_failures: 3,
        window_seconds: 900,
    };

    #[test]
    fn an_address_under_its_thresholds_is_answered() {
        let counted = [minute("", 0, 4), minute("n", 0, 2)];
        assert_eq!(released_at(&counted, Some("n"), POLICY), None);
    }

    /// Let back once enough of the oldest minutes have left the window, not
    /// once all of them have.
    #[test]
    fn the_oldest_minutes_leave_the_window_first() {
        let counted = [minute("", 0, 3), minute("", 60, 3), minute("", 120, 3)];
        assert_eq!(
            released_at(&counted, None, POLICY),
            Some(60 + MINUTE + 900),
            "nine failures over a threshold of five wait for two minutes to leave, not three"
        );
    }

    #[test]
    fn a_name_guessed_from_one_address_is_held_before_the_address_is() {
        let counted = [minute("", 0, 3), minute("n", 0, 3)];
        assert_eq!(released_at(&counted, Some("n"), POLICY), Some(MINUTE + 900));
        assert_eq!(
            released_at(&counted, Some("other"), POLICY),
            None,
            "another name from the same address was held with it"
        );
    }

    #[test]
    fn two_counts_over_their_thresholds_hold_until_the_later_release() {
        let counted = [minute("", 0, 5), minute("n", 0, 1), minute("n", 300, 3)];
        assert_eq!(
            released_at(&counted, Some("n"), POLICY),
            Some(300 + MINUTE + 900)
        );
    }

    #[test]
    fn a_network_of_64_bits_is_one_address() {
        assert_eq!(
            counted_source("2001:db8:1:2:aaaa::1"),
            counted_source("2001:db8:1:2:ffff:ffff:ffff:ffff")
        );
        assert_ne!(
            counted_source("2001:db8:1:2::1"),
            counted_source("2001:db8:1:3::1")
        );
        assert_eq!(counted_source("2001:db8:1:2::1"), "2001:db8:1:2::/64");
        assert_eq!(counted_source("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(counted_source(" 203.0.113.7 "), "203.0.113.7");
        assert_eq!(counted_source(&"X".repeat(100)).len(), UNREAD_ADDRESS_LIMIT);
    }

    /// Whatever an address claims to be, it is counted in lowercase, and so
    /// never under a device's key.
    #[test]
    fn no_address_is_counted_as_a_device() {
        for claimed in ["Device:00ff", "DEVICE:00FF", " Device:00ff", "device:00ff"] {
            assert!(!counted_source(claimed).starts_with(DEVICE), "{claimed}");
        }
    }

    #[test]
    fn a_device_stands_in_for_the_address_only_under_a_name() {
        let device = Device {
            id: "00ff".to_owned(),
        };
        let named = Knock::counted_as(Some("203.0.113.7"), "n").on_device(&device);
        assert!(named.is_on_device());
        assert_eq!(named.source.as_deref(), Some("Device:00ff"));
        assert_eq!(named.counted_name(), Some("n"));

        let nameless = Knock::counted_as(Some("203.0.113.7"), "").on_device(&device);
        assert!(!nameless.is_on_device());
        assert_eq!(nameless.source.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn every_spelling_of_a_name_counts_alike() {
        assert_eq!(counted_name(" Ada.Lovelace "), "ada.lovelace");
        assert_eq!(counted_name("+228 90 00 00 00"), "+22890000000");
        assert_eq!(counted_name("ÉLODIE"), "élodie");
    }
}
