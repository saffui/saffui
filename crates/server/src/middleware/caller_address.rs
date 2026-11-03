//! Where a request comes from, for what is counted per address.
//!
//! The peer of the connection is the only address nobody can make up. A
//! header says anything its sender likes, so `X-Forwarded-For` is read only
//! when the peer is a proxy the deployment named, and then from the right:
//! each proxy appends the address it saw, so the first entry from the right
//! that is not one of ours is the last address a machine of ours vouches
//! for. The leftmost entry is whatever the caller wrote.
//!
//! Every address is read in its canonical form: an IPv4 address that a
//! listener on both families writes as `::ffff:a.b.c.d` is that IPv4
//! address, counted as itself and not as one of a shared /64.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::HttpRequest;
use saffui_core::app::App as Product;
use saffui_core::settings::AddressRange;

const FORWARDED_FOR: &str = "x-forwarded-for";

/// Reads the address a request comes from. `None` when the connection has
/// no address, as under a test: nothing is then counted per address.
pub(crate) fn read_caller_address(product: &Product, request: &HttpRequest) -> Option<IpAddr> {
    let peer = request.peer_addr()?.ip();
    let forwarded: Vec<&str> = request
        .headers()
        .get_all(FORWARDED_FOR)
        .filter_map(|header| header.to_str().ok())
        .collect();
    let trusted = &product.settings.trusted_proxies;
    if !forwarded.is_empty() && !trusted.iter().any(|range| range.contains(peer)) {
        say_unbelieved_header(peer);
    }
    Some(choose_caller(peer, &forwarded, trusted))
}

/// When a report of an unbelieved header was last written, in seconds.
static LAST_REPORT: AtomicU64 = AtomicU64::new(0);
/// How often, at most, it is written.
const REPORT_EVERY_SECONDS: u64 = 60;

/// Says that a peer which is no proxy of ours sent `X-Forwarded-For`. A
/// deployment behind a proxy it forgot to name counts every caller as that
/// proxy: once a minute is enough to be read, and too little to fill a
/// journal whoever sends the header.
fn say_unbelieved_header(peer: IpAddr) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if is_report_due(&LAST_REPORT, now) {
        tracing::warn!(
            %peer,
            "X-Forwarded-For came from a peer that is no trusted proxy: it is not believed"
        );
    }
}

/// Tells whether a report is due at `now`, and takes the turn when it is:
/// of two requests at once, one writes it.
fn is_report_due(last: &AtomicU64, now: u64) -> bool {
    let before = last.load(Ordering::Relaxed);
    now.saturating_sub(before) >= REPORT_EVERY_SECONDS
        && last
            .compare_exchange(before, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

fn choose_caller(peer: IpAddr, forwarded: &[&str], trusted: &[AddressRange]) -> IpAddr {
    let is_trusted = |address: IpAddr| trusted.iter().any(|range| range.contains(address));
    let peer = peer.to_canonical();
    if !is_trusted(peer) {
        return peer;
    }
    let mut vouched_for = peer;
    let entries = forwarded
        .iter()
        .flat_map(|header| header.split(','))
        .map(str::trim);
    for entry in entries.rev() {
        // An entry that is not an address ends what can be believed.
        let Some(address) = read_forwarded_entry(entry) else {
            break;
        };
        vouched_for = address.to_canonical();
        if !is_trusted(vouched_for) {
            break;
        }
    }
    vouched_for
}

/// Reads one entry of `X-Forwarded-For`: an address, or an address and the
/// port some proxies write after it (`a.b.c.d:port`, `[v6]:port`, `[v6]`).
fn read_forwarded_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(address);
    }
    if let Ok(socket) = entry.parse::<std::net::SocketAddr>() {
        return Some(socket.ip());
    }
    entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inside| inside.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::AtomicU64;

    use saffui_core::settings::AddressRange;

    use super::{choose_caller, is_report_due};

    fn read(address: &str) -> IpAddr {
        address.parse().expect("an address")
    }

    fn range(written: &str) -> AddressRange {
        AddressRange::parse(written).expect("a range")
    }

    #[test]
    fn a_peer_that_is_no_proxy_of_ours_is_the_caller_whatever_it_claims() {
        let trusted = [range("10.0.0.1")];

        assert_eq!(
            choose_caller(read("203.0.113.7"), &["198.51.100.9"], &trusted),
            read("203.0.113.7")
        );
        assert_eq!(
            choose_caller(read("203.0.113.7"), &["198.51.100.9"], &[]),
            read("203.0.113.7")
        );
    }

    #[test]
    fn behind_our_proxies_the_caller_is_the_last_address_one_of_them_saw() {
        let trusted = [range("10.0.0.1"), range("10.0.0.2")];

        assert_eq!(
            choose_caller(read("10.0.0.1"), &["203.0.113.7"], &trusted),
            read("203.0.113.7")
        );
        assert_eq!(
            choose_caller(read("10.0.0.1"), &["203.0.113.7, 10.0.0.2"], &trusted),
            read("203.0.113.7"),
            "our own proxies are stepped over"
        );
        assert_eq!(
            choose_caller(read("10.0.0.1"), &["203.0.113.7", "10.0.0.2"], &trusted),
            read("203.0.113.7"),
            "a header sent twice reads as one list"
        );
    }

    #[test]
    fn what_the_caller_wrote_on_the_left_is_never_believed() {
        let trusted = [range("10.0.0.1")];

        assert_eq!(
            choose_caller(read("10.0.0.1"), &["198.51.100.9, 203.0.113.7"], &trusted),
            read("203.0.113.7"),
            "the entry our proxy appended wins over the one the caller sent"
        );
        assert_eq!(
            choose_caller(read("10.0.0.1"), &["203.0.113.7, not-an-address"], &trusted),
            read("10.0.0.1"),
            "an entry that is no address ends what can be believed"
        );
        assert_eq!(
            choose_caller(read("10.0.0.1"), &[], &trusted),
            read("10.0.0.1")
        );
    }

    #[test]
    fn an_ipv4_address_written_as_ipv6_is_read_as_itself() {
        let trusted = [range("10.0.0.1")];

        assert_eq!(
            choose_caller(read("::ffff:203.0.113.7"), &[], &trusted),
            read("203.0.113.7")
        );
        assert_eq!(
            choose_caller(read("::ffff:10.0.0.1"), &["::ffff:198.51.100.9"], &trusted),
            read("198.51.100.9"),
            "a proxy of ours is known in either form"
        );
    }

    #[test]
    fn an_entry_a_proxy_writes_with_its_port_is_read_as_its_address() {
        let trusted = [range("10.0.0.1")];

        for written in ["203.0.113.7:51234", "203.0.113.7"] {
            assert_eq!(
                choose_caller(read("10.0.0.1"), &[written], &trusted),
                read("203.0.113.7"),
                "{written}"
            );
        }
        for written in ["[2001:db8::7]:443", "[2001:db8::7]"] {
            assert_eq!(
                choose_caller(read("10.0.0.1"), &[written], &trusted),
                read("2001:db8::7"),
                "{written}"
            );
        }
    }

    #[test]
    fn a_proxy_of_ours_is_known_by_its_range() {
        let trusted = [range("10.0.0.0/8"), range("2001:db8:a::/48")];

        assert_eq!(
            choose_caller(read("10.4.5.6"), &["203.0.113.7, 10.9.9.9"], &trusted),
            read("203.0.113.7")
        );
        assert_eq!(
            choose_caller(read("2001:db8:a::1"), &["198.51.100.9"], &trusted),
            read("198.51.100.9")
        );
        assert_eq!(
            choose_caller(read("11.0.0.1"), &["198.51.100.9"], &trusted),
            read("11.0.0.1"),
            "a peer outside every range is the caller"
        );
    }

    #[test]
    fn an_unbelieved_header_is_said_once_a_minute_at_most() {
        let last = AtomicU64::new(0);

        assert!(is_report_due(&last, 1_000));
        assert!(!is_report_due(&last, 1_030));
        assert!(!is_report_due(&last, 1_059));
        assert!(is_report_due(&last, 1_060));
    }
}
