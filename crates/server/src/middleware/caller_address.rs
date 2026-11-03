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

use actix_web::HttpRequest;
use saffui_core::app::App as Product;

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
    Some(choose_caller(
        peer,
        &forwarded,
        &product.settings.trusted_proxies,
    ))
}

fn choose_caller(peer: IpAddr, forwarded: &[&str], trusted: &[IpAddr]) -> IpAddr {
    let is_trusted = |address: IpAddr| trusted.iter().any(|known| known.to_canonical() == address);
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

    use super::choose_caller;

    fn read(address: &str) -> IpAddr {
        address.parse().expect("an address")
    }

    #[test]
    fn a_peer_that_is_no_proxy_of_ours_is_the_caller_whatever_it_claims() {
        let trusted = [read("10.0.0.1")];

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
        let trusted = [read("10.0.0.1"), read("10.0.0.2")];

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
        let trusted = [read("10.0.0.1")];

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
        let trusted = [read("10.0.0.1")];

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
        let trusted = [read("10.0.0.1")];

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
}
