use std::net::IpAddr;

use crate::ConfigError;

const HOPS: &str = "PROXY_HOPS";
const PEERS: &str = "PROXY_PEERS";
const HEADER: &str = "PROXY_HEADER";
const CERTIFICATE: &str = "PROXY_CLIENT_CERTIFICATE_HEADER";
const SCHEME: &str = "PROXY_SCHEME_HEADER";

/// Which header the proxies in front write.
///
/// One, never both. A server that reads whichever is present lets a caller
/// choose: it sends the one the proxies do not write, that one is believed,
/// and the address the proxies recorded is never looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    XForwardedFor,
    /// RFC 7239, whose `for=` elements this reads and whose other parameters
    /// it does not.
    Forwarded,
}

impl ProxyHeader {
    pub fn name(self) -> &'static str {
        match self {
            ProxyHeader::XForwardedFor => "x-forwarded-for",
            ProxyHeader::Forwarded => "forwarded",
        }
    }
}

/// One address the proxies dial from, or a block of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    network: IpAddr,
    prefix: u8,
}

impl Peer {
    /// `10.0.0.7`, `10.0.0.0/8`, `::1`, `fd00::/8`. A bare address is the
    /// whole of it, which is a prefix as wide as the address.
    pub fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = match value.trim().split_once('/') {
            Some((address, bits)) => (address, Some(bits.parse::<u8>().ok()?)),
            None => (value.trim(), None),
        };
        let network: IpAddr = address.parse().ok()?;
        let whole = if network.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(whole);
        (prefix <= whole).then_some(Peer { network, prefix })
    }

    /// Whether this entry covers that address. Two addresses of different
    /// families never match: `::ffff:10.0.0.1` is not `10.0.0.1` here, and
    /// treating them as one is how a v6 caller is read as a v4 peer.
    pub fn holds(&self, address: IpAddr) -> bool {
        let (held, asked) = match (self.network, address) {
            (IpAddr::V4(held), IpAddr::V4(asked)) => {
                (held.octets().to_vec(), asked.octets().to_vec())
            }
            (IpAddr::V6(held), IpAddr::V6(asked)) => {
                (held.octets().to_vec(), asked.octets().to_vec())
            }
            _ => return false,
        };
        let (whole, rest) = (usize::from(self.prefix) / 8, u32::from(self.prefix) % 8);
        if held[..whole] != asked[..whole] {
            return false;
        }
        if rest == 0 {
            return true;
        }
        // The last byte is compared only down to the bit the prefix stops at.
        let mask = 0xFFu8 << (8 - rest);
        held[whole] & mask == asked[whole] & mask
    }
}

/// What stands between a caller and this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxying {
    hops: usize,
    header: ProxyHeader,
    /// Which header the terminating proxy writes the client's certificate
    /// into. Absent reads none, which is what a deployment that terminates its
    /// own TLS, or does no mutual TLS, gets.
    certificate: Option<String>,
    /// Which header the terminating proxy writes the scheme the client spoke
    /// into, `https` or `http`. Absent reads none. This server never terminates
    /// TLS on its HTTP listener, so a request's scheme is a fact only the
    /// proxy in front can state, and only a named one is believed.
    scheme: Option<String>,
    /// Where the proxies dial from. Empty believes the header from whoever
    /// dialled, which is what a deployment that names none of them gets.
    peers: Vec<Peer>,
}

impl Proxying {
    /// Zero hops, the default, means the address is the peer that dialled the
    /// socket and no header is read at all. A header is a thing the client
    /// writes, and reading one without knowing how many proxies rewrote it is
    /// recording whatever the client wanted recorded.
    pub fn from_env() -> Result<Self, ConfigError> {
        let header = match crate::optional(HEADER).as_deref() {
            None | Some("x-forwarded-for") => ProxyHeader::XForwardedFor,
            Some("forwarded") => ProxyHeader::Forwarded,
            Some(_) => {
                return Err(ConfigError::Invalid {
                    key: format!("{}{HEADER}", crate::PREFIX),
                    expected: "x-forwarded-for or forwarded".to_owned(),
                });
            }
        };
        // Comma separated, and a value that is not an address is refused
        // rather than dropped: a typo that silently empties the list turns the
        // check off on the day it was meant to start.
        let mut peers = Vec::new();
        for named in crate::optional(PEERS).unwrap_or_default().split(',') {
            let named = named.trim();
            if named.is_empty() {
                continue;
            }
            peers.push(Peer::parse(named).ok_or_else(|| ConfigError::Invalid {
                key: format!("{}{PEERS}", crate::PREFIX),
                expected: "comma separated addresses or CIDR blocks".to_owned(),
            })?);
        }
        Ok(Proxying {
            hops: crate::parse_or(HOPS, 0)?,
            header,
            certificate: crate::optional(CERTIFICATE)
                .map(|named| named.trim().to_ascii_lowercase())
                .filter(|named| !named.is_empty()),
            scheme: crate::optional(SCHEME)
                .map(|named| named.trim().to_ascii_lowercase())
                .filter(|named| !named.is_empty()),
            peers,
        })
    }

    pub fn none() -> Self {
        Proxying::behind(0, ProxyHeader::XForwardedFor)
    }

    /// Built from values from anywhere, for a deployment described in something
    /// other than the environment.
    pub fn behind(hops: usize, header: ProxyHeader) -> Self {
        Proxying {
            hops,
            header,
            certificate: None,
            scheme: None,
            peers: Vec::new(),
        }
    }

    /// The same, trusting the header only from these addresses.
    pub fn behind_peers(hops: usize, header: ProxyHeader, peers: Vec<Peer>) -> Self {
        Proxying {
            hops,
            header,
            certificate: None,
            scheme: None,
            peers,
        }
    }

    /// The same, reading a client's certificate from a named header.
    pub fn behind_terminating_peers(
        header: ProxyHeader,
        certificate: &str,
        peers: Vec<Peer>,
    ) -> Self {
        Proxying {
            hops: 1,
            header,
            certificate: Some(certificate.to_ascii_lowercase()),
            scheme: None,
            peers,
        }
    }

    /// The same deployment, with the scheme read from this header.
    ///
    /// For the benches and for callers that assemble a `Proxying` in code; the
    /// environment door is `from_env`, which reads the same fact from
    /// `SAFFUI_PROXY_SCHEME_HEADER`.
    pub fn saying_the_scheme_in(mut self, header: &str) -> Self {
        self.scheme = Some(header.to_ascii_lowercase());
        self
    }

    /// The client's certificate, as the proxy in front wrote it down.
    ///
    /// Read only from a peer this deployment named, and named peers are
    /// required: unlike a forwarded address, whose fallback is the peer that
    /// dialled and is therefore harmless, a certificate believed from anybody
    /// is a certificate anybody may claim. A deployment that named no peers
    /// gets no certificate rather than everyone's.
    pub fn client_certificate<'a>(
        &self,
        peer: Option<&str>,
        carried: Option<&'a str>,
    ) -> Option<&'a str> {
        self.certificate.as_ref()?;
        // Named peers and nothing else. A list with nothing in it holds no
        // address, so a deployment that named none reads no certificate: the
        // opposite of what an empty list means for a forwarded address, whose
        // fallback is the peer that dialled and is therefore harmless.
        let dialled = peer
            .and_then(|named| named.parse::<IpAddr>().ok())
            .is_some_and(|address| self.peers.iter().any(|held| held.holds(address)));
        dialled.then_some(carried).flatten()
    }

    /// Which header carries it, for the transport to look up.
    pub fn certificate_header(&self) -> Option<&str> {
        self.certificate.as_deref()
    }

    /// The scheme the client actually spoke, as the proxy in front wrote it
    /// down.
    ///
    /// Read only from a peer this deployment named, under the rule
    /// [`client_certificate`](Self::client_certificate) states: a scheme
    /// believed from anybody is a scheme anybody may claim, and `https` is
    /// exactly the claim an attacker on the plain port would make. A
    /// deployment that named no peers reads no scheme rather than everyone's.
    pub fn forwarded_scheme<'a>(
        &self,
        peer: Option<&str>,
        carried: Option<&'a str>,
    ) -> Option<&'a str> {
        self.scheme.as_ref()?;
        let dialled = peer
            .and_then(|named| named.parse::<IpAddr>().ok())
            .is_some_and(|address| self.peers.iter().any(|held| held.holds(address)));
        dialled.then_some(carried).flatten()
    }

    /// Which header carries the scheme, for whoever holds the request.
    pub fn scheme_header(&self) -> Option<&str> {
        self.scheme.as_deref()
    }

    /// Whether this deployment has any trusted way to learn a request's
    /// scheme: a named header and at least one named peer to believe it from.
    ///
    /// Read where a realm asks for `ssl_enforcement`, so the ask can be
    /// refused when nothing could ever check it. A setting accepted there
    /// would be written, shown, and never once consulted, which is the exact
    /// shape of lie this codebase keeps finding in itself.
    pub fn can_learn_the_scheme(&self) -> bool {
        self.scheme.is_some() && !self.peers.is_empty()
    }

    /// The header to read, or nothing when no proxy stands in front and none
    /// should be read.
    pub fn header(&self) -> Option<ProxyHeader> {
        (self.hops > 0).then_some(self.header)
    }

    /// The address this deployment believes the caller has, given the peer that
    /// dialled and what the header carried.
    ///
    /// Each proxy appends the peer it saw, so a request that crossed `hops` of
    /// them arrives with the caller at `hops` places from the right, whatever
    /// the client put in front of it. Counting from the right is the whole
    /// point: the left-most entry is the one the client chose, and a server
    /// that reads it records an address anybody can name.
    ///
    /// A header shorter than the count came through fewer proxies than the
    /// deployment says it has, so it was not written by them. The peer answers
    /// instead, which is the one address nobody could have claimed.
    pub fn caller<'a>(&self, peer: Option<&'a str>, carried: Option<&'a str>) -> Option<&'a str> {
        if self.hops == 0 || !self.dialled_by_a_proxy(peer) {
            return peer;
        }
        let seen: Vec<&str> = carried
            .unwrap_or_default()
            .split(',')
            .filter_map(|element| self.address_of(element))
            .collect();
        seen.len()
            .checked_sub(self.hops)
            .and_then(|at| seen.get(at).copied())
            .or(peer)
    }

    /// Whether whoever dialled the socket is one of the proxies.
    ///
    /// The hop count says how many rewrote the header, and that is only true
    /// of a request that came through them. Reached directly, a caller writes
    /// the whole header itself and the count reads its last entry as the proxy's
    /// work. Naming the proxies is what tells the two apart.
    ///
    /// An empty list believes whoever dialled, which is what a deployment that
    /// names none of them gets and is the weaker of the two.
    fn dialled_by_a_proxy(&self, peer: Option<&str>) -> bool {
        if self.peers.is_empty() {
            return true;
        }
        peer.and_then(|named| named.parse::<IpAddr>().ok())
            .is_some_and(|address| self.peers.iter().any(|held| held.holds(address)))
    }

    /// One element of the header, as the address it names.
    fn address_of<'a>(&self, element: &'a str) -> Option<&'a str> {
        let named = match self.header {
            ProxyHeader::XForwardedFor => element.trim(),
            // §4: `for=` among semicolon separated parameters, the value
            // optionally quoted. The rest of them say nothing about who called.
            ProxyHeader::Forwarded => element
                .split(';')
                .map(str::trim)
                .find_map(|parameter| {
                    let (named, value) = parameter.split_once('=')?;
                    named.eq_ignore_ascii_case("for").then_some(value)
                })?
                .trim()
                .trim_matches('"'),
        };
        // §6: a port may follow, and an IPv6 is bracketed so the colons in it
        // are not read as one. `unknown` and the obfuscated forms name nobody.
        let bare = match named.strip_prefix('[') {
            Some(inside) => inside.split(']').next().unwrap_or_default(),
            None if named.matches(':').count() == 1 => named.split(':').next().unwrap_or_default(),
            None => named,
        };
        (!bare.is_empty() && bare != "unknown" && !bare.starts_with('_')).then_some(bare)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: Option<&str> = Some("10.0.0.9");

    fn peers(named: &[&str]) -> Vec<Peer> {
        named
            .iter()
            .map(|held| Peer::parse(held).unwrap())
            .collect()
    }

    #[test]
    fn an_entry_covers_an_address_or_a_block_of_them() {
        let one = Peer::parse("10.0.0.7").unwrap();
        assert!(one.holds("10.0.0.7".parse().unwrap()));
        assert!(!one.holds("10.0.0.8".parse().unwrap()));

        let block = Peer::parse("10.0.0.0/8").unwrap();
        assert!(block.holds("10.255.255.255".parse().unwrap()));
        assert!(!block.holds("11.0.0.1".parse().unwrap()));

        // A prefix that stops mid-byte compares only down to that bit.
        let odd = Peer::parse("192.168.4.0/22").unwrap();
        assert!(odd.holds("192.168.7.255".parse().unwrap()));
        assert!(!odd.holds("192.168.8.0".parse().unwrap()));

        let six = Peer::parse("fd00::/8").unwrap();
        assert!(six.holds("fd00::1".parse().unwrap()));
        assert!(!six.holds("fe00::1".parse().unwrap()));

        // The two families never match each other.
        assert!(!block.holds("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!six.holds("10.0.0.1".parse().unwrap()));

        assert_eq!(Peer::parse("not-an-address"), None);
        assert_eq!(Peer::parse("10.0.0.0/33"), None);
        assert_eq!(Peer::parse("fd00::/129"), None);
    }

    #[test]
    fn a_header_from_somebody_who_is_not_a_proxy_is_not_read() {
        let named = Proxying::behind_peers(
            1,
            ProxyHeader::XForwardedFor,
            peers(&["10.0.0.0/8", "fd00::/8"]),
        );
        // Through the proxy, the header is the proxy's work.
        assert_eq!(
            named.caller(Some("10.0.0.9"), Some("203.0.113.7")),
            Some("203.0.113.7")
        );
        assert_eq!(
            named.caller(Some("fd00::9"), Some("203.0.113.7")),
            Some("203.0.113.7")
        );
        // Reached directly, whatever it carries is its own claim.
        assert_eq!(
            named.caller(Some("198.51.100.4"), Some("203.0.113.7")),
            Some("198.51.100.4"),
            "a claimed address was believed from a peer that is not a proxy"
        );
        // And a peer that is not an address at all is not one of them.
        assert_eq!(
            named.caller(Some("not-an-address"), Some("203.0.113.7")),
            Some("not-an-address")
        );
        assert_eq!(named.caller(None, Some("203.0.113.7")), None);
    }

    #[test]
    fn naming_no_proxy_believes_whoever_dialled() {
        let anybody = Proxying::behind(1, ProxyHeader::XForwardedFor);
        assert_eq!(
            anybody.caller(Some("198.51.100.4"), Some("203.0.113.7")),
            Some("203.0.113.7"),
            "the weaker behaviour changed"
        );
    }

    #[test]
    fn no_proxy_reads_no_header() {
        let direct = Proxying::none();
        assert_eq!(
            direct.caller(PEER, Some("203.0.113.7")),
            PEER,
            "a header was read by a deployment that has no proxy"
        );
        assert_eq!(direct.header(), None);
    }

    #[test]
    fn one_proxy_reads_the_entry_it_wrote() {
        let one = Proxying::behind(1, ProxyHeader::XForwardedFor);
        assert_eq!(one.caller(PEER, Some("203.0.113.7")), Some("203.0.113.7"));
        // The client sent its own header and the proxy appended to it. What the
        // proxy wrote is last, and what the client claimed is ignored.
        assert_eq!(
            one.caller(PEER, Some("198.51.100.1, 203.0.113.7")),
            Some("203.0.113.7"),
            "a claimed address was believed"
        );
    }

    #[test]
    fn two_proxies_read_past_the_inner_one() {
        let two = Proxying::behind(2, ProxyHeader::XForwardedFor);
        assert_eq!(
            two.caller(PEER, Some("203.0.113.7, 192.0.2.4")),
            Some("203.0.113.7")
        );
        assert_eq!(
            two.caller(PEER, Some("198.51.100.1, 203.0.113.7, 192.0.2.4")),
            Some("203.0.113.7"),
            "a claimed address was believed"
        );
    }

    #[test]
    fn a_header_shorter_than_the_count_is_not_believed() {
        let two = Proxying::behind(2, ProxyHeader::XForwardedFor);
        assert_eq!(two.caller(PEER, Some("203.0.113.7")), PEER);
        assert_eq!(two.caller(PEER, None), PEER);
        assert_eq!(two.caller(PEER, Some("   ,  ")), PEER);
    }

    #[test]
    fn a_forwarded_element_is_read_by_its_for_parameter() {
        let one = Proxying::behind(1, ProxyHeader::Forwarded);
        assert_eq!(
            one.caller(PEER, Some("for=203.0.113.7;proto=https;by=192.0.2.4")),
            Some("203.0.113.7")
        );
        assert_eq!(
            one.caller(PEER, Some(r#"proto=https;For="203.0.113.7:4711""#)),
            Some("203.0.113.7"),
            "a port or a quote or a capital was not stripped"
        );
        assert_eq!(
            one.caller(PEER, Some(r#"for="[2001:db8::1]:8080""#)),
            Some("2001:db8::1")
        );
        assert_eq!(
            one.caller(PEER, Some("for=198.51.100.1, for=203.0.113.7;proto=https")),
            Some("203.0.113.7"),
            "a claimed address was believed"
        );
    }

    #[test]
    fn a_forwarded_element_naming_nobody_is_not_an_address() {
        let one = Proxying::behind(1, ProxyHeader::Forwarded);
        // §6.3: an obfuscated identifier, and §5.2's `unknown`. Both are
        // elements that say a hop happened and refuse to say from where, so
        // neither is the caller and neither is counted as a hop's answer.
        assert_eq!(one.caller(PEER, Some("for=unknown")), PEER);
        assert_eq!(one.caller(PEER, Some("for=_hidden")), PEER);
        assert_eq!(one.caller(PEER, Some("proto=https")), PEER);
    }

    #[test]
    fn the_two_headers_are_never_both_read() {
        let carried = Some("203.0.113.7");
        assert_eq!(
            Proxying::behind(1, ProxyHeader::Forwarded).caller(PEER, carried),
            PEER,
            "an x-forwarded-for value was read as a Forwarded element"
        );
        assert_eq!(
            Proxying::behind(1, ProxyHeader::XForwardedFor).caller(PEER, Some("for=203.0.113.7")),
            Some("for=203.0.113.7"),
            "read verbatim, which is what a deployment naming the wrong header gets"
        );
    }

    #[test]
    fn a_peer_list_that_does_not_parse_is_refused() {
        let _guard = crate::tests::env_guard();
        crate::tests::clear(&[HOPS, HEADER, PEERS]);
        crate::tests::set(HOPS, "1");

        crate::tests::set(PEERS, "10.0.0.0/8, fd00::/8");
        let held = Proxying::from_env().unwrap();
        assert_eq!(held.peers.len(), 2);

        // A typo that silently emptied the list would turn the check off on
        // the day it was meant to start.
        crate::tests::set(PEERS, "10.0.0.0/8, nonsense");
        assert!(Proxying::from_env().is_err());

        crate::tests::clear(&[PEERS, HOPS]);
    }

    #[test]
    fn absent_means_no_proxy_and_the_common_header() {
        let _guard = crate::tests::env_guard();
        crate::tests::clear(&[HOPS, HEADER, PEERS]);
        assert_eq!(Proxying::from_env().unwrap(), Proxying::none());

        crate::tests::set(HOPS, "2");
        crate::tests::set(HEADER, "forwarded");
        assert_eq!(
            Proxying::from_env().unwrap(),
            Proxying::behind(2, ProxyHeader::Forwarded)
        );

        crate::tests::set(HEADER, "x-real-ip");
        assert!(
            Proxying::from_env().is_err(),
            "an unread header was accepted"
        );

        crate::tests::clear(&[HEADER]);
        crate::tests::set(HOPS, "some");
        assert!(Proxying::from_env().is_err());
        crate::tests::clear(&[HOPS]);
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;

    fn behind(peers: &[&str]) -> Proxying {
        Proxying::behind_terminating_peers(
            ProxyHeader::XForwardedFor,
            "x-ssl-client-cert",
            peers.iter().filter_map(|held| Peer::parse(held)).collect(),
        )
    }

    /// The whole guard: a header is what any caller writes, and this one says
    /// whose token it is.
    #[test]
    fn a_certificate_is_read_only_from_a_named_peer() {
        let proxying = behind(&["10.0.0.0/8"]);
        assert_eq!(
            proxying.client_certificate(Some("10.1.2.3"), Some("a-certificate")),
            Some("a-certificate")
        );
        assert_eq!(
            proxying.client_certificate(Some("203.0.113.7"), Some("a-certificate")),
            None,
            "a certificate was believed from an address nobody named"
        );
    }

    /// Naming no peer reads no certificate, which is the opposite of what an
    /// empty list means for a forwarded address. An address believed from
    /// anybody falls back to the peer that dialled and is harmless; a
    /// certificate believed from anybody is one anybody may claim.
    #[test]
    fn naming_no_peer_reads_no_certificate() {
        let proxying = behind(&[]);
        assert_eq!(
            proxying.client_certificate(Some("10.1.2.3"), Some("a-certificate")),
            None
        );
    }

    /// A deployment that named no header terminates its own TLS, or does no
    /// mutual TLS at all.
    #[test]
    fn naming_no_header_reads_no_certificate() {
        let proxying = Proxying::behind_peers(
            1,
            ProxyHeader::XForwardedFor,
            vec![Peer::parse("10.0.0.0/8").expect("a peer")],
        );
        assert_eq!(
            proxying.client_certificate(Some("10.1.2.3"), Some("a-certificate")),
            None
        );
    }

    #[test]
    fn a_caller_with_no_address_is_no_named_peer() {
        assert_eq!(
            behind(&["10.0.0.0/8"]).client_certificate(None, Some("a-certificate")),
            None
        );
    }
}
