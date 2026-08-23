//! How many reverse proxies stand in front, and which header they write. The
//! two together are the only thing that makes a forwarded address readable.

use crate::ConfigError;

const HOPS: &str = "PROXY_HOPS";
const HEADER: &str = "PROXY_HEADER";

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

/// What stands between a caller and this server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proxying {
    hops: usize,
    header: ProxyHeader,
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
        Ok(Proxying {
            hops: crate::parse_or(HOPS, 0)?,
            header,
        })
    }

    pub fn none() -> Self {
        Proxying::behind(0, ProxyHeader::XForwardedFor)
    }

    /// Built from values from anywhere, for a deployment described in something
    /// other than the environment.
    pub fn behind(hops: usize, header: ProxyHeader) -> Self {
        Proxying { hops, header }
    }

    /// The header to read, or nothing when no proxy stands in front and none
    /// should be read.
    pub fn header(self) -> Option<ProxyHeader> {
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
    pub fn caller<'a>(self, peer: Option<&'a str>, carried: Option<&'a str>) -> Option<&'a str> {
        if self.hops == 0 {
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
    fn absent_means_no_proxy_and_the_common_header() {
        let _guard = crate::tests::env_guard();
        crate::tests::clear(&[HOPS, HEADER]);
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
