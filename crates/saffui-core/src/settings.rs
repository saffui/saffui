//! What the deployment says once, at start.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where the public reaches this deployment: a scheme and an authority,
/// nothing after. Every issuer starts with it, and an issuer is compared byte
/// for byte by every relying party: it carries no product name and no version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicOrigin(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublicOriginError {
    #[error("expected https://host or https://host:port, the host in lower case")]
    Unreadable,
    #[error("the port is the default of the scheme: leave it out")]
    DefaultPort,
    #[error("http is accepted for this machine only")]
    ClearToRemoteHost,
}

enum Host<'a> {
    Name(&'a str),
    Address(IpAddr),
}

impl PublicOrigin {
    /// Reads an origin as the operator wrote it. Only the spelling a URL
    /// parser writes back is accepted, so that one origin has one issuer.
    ///
    /// # Errors
    ///
    /// Returns why the text cannot be the public origin.
    pub fn parse(text: &str) -> Result<Self, PublicOriginError> {
        let (secure, authority) = if let Some(rest) = text.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(PublicOriginError::Unreadable);
        };
        let (host, port) = read_authority(authority).ok_or(PublicOriginError::Unreadable)?;
        if port == Some(if secure { 443 } else { 80 }) {
            return Err(PublicOriginError::DefaultPort);
        }
        let loopback = match host {
            Host::Name(name) => name == "localhost",
            Host::Address(address) => {
                address == IpAddr::V4(Ipv4Addr::LOCALHOST)
                    || address == IpAddr::V6(Ipv6Addr::LOCALHOST)
            }
        };
        if !secure && !loopback {
            return Err(PublicOriginError::ClearToRemoteHost);
        }
        Ok(Self(text.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A range of addresses: one address, or a network and the length of its
/// prefix (`10.0.0.0/8`, `2001:db8::/32`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    network: IpAddr,
    prefix: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AddressRangeError {
    #[error("expected an address, or an address and the length of its prefix")]
    Unreadable,
    #[error("the address has bits set past its prefix: write the start of the range")]
    NotItsStart,
    #[error("a prefix shorter than 8 bits would hold callers from anywhere")]
    TooWide,
}

/// The shortest prefix a range may have. Wider, it would believe the word
/// of machines that are no proxy of the deployment.
const SHORTEST_PREFIX: u8 = 8;

impl AddressRange {
    /// Reads an address or a range. An IPv4 address written in IPv6
    /// (`::ffff:a.b.c.d`) is refused: it is written as itself.
    ///
    /// # Errors
    ///
    /// Returns why the text is no range this deployment believes.
    pub fn parse(text: &str) -> Result<Self, AddressRangeError> {
        let (address, prefix) = match text.split_once('/') {
            None => (text, None),
            Some((address, prefix)) => (address, Some(prefix)),
        };
        let network: IpAddr = address.parse().map_err(|_| AddressRangeError::Unreadable)?;
        if matches!(network, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
            return Err(AddressRangeError::Unreadable);
        }
        let bits = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => bits,
            Some(written) => {
                // Digits only, without a sign or a leading zero: one spelling per prefix.
                if written.is_empty()
                    || written.len() > 3
                    || (written.len() > 1 && written.starts_with('0'))
                    || !written.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(AddressRangeError::Unreadable);
                }
                written
                    .parse::<u8>()
                    .map_err(|_| AddressRangeError::Unreadable)?
            }
        };
        if prefix > bits {
            return Err(AddressRangeError::Unreadable);
        }
        if prefix < SHORTEST_PREFIX {
            return Err(AddressRangeError::TooWide);
        }
        let range = Self { network, prefix };
        if range.mask(network) != Some(to_bits(network)) {
            return Err(AddressRangeError::NotItsStart);
        }
        Ok(range)
    }

    /// Tells whether an address is in the range, read in its canonical form.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        self.mask(address.to_canonical()) == Some(to_bits(self.network))
    }

    /// The bits of `address` under the prefix, when it is of the family of
    /// the range.
    fn mask(&self, address: IpAddr) -> Option<u128> {
        if address.is_ipv4() != self.network.is_ipv4() {
            return None;
        }
        let width: u32 = if self.network.is_ipv4() { 32 } else { 128 };
        // At least 8 bits of prefix: the shift never reaches the width.
        let host_bits = width - u32::from(self.prefix);
        let mask = u128::MAX.checked_shl(host_bits).unwrap_or(0);
        Some(to_bits(address) & mask)
    }
}

fn to_bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub public_origin: PublicOrigin,
    /// The proxies in front of this deployment. Only a peer in one of these
    /// ranges is believed when it says who the request comes from.
    pub trusted_proxies: Vec<AddressRange>,
}

impl Settings {
    /// The settings of a deployment that nothing stands in front of.
    #[must_use]
    pub fn reached_directly(public_origin: PublicOrigin) -> Self {
        Self {
            public_origin,
            trusted_proxies: Vec::new(),
        }
    }
}

fn read_authority(authority: &str) -> Option<(Host<'_>, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let address: Ipv6Addr = inside.parse().ok()?;
        // A URL parser writes a mapped address in hexadecimal, where the
        // standard library writes it dotted: no spelling is shared.
        if address.to_ipv4_mapped().is_some() || address.to_string() != inside {
            return None;
        }
        let port = match after {
            "" => None,
            _ => Some(read_port(after.strip_prefix(':')?)?),
        };
        return Some((Host::Address(IpAddr::V6(address)), port));
    }
    let (name, port) = match authority.split_once(':') {
        Some((name, port)) => (name, Some(read_port(port)?)),
        None => (authority, None),
    };
    Some((read_host_name(name)?, port))
}

fn read_host_name(name: &str) -> Option<Host<'_>> {
    let last = name.rsplit('.').next()?;
    // A host whose last label is a number is an address to every URL parser.
    if last.bytes().all(|byte| byte.is_ascii_digit()) || last.starts_with("0x") {
        let address: Ipv4Addr = name.parse().ok()?;
        return (address.to_string() == name).then_some(Host::Address(IpAddr::V4(address)));
    }
    let plain = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    (name.len() <= 253 && name.split('.').all(plain)).then_some(Host::Name(name))
}

fn read_port(text: &str) -> Option<u16> {
    // `u16::from_str` also takes a sign and leading zeros.
    if text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{AddressRange, AddressRangeError, PublicOrigin, PublicOriginError};

    #[test]
    fn an_https_origin_and_a_loopback_http_origin_are_read() {
        for text in [
            "https://id.example.org",
            "https://id.example.org:8443",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "https://192.0.2.10",
            "https://[2001:db8::1]:8443",
            "https://a23456789-123456789-123456789-123456789-123456789-123456789-123.example.org",
        ] {
            assert_eq!(
                PublicOrigin::parse(text).map(|origin| origin.to_string()),
                Ok(text.to_owned())
            );
        }
    }

    #[test]
    fn anything_after_the_authority_is_refused() {
        for text in [
            "https://id.example.org/",
            "https://id.example.org/auth",
            "https://id.example.org?x=1",
            "https://user@id.example.org",
            "https://",
            "id.example.org",
            "ftp://id.example.org",
        ] {
            assert_eq!(
                PublicOrigin::parse(text),
                Err(PublicOriginError::Unreadable),
                "{text}"
            );
        }
    }

    #[test]
    fn an_authority_a_url_parser_would_not_write_back_the_same_is_refused() {
        for text in [
            "https://[",
            "https://]",
            "https://:",
            "https://:8443",
            "https://a:b:c",
            "https://ID.Example.org",
            "https://id.example.org:",
            "https://id.example.org:abc",
            "https://id.example.org:+8443",
            "https://id.example.org:08443",
            "https://id.example.org:65536",
            "https://192.0.2.999",
            "https://0x7f.0.0.1",
            "https://id.0x7f",
            "https://1.2.3.0x4",
            "https://[0:0:0:0:0:0:0:1]",
            "https://[::ffff:192.0.2.1]",
            "http://[::1]evil.example",
            "http://127.0.0.1]x",
        ] {
            assert_eq!(
                PublicOrigin::parse(text),
                Err(PublicOriginError::Unreadable),
                "{text}"
            );
        }
    }

    #[test]
    fn what_a_url_parser_keeps_but_dns_or_tcp_cannot_carry_is_refused() {
        for text in [
            "https://id..example.org",
            "https://-id.example.org",
            "https://id-.example.org",
            "https://a23456789-123456789-123456789-123456789-123456789-123456789-1234.example.org",
            "https://id.example.org:0",
        ] {
            assert_eq!(
                PublicOrigin::parse(text),
                Err(PublicOriginError::Unreadable),
                "{text}"
            );
        }
    }

    #[test]
    fn a_second_spelling_of_a_host_a_url_parser_keeps_is_refused() {
        // Each would name an issuer of its own for the same host.
        for text in ["https://id.example.org.", "https://[::ffff:c000:201]"] {
            assert_eq!(
                PublicOrigin::parse(text),
                Err(PublicOriginError::Unreadable),
                "{text}"
            );
        }
    }

    #[test]
    fn a_host_name_longer_than_253_bytes_is_refused() {
        let label = "a".repeat(63);
        let name = [label.as_str(); 4].join(".");
        assert_eq!(name.len(), 255);
        assert_eq!(
            PublicOrigin::parse(&format!("https://{name}")),
            Err(PublicOriginError::Unreadable)
        );
        assert!(PublicOrigin::parse(&format!("https://{}", &name[..253])).is_ok());
    }

    #[test]
    fn the_default_port_of_the_scheme_is_refused() {
        for text in ["https://id.example.org:443", "http://localhost:80"] {
            assert_eq!(
                PublicOrigin::parse(text),
                Err(PublicOriginError::DefaultPort),
                "{text}"
            );
        }
    }

    #[test]
    fn http_to_a_host_that_is_not_this_machine_is_refused() {
        for text in ["http://id.example.org", "http://127.0.0.2:8080"] {
            assert_eq!(
                PublicOrigin::parse(text),
                Err(PublicOriginError::ClearToRemoteHost),
                "{text}"
            );
        }
    }

    fn read(address: &str) -> IpAddr {
        address.parse().expect("an address")
    }

    #[test]
    fn a_range_holds_the_addresses_under_its_prefix_and_no_other() {
        let private = AddressRange::parse("10.0.0.0/8").expect("a range");
        let documentation = AddressRange::parse("2001:db8::/32").expect("a range");
        let alone = AddressRange::parse("192.0.2.7").expect("an address");

        assert!(private.contains(read("10.255.3.4")));
        assert!(
            private.contains(read("::ffff:10.1.2.3")),
            "read in its canonical form"
        );
        assert!(!private.contains(read("11.0.0.1")));
        assert!(!private.contains(read("::a00:1")), "another family");
        assert!(documentation.contains(read("2001:db8:ffff::1")));
        assert!(!documentation.contains(read("2001:db9::1")));
        assert!(alone.contains(read("192.0.2.7")));
        assert!(!alone.contains(read("192.0.2.8")));
    }

    #[test]
    fn a_range_is_written_from_its_start_never_wider_than_eight_bits() {
        for (written, refused) in [
            ("10.0.0.1/8", AddressRangeError::NotItsStart),
            ("2001:db8::1/32", AddressRangeError::NotItsStart),
            ("0.0.0.0/0", AddressRangeError::TooWide),
            ("::/0", AddressRangeError::TooWide),
            ("8.0.0.0/7", AddressRangeError::TooWide),
            ("10.0.0.0/33", AddressRangeError::Unreadable),
            ("10.0.0.0/", AddressRangeError::Unreadable),
            ("10.0.0.0/+8", AddressRangeError::Unreadable),
            ("10.0.0.0/008", AddressRangeError::Unreadable),
            ("::ffff:10.0.0.1", AddressRangeError::Unreadable),
            ("proxy.internal", AddressRangeError::Unreadable),
        ] {
            assert_eq!(AddressRange::parse(written), Err(refused), "{written}");
        }
        assert!(AddressRange::parse("fd00::/8").is_ok());
        assert!(AddressRange::parse("2001:db8::7/128").is_ok());
    }
}
