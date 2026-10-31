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

#[derive(Clone, Debug)]
pub struct Settings {
    pub public_origin: PublicOrigin,
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
    use super::{PublicOrigin, PublicOriginError};

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
}
