//! A client small enough to read: one request per connection, the whole
//! answer read until the server closes.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct Answer {
    pub status: u16,
    pub head: String,
    pub body: String,
}

/// Sends one request and reads the whole answer.
pub fn send_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    head: &[(&str, &str)],
    body: &str,
) -> io::Result<Answer> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request = String::new();
    let _ = write!(
        request,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    );
    for (name, value) in head {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    if !body.is_empty() || method != "GET" {
        let _ = write!(request, "Content-Length: {}\r\n", body.len());
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes())?;

    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    let (head, body) = answer
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::other(format!("not an HTTP answer: {answer:?}")))?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::other(format!("no status in {head:?}")))?;
    Ok(Answer {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    })
}

pub fn get(address: SocketAddr, path: &str) -> io::Result<Answer> {
    send_request(address, "GET", path, &[], "")
}
