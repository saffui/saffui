use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use models::entities::mail::MailSettings;
use openssl::ssl::{SslConnector, SslMethod, SslStream};

/// How long the relay gets, at each step and altogether.
const PATIENCE: Duration = Duration::from_secs(10);

/// What the console needs to say about a relay without guessing at any of it.
///
/// Every field is read off the dialogue this probe actually held. A relay that
/// answers nothing leaves the field absent rather than filled with a default,
/// because a screen that prints a version nobody negotiated is worse than one
/// that prints nothing.
#[derive(Debug, Default, serde::Serialize)]
pub struct RelayReport {
    /// How long the socket took to open, which is the one number an operator
    /// compares against yesterday.
    pub reached_in_millis: Option<u64>,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    /// When the relay's certificate stops being valid, in RFC 3339.
    pub certificate_until: Option<String>,
    pub certificate_issuer: Option<String>,
    /// The largest message the relay says it takes, from its SIZE capability.
    pub max_message_bytes: Option<i64>,
    /// The authentication mechanisms it offers, in the order it offered them.
    pub auth_offered: Vec<String>,
    /// The dialogue, as it happened. Never a secret: an AUTH line is entered
    /// as the command alone, because the argument is the credential.
    pub transcript: Vec<String>,
    /// Absent where the whole exchange completed.
    pub refused: Option<String>,
}

/// Hold the relay in conversation and write down what it says.
///
/// The point is not to send anything. It is to answer the questions an
/// operator asks when mail stops: does it answer, how fast, what does the
/// handshake settle on, whose certificate is it, how big a message will it
/// take, and how does it want to be authenticated.
pub fn look_at_relay(settings: &MailSettings) -> RelayReport {
    let mut report = RelayReport::default();
    let started = Instant::now();

    let address = format!("{}:{}", settings.host, settings.port);
    let stream = match TcpStream::connect(&address) {
        Ok(held) => held,
        Err(why) => {
            report.refused = Some(format!("the socket did not open: {why}"));
            return report;
        }
    };
    report.reached_in_millis = Some(started.elapsed().as_millis() as u64);
    let _ = stream.set_read_timeout(Some(PATIENCE));
    let _ = stream.set_write_timeout(Some(PATIENCE));

    if settings.implicit_tls {
        if let Some(secured) = raise_tls(stream, &settings.host, &mut report) {
            finish_the_dialogue(secured, settings, &mut report);
        }
        return report;
    }

    let mut plain = Dialogue::new(stream);
    if !plain.hear_greeting(&mut report) || !plain.send_hello(&settings.host, &mut report) {
        return report;
    }
    if !plain.send_command("STARTTLS", &mut report) {
        report.refused =
            Some("the relay would not start TLS, and nothing is sent in the clear".into());
        return report;
    }
    if let Some(secured) = raise_tls(plain.into_inner(), &settings.host, &mut report) {
        finish_the_dialogue(secured, settings, &mut report);
    }
    report
}

/// The handshake, and what it settled on.
fn raise_tls(
    stream: TcpStream,
    host: &str,
    report: &mut RelayReport,
) -> Option<SslStream<TcpStream>> {
    let connector = match SslConnector::builder(SslMethod::tls_client()) {
        Ok(held) => held.build(),
        Err(why) => {
            report.refused = Some(format!("no TLS client could be built: {why}"));
            return None;
        }
    };
    let secured = match connector.connect(host, stream) {
        Ok(held) => held,
        Err(why) => {
            report.refused = Some(format!("the handshake failed: {why}"));
            return None;
        }
    };

    report.tls_version = Some(secured.ssl().version_str().to_owned());
    report.cipher = secured
        .ssl()
        .current_cipher()
        .map(|held| held.name().to_owned());
    if let Some(certificate) = secured.ssl().peer_certificate() {
        report.certificate_until = Some(certificate.not_after().to_string());
        // The common name where the issuer states one, and the last thing it
        // states otherwise: an issuer is read by a person, not parsed.
        // The last thing the issuer states about itself, which is the name a
        // person recognises. An issuer is read, not parsed.
        report.certificate_issuer = certificate
            .issuer_name()
            .entries()
            .filter_map(|entry| entry.data().to_string().ok())
            .last();
    }
    report.transcript.push("--- TLS ---".to_owned());
    Some(secured)
}

/// The half of the dialogue that only happens once the channel is private.
fn finish_the_dialogue(
    secured: SslStream<TcpStream>,
    settings: &MailSettings,
    report: &mut RelayReport,
) {
    let mut talking = Dialogue::new(secured);
    if settings.implicit_tls && !talking.hear_greeting(report) {
        return;
    }
    if !talking.send_hello(&settings.host, report) {
        return;
    }
    // Authentication is attempted only where the settings hold a credential,
    // and the line is written down as the command alone: the argument is the
    // credential, and a transcript on a screen is a transcript in a screenshot.
    if let Some(held) = &settings.credentials {
        talking.send_command_writing(
            &format!("AUTH LOGIN {}", encoded(&held.username)),
            &format!("AUTH LOGIN ({})", held.username),
            report,
        );
    }
    talking.send_command("QUIT", report);
}

fn encoded(held: &str) -> String {
    data_encoding::BASE64.encode(held.as_bytes())
}

/// One side of an SMTP conversation, over whatever the channel turned out to
/// be.
struct Dialogue<S: std::io::Read + Write> {
    reader: BufReader<S>,
}

impl<S: std::io::Read + Write> Dialogue<S> {
    fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    fn into_inner(self) -> S {
        self.reader.into_inner()
    }

    /// Read one reply, which SMTP spells over as many lines as it likes: a
    /// hyphen after the code means another line follows.
    fn hear_reply(&mut self, report: &mut RelayReport) -> Option<Vec<String>> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => {
                    report.refused = Some("the relay closed the connection".into());
                    return None;
                }
                Ok(_) => {}
                Err(why) => {
                    report.refused = Some(format!("the relay went quiet: {why}"));
                    return None;
                }
            }
            let line = line.trim_end().to_owned();
            report.transcript.push(format!("< {line}"));
            let more = line.as_bytes().get(3) == Some(&b'-');
            lines.push(line);
            if !more {
                return Some(lines);
            }
        }
    }

    fn hear_greeting(&mut self, report: &mut RelayReport) -> bool {
        matches!(self.hear_reply(report), Some(lines) if lines.first().is_some_and(|held| held.starts_with('2')))
    }

    fn send_command(&mut self, command: &str, report: &mut RelayReport) -> bool {
        self.send_command_writing(command, command, report)
    }

    /// Send one thing and write down another. The two differ exactly once,
    /// where the argument is a credential.
    fn send_command_writing(
        &mut self,
        command: &str,
        written: &str,
        report: &mut RelayReport,
    ) -> bool {
        report.transcript.push(format!("> {written}"));
        if self
            .reader
            .get_mut()
            .write_all(format!("{command}\r\n").as_bytes())
            .is_err()
        {
            report.refused = Some("the relay stopped listening".into());
            return false;
        }
        let Some(lines) = self.hear_reply(report) else {
            return false;
        };
        lines
            .first()
            .is_some_and(|held| held.starts_with('2') || held.starts_with('3'))
    }

    /// EHLO, and what the relay says it can do.
    fn send_hello(&mut self, host: &str, report: &mut RelayReport) -> bool {
        report.transcript.push(format!("> EHLO {host}"));
        if self
            .reader
            .get_mut()
            .write_all(format!("EHLO {host}\r\n").as_bytes())
            .is_err()
        {
            report.refused = Some("the relay stopped listening".into());
            return false;
        }
        let Some(lines) = self.hear_reply(report) else {
            return false;
        };
        for line in &lines {
            let said = line.get(4..).unwrap_or_default().trim();
            if let Some(size) = said.strip_prefix("SIZE ") {
                report.max_message_bytes = size.trim().parse().ok();
            }
            if let Some(mechanisms) = said.strip_prefix("AUTH ") {
                report.auth_offered = mechanisms.split_whitespace().map(str::to_owned).collect();
            }
        }
        lines.first().is_some_and(|held| held.starts_with('2'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    /// A relay that says whatever the test hands it, one line per reply.
    fn relay(script: Vec<&'static str>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a caller");
            let mut said = script.into_iter();
            if let Some(greeting) = said.next() {
                let _ = stream.write_all(format!("{greeting}\r\n").as_bytes());
            }
            let mut buffer = [0_u8; 512];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                match said.next() {
                    Some(reply) => {
                        let _ = stream.write_all(format!("{reply}\r\n").as_bytes());
                    }
                    None => break,
                }
            }
        });
        port
    }

    fn settings(port: u16) -> MailSettings {
        MailSettings {
            host: "127.0.0.1".to_owned(),
            port,
            from_address: "no-reply@saffui.test".to_owned(),
            from_name: String::new(),
            reply_to: None,
            implicit_tls: false,
            credentials: None,
        }
    }

    /// The one refusal that matters. A relay that will not upgrade is left,
    /// not talked to in the clear: everything after the greeting is a
    /// password, a recipient or a message body.
    #[test]
    fn a_relay_that_will_not_start_tls_is_left_rather_than_spoken_to_in_the_clear() {
        let port = relay(vec![
            "220 relay.test ESMTP ready",
            "250-relay.test\r\n250 SIZE 20480000",
            "454 4.7.0 TLS not available",
        ]);

        let report = look_at_relay(&settings(port));

        assert!(
            report
                .refused
                .is_some_and(|why| why.contains("nothing is sent in the clear")),
            "a relay refusing TLS was not left"
        );
        assert!(
            report.tls_version.is_none(),
            "a version was reported with no handshake"
        );
    }

    /// What the relay says about itself is read off the dialogue, not assumed.
    #[test]
    fn the_capabilities_are_read_off_what_the_relay_answered() {
        let port = relay(vec![
            "220 relay.test ESMTP ready",
            "250-relay.test\r\n250-SIZE 20480000\r\n250 AUTH LOGIN PLAIN",
            "454 4.7.0 TLS not available",
        ]);

        let report = look_at_relay(&settings(port));

        assert_eq!(report.max_message_bytes, Some(20_480_000));
        assert_eq!(
            report.auth_offered,
            vec!["LOGIN".to_owned(), "PLAIN".to_owned()]
        );
        assert!(
            report.reached_in_millis.is_some(),
            "the socket opened and was not timed"
        );
    }

    /// A relay nobody is running answers nothing, and the probe says so
    /// rather than reporting a reading it never took.
    #[test]
    fn a_relay_that_is_not_there_reports_nothing_it_did_not_see() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        drop(listener);

        let report = look_at_relay(&settings(port));

        assert!(report.refused.is_some());
        assert!(report.reached_in_millis.is_none());
        assert!(report.tls_version.is_none());
        assert!(report.certificate_issuer.is_none());
        assert!(report.max_message_bytes.is_none());
    }
}
