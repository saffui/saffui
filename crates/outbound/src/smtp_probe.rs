//! A relay held in conversation and what it said written down, for the
//! operator asking why mail stopped.

use data_encoding::BASE64;
use models::entities::mail::MailSettings;

use crate::smtp::{Notes, SmtpClient, Unsent};

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
    /// When the relay's certificate stops being valid, as OpenSSL prints it.
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

impl SmtpClient {
    /// Hold the relay in conversation and write down what it says.
    ///
    /// The point is not to send anything. It is to answer the questions an
    /// operator asks when mail stops: does it answer, how fast, what does the
    /// handshake settle on, whose certificate is it, how big a message will it
    /// take, and how does it want to be authenticated. The conversation is the
    /// one a letter opens, up to the EHLO over TLS, so what the probe sees is
    /// what a letter would meet.
    pub async fn look_at(&self, settings: &MailSettings) -> RelayReport {
        let mut notes = Notes::kept();
        let refused = self.hold_conversation(settings, &mut notes).await.err();
        RelayReport::written_from(notes, refused)
    }

    async fn hold_conversation(
        &self,
        settings: &MailSettings,
        notes: &mut Notes,
    ) -> Result<(), Unsent> {
        let (mut talk, _) = self.open(settings, notes).await?;
        // Authentication is attempted only where the settings hold a
        // credential, and only as far as the name: the relay's answer says how
        // it wants the rest, and a password has no business in a probe.
        if let Some(held) = &settings.credentials {
            talk.say_writing(
                &format!("AUTH LOGIN {}", BASE64.encode(held.username.as_bytes())),
                &format!("AUTH LOGIN ({})", held.username),
                notes,
            )
            .await?;
        }
        talk.say("QUIT", notes).await?;
        Ok(())
    }
}

impl RelayReport {
    fn written_from(notes: Notes, refused: Option<Unsent>) -> RelayReport {
        let offered = notes.offered.unwrap_or_default();
        let handshake = notes.handshake;
        RelayReport {
            reached_in_millis: notes.reached_in.map(|held| held.as_millis() as u64),
            tls_version: handshake.as_ref().map(|held| held.version.clone()),
            cipher: handshake.as_ref().and_then(|held| held.cipher.clone()),
            certificate_until: handshake.as_ref().and_then(|held| held.until.clone()),
            certificate_issuer: handshake.and_then(|held| held.issuer),
            max_message_bytes: offered.size,
            auth_offered: offered.auth,
            transcript: notes.transcript,
            refused: refused.map(|why| why.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::serving::Egress;
    use std::io::{Read, Write};
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

    /// A client that may dial this machine, where the test relays listen.
    fn client() -> SmtpClient {
        SmtpClient::new(Egress::Anywhere).expect("a TLS client")
    }

    /// The one refusal that matters. A relay that will not upgrade is left,
    /// not talked to in the clear: everything after the greeting is a
    /// password, a recipient or a message body.
    #[tokio::test]
    async fn a_relay_that_will_not_start_tls_is_left_rather_than_spoken_to_in_the_clear() {
        let port = relay(vec![
            "220 relay.test ESMTP ready",
            "250-relay.test\r\n250 SIZE 20480000",
            "454 4.7.0 TLS not available",
        ]);

        let report = client().look_at(&settings(port)).await;

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
    #[tokio::test]
    async fn the_capabilities_are_read_off_what_the_relay_answered() {
        let port = relay(vec![
            "220 relay.test ESMTP ready",
            "250-relay.test\r\n250-SIZE 20480000\r\n250 AUTH LOGIN PLAIN",
            "454 4.7.0 TLS not available",
        ]);

        let report = client().look_at(&settings(port)).await;

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
    #[tokio::test]
    async fn a_relay_that_is_not_there_reports_nothing_it_did_not_see() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        drop(listener);

        let report = client().look_at(&settings(port)).await;

        assert!(report.refused.is_some());
        assert!(report.reached_in_millis.is_none());
        assert!(report.tls_version.is_none());
        assert!(report.certificate_issuer.is_none());
        assert!(report.max_message_bytes.is_none());
    }
}
