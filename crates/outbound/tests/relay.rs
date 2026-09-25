//! A real relay between this client and a mailbox: mailpit, requiring
//! STARTTLS under a certificate a test authority issued, and taking any
//! credential. What arrives is read back through its API.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use auth::messaging::{Deliver, Message, Undelivered, told};
use config::serving::Egress;
use crypto::secrecy::SecretBox;
use models::entities::mail::{MailCredentials, MailSettings};
use openssl::x509::X509;
use outbound::senders::Smtp;
use outbound::smtp::SmtpClient;

/// Where the relay listens, where its API answers, and who issued its
/// certificate.
struct Relay {
    host: String,
    port: u16,
    api: String,
    authority: X509,
}

/// The relay the environment names, or a line saying there is none.
fn relay() -> Option<Relay> {
    let (Ok(address), Ok(api), Ok(authority)) = (
        std::env::var("SAFFUI_TEST_SMTP"),
        std::env::var("SAFFUI_TEST_SMTP_API"),
        std::env::var("SAFFUI_TEST_SMTP_CA"),
    ) else {
        eprintln!("SAFFUI_TEST_SMTP unset; there is no relay to send through");
        return None;
    };
    let (host, port) = address.rsplit_once(':').expect("the relay as host:port");
    let pem = std::fs::read(authority).expect("the authority's certificate");
    Some(Relay {
        host: host.to_owned(),
        port: port.parse().expect("a port"),
        api,
        authority: X509::from_pem(&pem).expect("a certificate"),
    })
}

fn settings(relay: &Relay) -> MailSettings {
    MailSettings {
        host: relay.host.clone(),
        port: relay.port,
        from_address: "no-reply@saffui.test".to_owned(),
        from_name: "saffui".to_owned(),
        reply_to: None,
        implicit_tls: false,
        credentials: Some(MailCredentials {
            username: "ada".to_owned(),
            password: SecretBox::new(Box::new("a-mail-password".to_owned())),
        }),
    }
}

/// A subject no earlier run has used.
fn fresh_subject() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock past 1970")
        .as_nanos();
    format!("saffui relay test {now} {}", std::process::id())
}

/// The letter the relay's mailbox holds under `subject`, as it arrived.
fn arrived(relay: &Relay, subject: &str) -> Option<String> {
    for _ in 0..30 {
        let listing = ureq::get(format!("{}/api/v1/messages", relay.api))
            .call()
            .expect("the mailbox answers")
            .body_mut()
            .read_to_string()
            .expect("a listing");
        let listed: serde_json::Value = serde_json::from_str(&listing).expect("a listing");
        let found = listed["messages"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|held| held["Subject"] == subject)
            .and_then(|held| held["ID"].as_str().map(str::to_owned));
        if let Some(id) = found {
            return ureq::get(format!("{}/api/v1/message/{id}/raw", relay.api))
                .call()
                .expect("the letter")
                .body_mut()
                .read_to_string()
                .ok();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// The whole road against a relay this crate did not write: STARTTLS, the
/// sign-in, the envelope and the letter, whose lines starting with a dot
/// arrive as they were written.
#[tokio::test]
#[ignore = "needs a relay (SAFFUI_TEST_SMTP)"]
async fn a_letter_crosses_a_real_relay_intact() {
    let Some(relay) = relay() else {
        return;
    };
    let subject = fresh_subject();
    let sender = Smtp::through(
        SmtpClient::trusting(&relay.authority, Egress::Anywhere).expect("a TLS client"),
    );
    let message = Message::to(
        "ada@example.test",
        told(
            &subject,
            "Plain words.\n.a line that starts with a dot\n..and one with two\n",
        ),
    );

    sender
        .send(&settings(&relay), &message)
        .await
        .expect("the relay took the letter");

    let raw = arrived(&relay, &subject).expect("the letter arrived");
    assert!(raw.contains("To: ada@example.test"), "{raw}");
    assert!(
        raw.contains("\r\n.a line that starts with a dot\r\n"),
        "a line's dot did not arrive as written: {raw}"
    );
    assert!(raw.contains("\r\n..and one with two\r\n"), "{raw}");
}

/// The probe reads a real relay the way a letter meets it: over TLS, under
/// the test authority, with the mechanisms offered after the handshake.
#[tokio::test]
#[ignore = "needs a relay (SAFFUI_TEST_SMTP)"]
async fn the_probe_reads_a_real_relay() {
    let Some(relay) = relay() else {
        return;
    };

    let report = SmtpClient::trusting(&relay.authority, Egress::Anywhere)
        .expect("a TLS client")
        .look_at(&settings(&relay))
        .await;

    assert_eq!(report.refused, None, "{report:?}");
    assert!(
        report
            .tls_version
            .as_deref()
            .is_some_and(|version| version.starts_with("TLSv1.")),
        "{report:?}"
    );
    assert_eq!(
        report.certificate_issuer.as_deref(),
        Some("saffui test authority")
    );
    assert!(
        report.auth_offered.iter().any(|held| held == "PLAIN"),
        "{report:?}"
    );
    assert!(
        !report
            .transcript
            .iter()
            .any(|line| line.contains("a-mail-password")),
        "the transcript holds the password"
    );
}

/// A relay whose certificate no authority this client trusts issued is left
/// at the handshake, before anything is said over it.
#[tokio::test]
#[ignore = "needs a relay (SAFFUI_TEST_SMTP)"]
async fn a_relay_under_an_unknown_authority_is_left() {
    let Some(relay) = relay() else {
        return;
    };
    let sender = Smtp::through(SmtpClient::new(Egress::Anywhere).expect("a TLS client"));
    let message = Message::to("ada@example.test", told(&fresh_subject(), "Plain words.\n"));

    let refused = sender.send(&settings(&relay), &message).await;

    assert!(matches!(refused, Err(Undelivered::Refused)), "{refused:?}");
}
