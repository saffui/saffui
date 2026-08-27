use std::time::Duration;

use auth::messaging::{Deliver, Message, Undelivered};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message as Letter, SmtpTransport, Transport};
use models::entities::mail::MailSettings;
use secrecy::ExposeSecret;

/// How long a server gets to take a message.
const PATIENCE: Duration = Duration::from_secs(10);

/// The realm's own SMTP server.
pub struct Smtp;

#[async_trait::async_trait]
impl Deliver for Smtp {
    async fn send(&self, settings: &MailSettings, message: &Message) -> Result<(), Undelivered> {
        let letter = compose(settings, message)?;
        let transport = transport(settings)?;
        // Off the reactor: the library sends on the calling thread, and a slow
        // server would otherwise hold every other request on this worker.
        tokio::task::spawn_blocking(move || transport.send(&letter))
            .await
            .map_err(|_| Undelivered::Refused)?
            .map(|_| ())
            .map_err(|why| {
                tracing::warn!(why = %why, "a message was not sent");
                Undelivered::Refused
            })
    }
}

fn compose(settings: &MailSettings, message: &Message) -> Result<Letter, Undelivered> {
    let from: Mailbox = if settings.from_name.is_empty() {
        settings.from_address.parse()
    } else {
        format!("{} <{}>", settings.from_name, settings.from_address).parse()
    }
    .map_err(|_| Undelivered::Refused)?;

    let mut building = Letter::builder()
        .from(from)
        .to(message.to.parse().map_err(|_| Undelivered::Refused)?)
        .subject(&message.subject)
        .header(ContentType::TEXT_PLAIN);
    if let Some(reply_to) = &settings.reply_to {
        building = building.reply_to(reply_to.parse().map_err(|_| Undelivered::Refused)?);
    }
    building
        .body(message.body.clone())
        .map_err(|_| Undelivered::Refused)
}

/// Always over TLS. Implicit wraps the socket from the first byte; otherwise
/// the connection is upgraded and a server that will not upgrade is refused
/// rather than fallen back to, which is how a password reaches the wire.
fn transport(settings: &MailSettings) -> Result<SmtpTransport, Undelivered> {
    let parameters = TlsParameters::new(settings.host.clone()).map_err(|_| Undelivered::Refused)?;
    let mut building = SmtpTransport::builder_dangerous(&settings.host)
        .port(settings.port)
        .timeout(Some(PATIENCE))
        .tls(if settings.implicit_tls {
            Tls::Wrapper(parameters)
        } else {
            Tls::Required(parameters)
        });
    if let Some(held) = &settings.credentials {
        building = building.credentials(Credentials::new(
            held.username.clone(),
            held.password.expose_secret().clone(),
        ));
    }
    Ok(building.build())
}

/// A gateway of the deployment's own, told over HTTP.
pub struct Webhook {
    url: String,
    bearer: Option<String>,
}

impl Webhook {
    pub fn new(url: String, bearer: Option<String>) -> Self {
        Webhook { url, bearer }
    }
}

#[async_trait::async_trait]
impl Deliver for Webhook {
    async fn send(&self, settings: &MailSettings, message: &Message) -> Result<(), Undelivered> {
        let body = serde_json::json!({
            "to": message.to,
            "from": settings.from_address,
            "subject": message.subject,
            "text": message.body,
        });
        let (url, bearer) = (self.url.clone(), self.bearer.clone());
        tokio::task::spawn_blocking(move || {
            let agent = ureq::Agent::config_builder()
                .timeout_global(Some(PATIENCE))
                .tls_config(
                    ureq::tls::TlsConfig::builder()
                        .provider(ureq::tls::TlsProvider::NativeTls)
                        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                        .build(),
                )
                .build()
                .new_agent();
            let mut posting = agent.post(&url);
            if let Some(bearer) = &bearer {
                posting = posting.header("authorization", &format!("Bearer {bearer}"));
            }
            posting
                .header("content-type", "application/json")
                .send(body.to_string())
                .map(|_| ())
                .map_err(|why| {
                    tracing::warn!(why = %why, "a message was not sent");
                    Undelivered::Refused
                })
        })
        .await
        .map_err(|_| Undelivered::Refused)?
    }
}

/// Writes the message to the log instead of sending it.
///
/// For a deployment being built, and named as such where it is chosen. It
/// prints the whole message, sign-in link included, which is why it is never
/// what a deployment gets by not choosing.
pub struct Logged;

#[async_trait::async_trait]
impl Deliver for Logged {
    async fn send(&self, _settings: &MailSettings, message: &Message) -> Result<(), Undelivered> {
        tracing::warn!(
            to = message.to,
            subject = message.subject,
            body = message.body,
            "a message was written to the log and not sent"
        );
        Ok(())
    }
}
