use std::time::Duration;

use auth::messaging::{Deliver, Message, Text, Texter, Undelivered};
use config::serving::Egress;
use ureq::unversioned::resolver::DefaultResolver;

use crate::api::rest::endpoints::protocol::hosted::{Outward, may_dial};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message as Letter, SmtpTransport, Transport};
use models::entities::mail::MailSettings;
use models::entities::sms::SmsSettings;
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

/// The realm's own SMS gateway, told over HTTP.
///
/// This is the wire a third-party sender implements to carry saffui's texts:
/// a POST to the realm's configured URL, `Authorization: Bearer <token>` when
/// the realm holds one, and a JSON body of exactly three fields,
/// `{"to": "<E.164>", "from": "<sender>", "text": "<body>"}`. Any 2xx is
/// taken as accepted; anything else is a refusal. A provider that speaks
/// another shape is fronted by a deployment's own adapter.
///
/// The URL is a realm administrator's word, not the operator's, so the dial
/// wears the same guardrails as every outbound call this server makes on
/// somebody else's say-so: the egress policy decides the scheme, the
/// resolver refuses addresses inside the deployment at resolution time, and
/// no redirect is followed out of the checked answer.
pub struct HttpTexter {
    egress: Egress,
}

impl HttpTexter {
    pub fn new(egress: Egress) -> Self {
        HttpTexter { egress }
    }
}

#[async_trait::async_trait]
impl Texter for HttpTexter {
    async fn text(&self, settings: &SmsSettings, text: &Text) -> Result<(), Undelivered> {
        if !may_dial(&settings.url, self.egress) {
            tracing::warn!("an sms gateway url is not one this egress policy dials");
            return Err(Undelivered::Refused);
        }
        let body = serde_json::json!({
            "to": text.to,
            "from": settings.sender,
            "text": text.body,
        });
        let url = settings.url.clone();
        let egress = self.egress;
        let bearer = settings
            .token
            .as_ref()
            .map(|held| secrecy::ExposeSecret::expose_secret(held).clone());
        tokio::task::spawn_blocking(move || {
            let agent = ureq::Agent::with_parts(
                ureq::Agent::config_builder()
                    .timeout_global(Some(PATIENCE))
                    .max_redirects(0)
                    .tls_config(
                        ureq::tls::TlsConfig::builder()
                            .provider(ureq::tls::TlsProvider::NativeTls)
                            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                            .build(),
                    )
                    .build(),
                ureq::unversioned::transport::DefaultConnector::new(),
                Outward(DefaultResolver::default(), egress),
            );
            let mut posting = agent.post(&url);
            if let Some(bearer) = &bearer {
                posting = posting.header("authorization", &format!("Bearer {bearer}"));
            }
            posting
                .header("content-type", "application/json")
                .send(body.to_string())
                .map(|_| ())
                .map_err(|why| {
                    tracing::warn!(why = %why, "a text was not sent");
                    Undelivered::Refused
                })
        })
        .await
        .map_err(|_| Undelivered::Refused)?
    }
}

/// Writes the text to the log instead of sending it.
///
/// For a deployment being built, and named as such where it is chosen. It
/// prints the whole body, one-time code included, which is why it is never
/// what a deployment gets by not choosing.
pub struct LoggedTexter;

#[async_trait::async_trait]
impl Texter for LoggedTexter {
    async fn text(&self, _settings: &SmsSettings, text: &Text) -> Result<(), Undelivered> {
        tracing::warn!(
            to = text.to,
            body = text.body,
            "a text was written to the log and not sent"
        );
        Ok(())
    }
}
