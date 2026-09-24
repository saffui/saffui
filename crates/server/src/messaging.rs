use std::time::Duration;

use auth::messaging::{Deliver, Message, Text, Texter, Undelivered};
use config::serving::Egress;

use lettre::message::Mailbox;
use lettre::message::{MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message as Letter, SmtpTransport, Transport};
use models::entities::mail::MailSettings;
use models::entities::sms::SmsSettings;
use outbound::egress::{may_dial, outward_agent};
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
        .subject(&message.subject);
    if let Some(reply_to) = &settings.reply_to {
        building = building.reply_to(reply_to.parse().map_err(|_| Undelivered::Refused)?);
    }
    // Both halves, text first. An alternative is read last part first, so a
    // client that draws HTML draws it and one that does not falls back to
    // exactly what this build has always sent.
    building
        .multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(message.body.clone()))
                .singlepart(SinglePart::html(message.html.clone())),
        )
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
///
/// An operator names this one rather than a realm, but it is dialled under the
/// same guardrails as every other outbound call: the egress policy decides the
/// scheme, the resolver refuses addresses inside the deployment, and no
/// redirect is followed out of the answer that was checked.
pub struct Webhook {
    url: String,
    bearer: Option<String>,
    egress: Egress,
}

impl Webhook {
    pub fn new(url: String, bearer: Option<String>, egress: Egress) -> Self {
        Webhook {
            url,
            bearer,
            egress,
        }
    }
}

#[async_trait::async_trait]
impl Deliver for Webhook {
    async fn send(&self, settings: &MailSettings, message: &Message) -> Result<(), Undelivered> {
        if !may_dial(&self.url, self.egress) {
            tracing::warn!("a message webhook url is not one this egress policy dials");
            return Err(Undelivered::Refused);
        }
        let body = serde_json::json!({
            "to": message.to,
            "from": settings.from_address,
            "subject": message.subject,
            "text": message.body,
        });
        let (url, bearer, egress) = (self.url.clone(), self.bearer.clone(), self.egress);
        tokio::task::spawn_blocking(move || {
            let agent = outward_agent(egress, PATIENCE);
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
            let agent = outward_agent(egress, PATIENCE);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> MailSettings {
        MailSettings {
            host: "smtp.example.test".to_owned(),
            port: 587,
            from_address: "noreply@example.test".to_owned(),
            from_name: "saffui".to_owned(),
            reply_to: None,
            implicit_tls: false,
            credentials: None,
        }
    }

    /// The last link nothing else covers. Everything above this weighs the two
    /// halves as values; this weighs the letter they are actually packed into,
    /// which is what a relay is handed.
    #[test]
    fn a_letter_is_packed_with_both_halves_and_the_text_one_first() {
        let message = Message::to(
            "ada@example.test",
            auth::messaging::told("Hello", "Plain words.\n"),
        );
        let built = compose(&settings(), &message).expect("a letter");
        let raw = String::from_utf8_lossy(&built.formatted()).into_owned();

        assert!(raw.contains("multipart/alternative"), "{raw}");
        assert!(raw.contains("text/plain"), "{raw}");
        assert!(raw.contains("text/html"), "{raw}");
        // An alternative is read last part first, so the text has to come
        // before the HTML for a client that draws HTML to prefer it.
        let text_at = raw.find("text/plain").expect("the text half");
        let html_at = raw.find("text/html").expect("the other half");
        assert!(
            text_at < html_at,
            "the halves are the wrong way round: {raw}"
        );
    }
}
