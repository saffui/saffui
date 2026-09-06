use deadpool_postgres::Transaction;
use models::entities::mail::MailSettings;
use models::entities::realm::RealmModel;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undelivered {
    /// The realm names no way to send, so nothing was attempted.
    #[error("this realm names no way to send")]
    NoWayToSend,
    #[error("the message could not be sent")]
    Refused,
}

/// A message and the settings it goes out under, ready to send once whatever
/// produced it has committed.
///
/// Kept apart from the sending on purpose: a transaction held open across a
/// conversation with somebody else's mail server is a pooled connection a slow
/// server takes away from every other request.
pub struct Outgoing {
    pub settings: MailSettings,
    pub message: Message,
    /// Who it is for and what it is for, so the attempt can be recorded
    /// against them. Never the body.
    pub about: About,
}

/// What a receipt says, beyond whether it worked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct About {
    pub user_id: String,
    pub purpose: String,
}

impl std::fmt::Debug for Outgoing {
    /// Named and not shown. The settings hold a password and the body holds
    /// whatever the message was for, which for a sign-in link is the link.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Outgoing(to {})", self.message.to)
    }
}

/// A text and the settings it goes out under, the way `Outgoing` carries a
/// mail: apart from the sending, so nothing holds a transaction open across
/// a conversation with a gateway.
pub struct OutgoingText {
    pub settings: models::entities::sms::SmsSettings,
    pub text: Text,
    /// Who it is for and what it is for, so the attempt can be recorded
    /// against them. Never the body.
    pub about: About,
}

impl std::fmt::Debug for OutgoingText {
    /// Named and not shown. The settings hold a token and the body holds a
    /// one-time code.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutgoingText(to {})", self.text.to)
    }
}

/// Whatever one step produced for sending, whichever wire it takes.
///
/// One channel out of the flow rather than one field per medium: a step
/// produces at most one message, and the caller delivers it after commit
/// without caring which kind it was until the moment it sends.
#[derive(Debug)]
pub enum Outbound {
    Mail(Outgoing),
    Text(OutgoingText),
}

/// What carries a message out.
///
/// The settings are handed in per call rather than held: they belong to a realm
/// and one deployment serves many.
#[async_trait::async_trait]
pub trait Deliver: Send + Sync {
    async fn send(&self, settings: &MailSettings, message: &Message) -> Result<(), Undelivered>;
}

/// A message for a phone: one body, no subject, and a destination that is a
/// number rather than an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    pub to: String,
    pub body: String,
}

/// What carries a text out, the way `Deliver` carries mail.
///
/// A separate trait rather than a channel flag on one: mail and SMS take
/// different settings, and a sender handed the wrong kind should fail to
/// compile rather than fail to send.
#[async_trait::async_trait]
pub trait Texter: Send + Sync {
    async fn text(
        &self,
        settings: &models::entities::sms::SmsSettings,
        text: &Text,
    ) -> Result<(), Undelivered>;
}

/// The words a mail speaks: the realm's rewording where it wrote one, the
/// built words otherwise, with `{{link}}` resolved in both halves.
///
/// The tongue is the realm's default, then English, then whatever the realm
/// wrote first: mail is composed before anyone is signed in to ask, so the
/// realm's own voice is the honest choice.
pub fn worded(
    realm: &models::entities::realm::RealmModel,
    kind: &str,
    link: &str,
    default_subject: &str,
    default_body: &str,
) -> (String, String) {
    let spoken = realm
        .mail_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| {
            realm
                .default_locale
                .as_deref()
                .and_then(|tongue| tongues.get(tongue))
                .or_else(|| tongues.get("en"))
                .or_else(|| tongues.values().next())
        });
    match spoken {
        Some(template) => (
            template.subject.replace("{{link}}", link),
            template.body.replace("{{link}}", link),
        ),
        None => (
            default_subject.replace("{{link}}", link),
            default_body.replace("{{link}}", link),
        ),
    }
}

#[cfg(test)]
mod wording {
    use super::*;
    use models::entities::realm::{MailTemplate, RealmCreateModel};
    use std::collections::HashMap;

    fn realm_with(
        default_locale: Option<&str>,
        templates: &[(&str, &str, &str, &str)],
    ) -> models::entities::realm::RealmModel {
        let mut realm = RealmCreateModel {
            name: "main".into(),
            display_name: "Main".into(),
            enabled: true,
        }
        .into_model(
            "main".into(),
            models::auditable::AuditableModel::from_creator("acme".into(), "test".into()),
        );
        realm.default_locale = default_locale.map(str::to_owned);
        let mut map: HashMap<String, HashMap<String, MailTemplate>> = HashMap::new();
        for (kind, tongue, subject, body) in templates {
            map.entry((*kind).to_owned()).or_default().insert(
                (*tongue).to_owned(),
                MailTemplate {
                    subject: (*subject).to_owned(),
                    body: (*body).to_owned(),
                },
            );
        }
        realm.mail_templates = (!map.is_empty()).then_some(map);
        realm
    }

    /// The realm's words win in its own tongue, English answers when the
    /// default tongue wrote nothing, the built words answer when the realm
    /// wrote nothing at all, and the link lands in every case.
    #[test]
    fn the_realms_words_win_and_the_link_always_lands() {
        let bare = realm_with(None, &[]);
        let (subject, body) = worded(&bare, "magic_link", "https://l", "Built", "Go: {{link}}");
        assert_eq!(subject, "Built");
        assert_eq!(body, "Go: https://l");

        let french = realm_with(
            Some("fr"),
            &[
                ("magic_link", "fr", "Votre lien", "Suivez : {{link}}"),
                ("magic_link", "en", "Your link", "Follow: {{link}}"),
            ],
        );
        let (subject, body) = worded(&french, "magic_link", "https://l", "Built", "{{link}}");
        assert_eq!(subject, "Votre lien");
        assert_eq!(body, "Suivez : https://l");

        let english_only = realm_with(
            Some("fr"),
            &[("magic_link", "en", "Your link", "Follow: {{link}}")],
        );
        let (subject, _) = worded(
            &english_only,
            "magic_link",
            "https://l",
            "Built",
            "{{link}}",
        );
        assert_eq!(
            subject, "Your link",
            "english did not answer for a silent tongue"
        );

        let other_kind = realm_with(Some("fr"), &[("verify_email", "fr", "V", "{{link}}")]);
        let (subject, _) = worded(&other_kind, "magic_link", "https://l", "Built", "{{link}}");
        assert_eq!(subject, "Built", "another kind's words leaked");
    }
}

/// How many texts any one realm sends in a day, until the realm says
/// otherwise: the brake on a billable action an attacker can trigger.
pub const TEXTS_PER_REALM_PER_DAY: i32 = 250;

/// How many texts one number may receive in one hour, until the realm says
/// otherwise: a burst at one number is the shape inflated traffic takes.
pub const TEXTS_PER_NUMBER_PER_HOUR: i32 = 5;

/// Why a text was held back. Said to the sign-in log, never to the caller:
/// what a throttle answers must not say which brake it tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    BlockedPrefix,
    NumberVelocity,
    DayBudget,
}

impl Held {
    fn as_str(self) -> &'static str {
        match self {
            Self::BlockedPrefix => "blocked-prefix",
            Self::NumberVelocity => "number-velocity",
            Self::DayBudget => "day-budget",
        }
    }
}

/// The realm's brakes on one send: a range it never texts, this number's
/// hour, and the realm's day. Checked in the minting transaction, and a
/// throttle is recorded where a failed sign-in is, because a throttle
/// tripping is the fact an operator hunting inflated traffic reads.
pub async fn text_brakes(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    user_id: &str,
    recipient: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Held>, ()> {
    let held = brakes_say(transaction, realm, recipient, now).await?;
    if let Some(held) = held {
        tracing::warn!(brake = held.as_str(), "a text was held back");
        let _ = store::providers::login_events::record(
            transaction,
            now.timestamp(),
            &store::providers::login_events::LoginEventWrite {
                kind: "sms_throttled",
                user_id: Some(user_id),
                detail: Some(serde_json::json!({
                    "brake": held.as_str(),
                    "to": recipient,
                })),
                ..Default::default()
            },
        )
        .await;
    }
    Ok(held)
}

async fn brakes_say(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    recipient: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Held>, ()> {
    if realm
        .sms_blocked_prefixes
        .iter()
        .flatten()
        .any(|prefix| recipient.starts_with(prefix.as_str()))
    {
        return Ok(Some(Held::BlockedPrefix));
    }
    let to_number =
        store::providers::sms::sent_to_number_this_hour(transaction, recipient, now.timestamp())
            .await
            .map_err(|_| ())?;
    if to_number
        >= realm
            .sms_per_number_cap
            .unwrap_or(TEXTS_PER_NUMBER_PER_HOUR)
    {
        return Ok(Some(Held::NumberVelocity));
    }
    let today = store::providers::sms::spent_today(transaction, now.timestamp())
        .await
        .map_err(|_| ())?;
    if today >= realm.sms_daily_cap.unwrap_or(TEXTS_PER_REALM_PER_DAY) {
        return Ok(Some(Held::DayBudget));
    }
    Ok(None)
}

/// Count one send everywhere a brake reads: the realm's day and this
/// number's hour, in the same transaction that minted the code.
pub async fn record_text(
    transaction: &Transaction<'_>,
    recipient: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), ()> {
    store::providers::sms::record_send(transaction, now.timestamp())
        .await
        .map_err(|_| ())?;
    store::providers::sms::record_send_to_number(transaction, recipient, now.timestamp())
        .await
        .map_err(|_| ())
}

/// The words around a code: the realm's rewording where it wrote one, held
/// to a length at the door, and the built words otherwise. Short on purpose:
/// an SMS is billed and truncated by length.
pub fn texted_words(realm: &RealmModel, kind: &str, code: &str) -> String {
    let spoken = realm
        .sms_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| {
            realm
                .default_locale
                .as_deref()
                .and_then(|tongue| tongues.get(tongue))
                .or_else(|| tongues.get("en"))
                .or_else(|| tongues.values().next())
        });
    match spoken {
        Some(body) => body.replace("{{code}}", code),
        None => match (kind, realm.default_locale.as_deref()) {
            ("verify_phone", Some("fr")) => {
                format!("{code} est votre code de vérification. Il expire dans 5 minutes.")
            }
            ("verify_phone", _) => {
                format!("{code} is your verification code. It expires in 5 minutes.")
            }
            (_, Some("fr")) => {
                format!("{code} est votre code de connexion. Il expire dans 5 minutes.")
            }
            (_, _) => format!("{code} is your sign-in code. It expires in 5 minutes."),
        },
    }
}

/// The words around a doorbell link, the same way: the realm's rewording
/// where it wrote one, the built words otherwise, with `{{link}}` resolved.
pub fn texted_link(realm: &models::entities::realm::RealmModel, kind: &str, link: &str) -> String {
    let spoken = realm
        .sms_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| {
            realm
                .default_locale
                .as_deref()
                .and_then(|tongue| tongues.get(tongue))
                .or_else(|| tongues.get("en"))
                .or_else(|| tongues.values().next())
        });
    match spoken {
        Some(body) => body.replace("{{link}}", link),
        None => match realm.default_locale.as_deref() {
            Some("fr") => format!("Une demande de connexion vous attend : {link}"),
            _ => format!("A sign-in request awaits you: {link}"),
        },
    }
}
