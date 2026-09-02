use models::entities::mail::MailSettings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undelivered {
    /// The realm names no way to send, so nothing was attempted.
    #[error("this realm has no mail settings")]
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

/// What carries a message out.
///
/// The settings are handed in per call rather than held: they belong to a realm
/// and one deployment serves many.
#[async_trait::async_trait]
pub trait Deliver: Send + Sync {
    async fn send(&self, settings: &MailSettings, message: &Message) -> Result<(), Undelivered>;
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
