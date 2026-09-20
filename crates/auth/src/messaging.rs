use deadpool_postgres::Transaction;
use models::entities::attributes;
use models::entities::mail::MailSettings;
use models::entities::realm::RealmModel;
use models::entities::user::{UserModel, profile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub to: String,
    pub subject: String,
    /// The text half, which is what this build has always sent.
    pub body: String,
    /// The same words laid out, sent beside the text rather than instead of
    /// it, so a reader whose client shows text loses nothing.
    pub html: String,
}

impl Message {
    /// A letter for one reader, in both halves at once.
    ///
    /// The only way a message is made, so nothing can compose one and leave a
    /// half behind.
    pub fn to(reader: &str, worded: Worded) -> Self {
        Message {
            to: reader.to_owned(),
            subject: worded.subject,
            body: worded.text,
            html: worded.html,
        }
    }
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
    reader: Option<&str>,
    said: &[(&str, &str)],
) -> Worded {
    let spoken = realm
        .mail_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| pick_wording(tongues, reader, realm.default_locale.as_deref()));
    let tongue = choose_tongue(reader, realm.default_locale.as_deref());
    let (subject, body) = match spoken {
        Some(template) => (template.subject.as_str(), template.body.as_str()),
        None => built_words(kind, tongue),
    };
    put_in(kind, tongue, subject, body, link, said)
}

/// This build's own words for one kind of mail, in one tongue. A realm that
/// wrote nothing is answered from here rather than from its caller, so the
/// same sentence is not spelled once per place that sends it.
/// One wording, put into both halves.
///
/// The letter is written from the wording BEFORE anything is put in, so the
/// marker is still standing where it stands and the layout knows where the
/// button goes. The single place a `Worded` is made, so the two halves cannot
/// be written from different words.
pub fn put_in(
    kind: &str,
    tongue: Tongue,
    subject: &str,
    body: &str,
    link: &str,
    said: &[(&str, &str)],
) -> Worded {
    Worded {
        subject: filled(subject, link, said),
        text: filled(body, link, said),
        html: crate::letter::written(subject, body, link, said, button_words(kind, tongue)),
    }
}

/// The realm's own words for a kind, in a tongue this reader can read.
///
/// Opened for the messages this build assembles rather than looks up: a notice
/// has no fixed wording to fall back to, so it does the lookup itself and
/// composes its own default. The walk is the same one every other message
/// takes, so a realm's tongues are chosen the same way everywhere.
pub fn reworded<'a>(
    realm: &'a models::entities::realm::RealmModel,
    kind: &str,
    reader: Option<&str>,
) -> Option<&'a models::entities::realm::MailTemplate> {
    realm
        .mail_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| pick_wording(tongues, reader, realm.default_locale.as_deref()))
}

/// A letter with nothing to press: the notices that only tell somebody what
/// happened, and name no link at all.
pub fn told(subject: &str, body: &str) -> Worded {
    Worded {
        subject: subject.to_owned(),
        text: body.to_owned(),
        html: crate::letter::written(subject, body, "", &[], ""),
    }
}

/// The build's own wording for a kind, where no realm row says otherwise.
pub fn built(kind: &str, tongue: Tongue, link: &str, said: &[(&str, &str)]) -> Worded {
    let (subject, body) = built_words(kind, tongue);
    put_in(kind, tongue, subject, body, link, said)
}

/// What the button on a letter says, by what the letter is for.
///
/// A label rather than a bare address: a reader is told what pressing it does
/// before they press it, which is the whole difference between a letter and a
/// lure. A kind nobody wrote a label for gets the plain one.
pub fn button_words(kind: &str, tongue: Tongue) -> &'static str {
    match (kind, tongue) {
        ("magic_link", Tongue::French) => "Se connecter",
        ("magic_link", _) => "Sign in",
        ("verify_email" | "verify_phone", Tongue::French) => "Confirmer l'adresse",
        ("verify_email" | "verify_phone", _) => "Confirm the address",
        ("reset_password", Tongue::French) => "Choisir un mot de passe",
        ("reset_password", _) => "Set a password",
        (_, Tongue::French) => "Continuer",
        (_, _) => "Continue",
    }
}

/// A message in both halves it is sent in.
///
/// One value rather than two calls: the halves are written from the same words
/// at the same moment, so nothing can compose a letter and forget one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worded {
    pub subject: String,
    /// What this build has always sent, unchanged.
    pub text: String,
    pub html: String,
}

pub fn built_words(kind: &str, tongue: Tongue) -> (&'static str, &'static str) {
    match (kind, tongue) {
        ("magic_link", Tongue::French) => (
            "Votre lien de connexion",
            "Suivez ce lien pour vous connecter. Il ne sert qu'une fois, et \
             seulement dans le navigateur d'où vous êtes parti.\n\n{{link}}\n",
        ),
        ("verify_email", Tongue::French) => (
            "Confirmez votre adresse",
            "Confirmez cette adresse pour terminer. Le lien ne sert \
             qu'une fois.\n\n{{link}}\n",
        ),
        ("reset_password", Tongue::French) => (
            "Choisissez un nouveau mot de passe",
            "Quelqu'un a demandé un nouveau mot de passe pour ce compte. Si ce \
             n'était pas vous, rien n'a changé et vous pouvez ignorer ce \
             message.\n\n{{link}}\n",
        ),
        ("subject_request", Tongue::French) => (
            "Confirmez votre demande",
            "Quelqu'un a demandé d'agir sur les données personnelles de ce \
             compte ({{kind}}). Si c'était vous, suivez le lien pour confirmer. \
             Sinon, rien ne se passe sans lui.\n\n{{link}}\n",
        ),
        ("verify_email", _) => (
            "Confirm your address",
            "Confirm this address to finish. The link works \
             once.\n\n{{link}}\n",
        ),
        ("reset_password", _) => (
            "Set a new password",
            "Somebody asked to set a new password for this account. If it was \
             not you, nothing has changed and you can ignore this.\n\n{{link}}\n",
        ),
        ("subject_request", _) => (
            "Confirm your privacy request",
            "Somebody asked us to act on the personal data of this account \
             ({{kind}}). If it was you, follow the link to confirm the request. \
             If not, nothing happens without it.\n\n{{link}}\n",
        ),
        // The sign-in link, and also what a kind this build cannot name is
        // answered with: the door admits four kinds, so nothing reaches here
        // by accident, and a mail nobody can name is still one somebody waits
        // for.
        (_, _) => (
            "Your sign-in link",
            "Follow this link to sign in. It works once, and only in the \
             browser you started from.\n\n{{link}}\n",
        ),
    }
}

/// What a privacy request is called, in the tongue the message is written in.
pub fn worded_kind(kind: &str, tongue: Tongue) -> &'static str {
    match (kind, tongue) {
        ("access", Tongue::French) => "accès",
        ("rectification", Tongue::French) => "rectification",
        ("erasure", Tongue::French) => "effacement",
        ("objection", Tongue::French) => "opposition",
        ("portability", Tongue::French) => "portabilité",
        ("access", _) => "access",
        ("rectification", _) => "rectification",
        ("erasure", _) => "erasure",
        ("objection", _) => "objection",
        ("portability", _) => "portability",
        (_, Tongue::French) => "demande",
        (_, _) => "request",
    }
}

/// One text with its link and whatever else it names put in. Names are
/// written `{{like-this}}` and a name nothing supplies is left standing.
fn filled(text: &str, link: &str, said: &[(&str, &str)]) -> String {
    let mut whole = text.replace("{{link}}", link);
    for (name, value) in said {
        whole = whole.replace(&format!("{{{{{name}}}}}"), value);
    }
    whole
}

/// The two tongues this build writes its own words in. A realm may file a
/// template under any tag; these are what answers when it filed none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tongue {
    English,
    French,
}

/// The tongue a message is written in: the person's where it is one of the two
/// spoken here, the realm's otherwise, English when neither says.
pub fn choose_tongue(person: Option<&str>, realm: Option<&str>) -> Tongue {
    [person, realm]
        .into_iter()
        .flatten()
        .find_map(|asked| {
            match asked
                .split(['-', '_'])
                .next()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("fr") => Some(Tongue::French),
                Some("en") => Some(Tongue::English),
                _ => None,
            }
        })
        .unwrap_or(Tongue::English)
}

/// The tongue a person says they read, as they wrote it. Any tag, because a
/// realm's own template may be filed under one this build does not speak.
pub fn tongue_spoken_by(person: &UserModel) -> Option<&str> {
    person
        .attributes
        .as_ref()
        .and_then(|held| attributes::string_at(held, profile::LOCALE))
}

#[cfg(test)]
mod tongues {
    use super::*;

    /// A message is written in the person's tongue where it is one of the two
    /// spoken here, the realm's otherwise, English when neither says.
    #[test]
    fn the_person_is_answered_before_the_realm_and_english_answers_last() {
        assert_eq!(choose_tongue(Some("fr-FR"), Some("en")), Tongue::French);
        assert_eq!(choose_tongue(Some("EN_us"), Some("fr")), Tongue::English);
        assert_eq!(choose_tongue(Some("de"), Some("fr")), Tongue::French);
        assert_eq!(choose_tongue(None, Some("fr")), Tongue::French);
        assert_eq!(choose_tongue(Some("de"), None), Tongue::English);
        assert_eq!(choose_tongue(None, None), Tongue::English);
    }
}

/// The wording filed under one tongue, compared without regard to case: a map
/// filed under `pt-BR` answers a realm whose tongue is written `pt-br`.
fn wording_in<'a, T>(
    tongues: &'a std::collections::HashMap<String, T>,
    wanted: &str,
) -> Option<&'a T> {
    fn language(tag: &str) -> String {
        tag.split(['-', '_'])
            .next()
            .unwrap_or(tag)
            .to_ascii_lowercase()
    }
    tongues
        .iter()
        .find(|(held, _)| held.eq_ignore_ascii_case(wanted))
        .or_else(|| {
            // A person says `fr-CA` where a realm filed `fr`, so the language
            // answers where the exact tag does not. First by name, so two
            // regional filings cannot answer in turn.
            let asked = language(wanted);
            tongues
                .iter()
                .filter(|(held, _)| language(held) == asked)
                .min_by(|(one, _), (other, _)| one.cmp(other))
        })
        .map(|(_, wording)| wording)
}

/// The one wording a realm's map answers with: its own tongue, then English,
/// then the first by name.
fn pick_wording<'a, T>(
    tongues: &'a std::collections::HashMap<String, T>,
    reader: Option<&str>,
    realm: Option<&str>,
) -> Option<&'a T> {
    reader
        .and_then(|tongue| wording_in(tongues, tongue))
        .or_else(|| realm.and_then(|tongue| wording_in(tongues, tongue)))
        .or_else(|| wording_in(tongues, "en"))
        .or_else(|| {
            // A map hands its entries back in no order of its own, so a realm
            // holding several tongues and naming none would answer a different
            // language from one run to the next.
            tongues
                .iter()
                .min_by(|(one, _), (other, _)| one.cmp(other))
                .map(|(_, wording)| wording)
        })
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
        let held = worded(&bare, "magic_link", "https://l", None, &[]);
        let (subject, body) = (held.subject, held.text);
        assert_eq!(subject, "Your sign-in link");
        assert!(
            body.ends_with("https://l\n"),
            "the link did not land: {body}"
        );

        let french = realm_with(
            Some("fr"),
            &[
                ("magic_link", "fr", "Votre lien", "Suivez : {{link}}"),
                ("magic_link", "en", "Your link", "Follow: {{link}}"),
            ],
        );
        let held = worded(&french, "magic_link", "https://l", None, &[]);
        let (subject, body) = (held.subject, held.text);
        assert_eq!(subject, "Votre lien");
        assert_eq!(body, "Suivez : https://l");

        let english_only = realm_with(
            Some("fr"),
            &[("magic_link", "en", "Your link", "Follow: {{link}}")],
        );
        let subject = worded(&english_only, "magic_link", "https://l", None, &[]).subject;
        assert_eq!(
            subject, "Your link",
            "english did not answer for a silent tongue"
        );

        let other_kind = realm_with(Some("fr"), &[("verify_email", "fr", "V", "{{link}}")]);
        let subject = worded(&other_kind, "magic_link", "https://l", None, &[]).subject;
        assert_eq!(
            subject, "Votre lien de connexion",
            "another kind's words leaked, or the realm's own tongue was ignored"
        );
    }

    fn texting_realm(
        default_locale: Option<&str>,
        templates: &[(&str, &str, &str)],
    ) -> models::entities::realm::RealmModel {
        let mut realm = realm_with(default_locale, &[]);
        let mut map: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (kind, tongue, body) in templates {
            map.entry((*kind).to_owned())
                .or_default()
                .insert((*tongue).to_owned(), (*body).to_owned());
        }
        realm.sms_templates = (!map.is_empty()).then_some(map);
        realm
    }

    /// A realm holding several tongues and naming none answers the same one on
    /// every run, and a tongue answers whatever case it was filed under. The
    /// realm is built afresh each turn because a map seeds its own order.
    #[test]
    fn the_tongue_that_answers_is_chosen_and_not_drawn() {
        for _ in 0..20 {
            let unnamed = realm_with(
                None,
                &[
                    ("magic_link", "sv", "Svenska", "{{link}}"),
                    ("magic_link", "de", "Deutsch", "{{link}}"),
                    ("magic_link", "fr", "Francais", "{{link}}"),
                ],
            );
            let subject = worded(&unnamed, "magic_link", "https://l", None, &[]).subject;
            assert_eq!(
                subject, "Deutsch",
                "the tongue was drawn rather than chosen"
            );
        }

        let cased = realm_with(
            Some("pt-br"),
            &[
                ("magic_link", "de", "Deutsch", "{{link}}"),
                ("magic_link", "pt-BR", "Portugues", "{{link}}"),
            ],
        );
        let subject = worded(&cased, "magic_link", "https://l", None, &[]).subject;
        assert_eq!(subject, "Portugues", "case kept a realm from its own words");
    }

    /// What the person reads outranks what the realm reads, for the realm's
    /// own templates and for this build's words alike.
    #[test]
    fn the_person_outranks_the_realm_in_both_kinds_of_wording() {
        let realm = realm_with(
            Some("en"),
            &[
                ("magic_link", "en", "Your link", "Follow: {{link}}"),
                ("magic_link", "fr", "Votre lien", "Suivez : {{link}}"),
            ],
        );
        let subject = worded(&realm, "magic_link", "https://l", Some("fr-CA"), &[]).subject;
        assert_eq!(
            subject, "Votre lien",
            "the realm's tongue beat the reader's"
        );
        let subject = worded(&realm, "magic_link", "https://l", None, &[]).subject;
        assert_eq!(
            subject, "Your link",
            "a silent reader did not fall to the realm"
        );

        // An exact filing outranks the bare language, so a realm that took the
        // trouble to separate two regions is not flattened back into one.
        let regional = realm_with(
            None,
            &[
                ("magic_link", "pt", "Portugues", "{{link}}"),
                ("magic_link", "pt-BR", "Brasileiro", "{{link}}"),
            ],
        );
        let subject = worded(&regional, "magic_link", "https://l", Some("pt-BR"), &[]).subject;
        assert_eq!(subject, "Brasileiro", "the region was flattened away");
        let subject = worded(&regional, "magic_link", "https://l", Some("pt-PT"), &[]).subject;
        assert_eq!(
            subject, "Portugues",
            "an unfiled region did not fall back to its language"
        );

        // Nothing written by the realm, so this build answers, and it answers
        // in the tongue the person reads rather than the one the realm names.
        let silent = realm_with(Some("en"), &[]);
        let held = worded(&silent, "reset_password", "https://l", Some("fr"), &[]);
        let (subject, body) = (held.subject, held.text);
        assert_eq!(subject, "Choisissez un nouveau mot de passe");
        assert!(
            body.contains("mot de passe"),
            "built words came out English: {body}"
        );
        let subject = worded(&silent, "reset_password", "https://l", None, &[]).subject;
        assert_eq!(subject, "Set a new password");
    }

    /// A name beyond the link is put in, and one nothing supplies is left
    /// standing rather than blanked.
    #[test]
    fn a_named_value_beyond_the_link_is_put_in() {
        let silent = realm_with(None, &[]);
        let body = worded(
            &silent,
            "subject_request",
            "https://l",
            Some("fr"),
            &[("kind", worded_kind("erasure", Tongue::French))],
        )
        .text;
        assert!(
            body.contains("(effacement)"),
            "the request was not named: {body}"
        );
        let body = worded(&silent, "subject_request", "https://l", Some("fr"), &[]).text;
        assert!(
            body.contains("{{kind}}"),
            "an unsupplied name was blanked: {body}"
        );
    }

    /// The texts pick their tongue by the rule the mails pick theirs by.
    #[test]
    fn a_text_picks_its_tongue_the_way_a_mail_does() {
        for _ in 0..20 {
            let unnamed = texting_realm(
                None,
                &[
                    ("sms_otp", "sv", "Svenska {{code}}"),
                    ("sms_otp", "de", "Deutsch {{code}}"),
                ],
            );
            assert_eq!(
                texted_words(&unnamed, "sms_otp", "123456", None),
                "Deutsch 123456",
                "the tongue was drawn rather than chosen"
            );
        }

        let cased = texting_realm(
            Some("pt-br"),
            &[
                ("sms_otp", "de", "Deutsch {{code}}"),
                ("sms_otp", "pt-BR", "Portugues {{code}}"),
            ],
        );
        assert_eq!(
            texted_words(&cased, "sms_otp", "123456", None),
            "Portugues 123456"
        );
    }

    /// Both halves are written from one wording at one moment, so a letter
    /// cannot say one thing to a client that draws HTML and another to a
    /// client that does not.
    #[test]
    fn the_two_halves_of_a_letter_say_the_same_thing() {
        let realm = realm_with(None, &[]);
        let held = worded(&realm, "magic_link", "https://saffui.example/go", None, &[]);

        assert!(!held.text.is_empty() && !held.html.is_empty());
        // The text half is text. Were the two ever to cross, a reader whose
        // client shows no HTML would be handed the markup itself.
        assert!(
            !held.text.contains('<') && !held.text.contains("&amp;"),
            "the text half carries markup: {}",
            held.text
        );
        assert!(held.html.starts_with("<!doctype html>"), "{}", held.html);
        assert!(
            held.html.contains(&held.subject),
            "the subject is not on the letter"
        );
        // Every word of the text half, punctuation aside, is on the other.
        for word in held
            .text
            .split_whitespace()
            .filter(|held| held.len() > 4 && !held.starts_with("http"))
        {
            assert!(
                held.html.contains(word),
                "`{word}` is in the text half and not in the other:\n{}",
                held.html
            );
        }
        // And the address is a button rather than a line of text.
        assert!(
            held.html.contains("href=\"https://saffui.example/go\""),
            "{}",
            held.html
        );
    }

    /// The halves keep their sides. Crossing them would hand a reader whose
    /// client shows no HTML the markup itself, and hand a client that draws
    /// HTML a wall of plain text.
    #[test]
    fn a_message_carries_each_half_on_its_own_side() {
        let realm = realm_with(None, &[]);
        let worded = worded(&realm, "magic_link", "https://saffui.example/go", None, &[]);
        let held = Message::to("ada@example.test", worded);

        assert_eq!(held.to, "ada@example.test");
        assert!(
            !held.body.contains('<'),
            "the text side carries markup: {}",
            held.body
        );
        assert!(held.html.starts_with("<!doctype html>"), "{}", held.html);
        assert_ne!(held.body, held.html);
    }

    /// A notice names no link, so its letter has nothing to press, and the
    /// words still cross.
    #[test]
    fn a_letter_with_nothing_to_press_still_carries_its_words() {
        let held = told(
            "Your password changed",
            "It changed a moment ago.\n\nIf that was not you, tell your administrator.\n",
        );
        assert!(!held.html.contains("href="), "{}", held.html);
        assert!(
            held.html.contains("tell your administrator"),
            "{}",
            held.html
        );
        assert_eq!(
            held.text,
            "It changed a moment ago.\n\nIf that was not you, tell your administrator.\n"
        );
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
pub fn texted_words(realm: &RealmModel, kind: &str, code: &str, reader: Option<&str>) -> String {
    let spoken = realm
        .sms_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| pick_wording(tongues, reader, realm.default_locale.as_deref()));
    match spoken {
        Some(body) => body.replace("{{code}}", code),
        None => match (kind, choose_tongue(reader, realm.default_locale.as_deref())) {
            ("verify_phone", Tongue::French) => {
                format!("{code} est votre code de vérification. Il expire dans 5 minutes.")
            }
            ("verify_phone", _) => {
                format!("{code} is your verification code. It expires in 5 minutes.")
            }
            (_, Tongue::French) => {
                format!("{code} est votre code de connexion. Il expire dans 5 minutes.")
            }
            (_, _) => format!("{code} is your sign-in code. It expires in 5 minutes."),
        },
    }
}

/// The words around a doorbell link, the same way: the realm's rewording
/// where it wrote one, the built words otherwise, with `{{link}}` resolved.
pub fn texted_link(
    realm: &models::entities::realm::RealmModel,
    kind: &str,
    link: &str,
    reader: Option<&str>,
) -> String {
    let spoken = realm
        .sms_templates
        .as_ref()
        .and_then(|held| held.get(kind))
        .and_then(|tongues| pick_wording(tongues, reader, realm.default_locale.as_deref()));
    match spoken {
        Some(body) => body.replace("{{link}}", link),
        None => match choose_tongue(reader, realm.default_locale.as_deref()) {
            Tongue::French => format!("Une demande de connexion vous attend : {link}"),
            Tongue::English => format!("A sign-in request awaits you: {link}"),
        },
    }
}
