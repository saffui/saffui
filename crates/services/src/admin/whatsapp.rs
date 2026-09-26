use crypto::envelope::Envelope;
use models::entities::whatsapp::WhatsAppSettings;
use secrecy::SecretBox;
use store::keyring::RealmKeyring;
use store::providers::realms::whatsapp;
use store::tenancy::UnitOfWork;

/// Meta approves a template in some seventy languages; a list past that is
/// not one it could have approved.
const LANGUAGES_AT_MOST: usize = 70;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("this realm has no WhatsApp settings")]
    NotFound,
    #[error("the phone number id is the digits Meta shows for the business number")]
    NotANumberId,
    #[error("a template name is lowercase letters, digits and underscores")]
    NotATemplate,
    #[error("the languages are the codes Meta approved the template in, like en_US or fr")]
    NotALanguage,
    #[error("Meta wants a token on every call, so one is needed")]
    NoToken,
    #[error("the settings could not be read or written")]
    Unwritable,
}

pub async fn read(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> Result<WhatsAppSettings, Unsettable> {
    whatsapp::load(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .ok_or(Unsettable::NotFound)
}

/// What an administrator wrote. A token left out keeps the one held.
pub struct Wanted {
    pub phone_number_id: String,
    pub template: String,
    pub languages: Vec<String>,
    pub token: Option<String>,
}

pub async fn write(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    wanted: Wanted,
) -> Result<(), Unsettable> {
    let phone_number_id = wanted.phone_number_id.trim().to_owned();
    if phone_number_id.is_empty()
        || phone_number_id.len() > 32
        || !phone_number_id.bytes().all(|held| held.is_ascii_digit())
    {
        return Err(Unsettable::NotANumberId);
    }
    let template = wanted.template.trim().to_owned();
    if template.is_empty()
        || template.len() > 512
        || !template
            .bytes()
            .all(|held| held.is_ascii_lowercase() || held.is_ascii_digit() || held == b'_')
    {
        return Err(Unsettable::NotATemplate);
    }
    let mut languages: Vec<String> = Vec::new();
    for asked in &wanted.languages {
        let language = asked.trim();
        if !is_a_language_code(language) {
            return Err(Unsettable::NotALanguage);
        }
        if !languages.iter().any(|held| held == language) {
            languages.push(language.to_owned());
        }
    }
    if languages.is_empty() || languages.len() > LANGUAGES_AT_MOST {
        return Err(Unsettable::NotALanguage);
    }
    let token = match wanted.token {
        Some(token) if token.trim().is_empty() => return Err(Unsettable::NoToken),
        Some(token) => SecretBox::new(Box::new(token)),
        None => {
            whatsapp::load(transaction, ring, envelope)
                .await
                .map_err(|_| Unsettable::Unwritable)?
                .ok_or(Unsettable::NoToken)?
                .token
        }
    };

    whatsapp::keep(
        transaction,
        ring,
        envelope,
        &WhatsAppSettings {
            phone_number_id,
            template,
            languages,
            token,
        },
    )
    .await
    .map_err(|_| Unsettable::Unwritable)
}

pub async fn forget(transaction: &UnitOfWork) -> Result<(), Unsettable> {
    whatsapp::forget(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .then_some(())
        .ok_or(Unsettable::NotFound)
}

/// A language as Meta spells one: two or three lowercase letters, and a
/// region after an underscore where the template names one (`en_US`, `fr`,
/// `pt_BR`).
fn is_a_language_code(code: &str) -> bool {
    let (language, region) = match code.split_once('_') {
        Some((language, region)) => (language, Some(region)),
        None => (code, None),
    };
    (2..=3).contains(&language.len())
        && language.bytes().all(|held| held.is_ascii_lowercase())
        && region.is_none_or(|region| {
            (2..=4).contains(&region.len()) && region.bytes().all(|held| held.is_ascii_alphabetic())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes a template is approved in pass, and a person's tag written
    /// the browser's way, or anything with room for markup, does not.
    #[test]
    fn a_language_is_spelled_the_way_meta_spells_it() {
        for held in ["en", "fr", "en_US", "pt_BR", "zh_HK", "fil"] {
            assert!(is_a_language_code(held), "{held} was refused");
        }
        for refused in [
            "", "e", "english", "en-US", "EN_us", "en_", "_US", "en_US_x", "fr<",
        ] {
            assert!(!is_a_language_code(refused), "{refused} was taken");
        }
    }
}
