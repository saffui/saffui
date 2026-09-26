use secrecy::SecretBox;

/// A realm's WhatsApp sender, token included, as the sender needs it.
///
/// Meta's own settings rather than a gateway's: one network carries every
/// WhatsApp message, so there is no address to name, only which business
/// number speaks and which approved template it speaks with.
///
/// Not serialisable, for the reason `SmsSettings` is not.
pub struct WhatsAppSettings {
    /// The id Meta gives the business number, not the number itself.
    pub phone_number_id: String,
    /// The approved authentication template.
    pub template: String,
    /// The languages the template was approved in, spelled the way Meta
    /// spells them. Never empty.
    pub languages: Vec<String>,
    /// A system user's token. Meta wants one on every call.
    pub token: SecretBox<String>,
}

/// The same settings without the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhatsAppSettingsView {
    pub phone_number_id: String,
    pub template: String,
    pub languages: Vec<String>,
}

impl WhatsAppSettings {
    /// A copy, token included. Written by hand because a secret is
    /// deliberately not `Clone`: every copy of one is a place it can be left.
    pub fn duplicate(&self) -> Self {
        WhatsAppSettings {
            phone_number_id: self.phone_number_id.clone(),
            template: self.template.clone(),
            languages: self.languages.clone(),
            token: SecretBox::new(Box::new(
                secrecy::ExposeSecret::expose_secret(&self.token).clone(),
            )),
        }
    }

    pub fn as_view(&self) -> WhatsAppSettingsView {
        WhatsAppSettingsView {
            phone_number_id: self.phone_number_id.clone(),
            template: self.template.clone(),
            languages: self.languages.clone(),
        }
    }
}
