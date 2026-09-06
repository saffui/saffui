use secrecy::SecretBox;

/// A realm's SMS gateway, token included, as the sender needs it.
///
/// Per realm and not per deployment: no gateway covers the continent, so two
/// realms serving two countries route through two providers. The build speaks
/// one wire shape to whatever the URL names; a provider that wants another is
/// fronted by a deployment's own adapter.
///
/// Not serialisable: the token is in it, and a struct that can be written out
/// is one that reaches a log or a response by accident.
pub struct SmsSettings {
    /// Where the gateway listens for a message to carry.
    pub url: String,
    /// The sender name or number the message goes out under.
    pub sender: String,
    /// The bearer the gateway wants, where it wants one.
    pub token: Option<SecretBox<String>>,
}

/// The same settings without the token, which is what a caller may see and
/// what an administrator writes when they are not changing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsSettingsView {
    pub url: String,
    pub sender: String,
    /// Whether a token is held. Not which one, and not how long it is.
    pub has_token: bool,
}

impl SmsSettings {
    /// A copy, token included. Written by hand because a secret is
    /// deliberately not `Clone`: every copy of one is a place it can be left.
    pub fn duplicate(&self) -> Self {
        SmsSettings {
            url: self.url.clone(),
            sender: self.sender.clone(),
            token: self.token.as_ref().map(|held| {
                SecretBox::new(Box::new(secrecy::ExposeSecret::expose_secret(held).clone()))
            }),
        }
    }

    pub fn as_view(&self) -> SmsSettingsView {
        SmsSettingsView {
            url: self.url.clone(),
            sender: self.sender.clone(),
            has_token: self.token.is_some(),
        }
    }
}
