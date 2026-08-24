use secrecy::SecretBox;

/// A realm's mail settings, password included, as the sender needs them.
///
/// Not serialisable: the password is in it, and a struct that can be written
/// out is one that reaches a log or a response by accident.
pub struct MailSettings {
    pub host: String,
    pub port: u16,
    pub from_address: String,
    pub from_name: String,
    pub reply_to: Option<String>,
    /// Implicit TLS wraps the socket; otherwise STARTTLS upgrades it and a
    /// server that refuses to upgrade is a server this build will not talk to.
    pub implicit_tls: bool,
    pub credentials: Option<MailCredentials>,
}

pub struct MailCredentials {
    pub username: String,
    pub password: SecretBox<String>,
}

/// The same settings without the password, which is what a caller may see and
/// what an administrator writes when they are not changing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSettingsView {
    pub host: String,
    pub port: u16,
    pub from_address: String,
    pub from_name: String,
    pub reply_to: Option<String>,
    pub implicit_tls: bool,
    pub username: Option<String>,
}

impl MailSettings {
    /// A copy, password included. Written by hand because a secret is
    /// deliberately not `Clone`: every copy of one is a place it can be left.
    pub fn duplicate(&self) -> Self {
        MailSettings {
            host: self.host.clone(),
            port: self.port,
            from_address: self.from_address.clone(),
            from_name: self.from_name.clone(),
            reply_to: self.reply_to.clone(),
            implicit_tls: self.implicit_tls,
            credentials: self.credentials.as_ref().map(|held| MailCredentials {
                username: held.username.clone(),
                password: SecretBox::new(Box::new(
                    secrecy::ExposeSecret::expose_secret(&held.password).clone(),
                )),
            }),
        }
    }

    pub fn as_view(&self) -> MailSettingsView {
        MailSettingsView {
            host: self.host.clone(),
            port: self.port,
            from_address: self.from_address.clone(),
            from_name: self.from_name.clone(),
            reply_to: self.reply_to.clone(),
            implicit_tls: self.implicit_tls,
            username: self.credentials.as_ref().map(|held| held.username.clone()),
        }
    }
}
