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
