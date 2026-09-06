use crate::ConfigError;

const SINK: &str = "MESSAGE_SINK";
const WEBHOOK_URL: &str = "MESSAGE_WEBHOOK_URL";

/// How this deployment sends.
///
/// No default. A deployment that has not said refuses to send, so whatever
/// needed a message fails rather than a sign-in link reaching a log nobody
/// meant to put one in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sink {
    /// Nothing sends. Anything that needs a message says so and stops.
    None,
    /// The SMTP server each realm names.
    Smtp,
    /// A gateway of the deployment's own, told over HTTP.
    Webhook { url: String },
    /// Written to the log rather than sent. For a deployment being built.
    Logged,
}

impl Sink {
    pub fn from_env() -> Result<Self, ConfigError> {
        match crate::optional(SINK).as_deref() {
            None | Some("none") => Ok(Sink::None),
            Some("smtp") => Ok(Sink::Smtp),
            Some("log") => Ok(Sink::Logged),
            Some("webhook") => Ok(Sink::Webhook {
                url: crate::required(WEBHOOK_URL)?,
            }),
            Some(_) => Err(ConfigError::Invalid {
                key: format!("{}{SINK}", crate::PREFIX),
                expected: "none, smtp, webhook or log".to_owned(),
            }),
        }
    }
}

const TEXT_SINK: &str = "SMS_SINK";

/// How this deployment sends SMS.
///
/// No default, for the reason mail has none. There is no URL here: the
/// gateway is each realm's own setting, so the deployment only says whether
/// texts go to it, to the log, or nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextSink {
    /// Nothing sends. Anything that needs a text says so and stops.
    None,
    /// The HTTP gateway each realm names.
    Http,
    /// Written to the log rather than sent. For a deployment being built.
    Logged,
}

impl TextSink {
    pub fn from_env() -> Result<Self, ConfigError> {
        match crate::optional(TEXT_SINK).as_deref() {
            None | Some("none") => Ok(TextSink::None),
            Some("http") => Ok(TextSink::Http),
            Some("log") => Ok(TextSink::Logged),
            Some(_) => Err(ConfigError::Invalid {
                key: format!("{}{TEXT_SINK}", crate::PREFIX),
                expected: "none, http or log".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{clear, env_guard, set};

    #[test]
    fn a_text_sink_is_named_or_nothing_sends() {
        let _guard = env_guard();
        clear(&[TEXT_SINK]);
        assert_eq!(TextSink::from_env().unwrap(), TextSink::None);
        set(TEXT_SINK, "http");
        assert_eq!(TextSink::from_env().unwrap(), TextSink::Http);
        set(TEXT_SINK, "carrier-pigeon");
        assert!(TextSink::from_env().is_err());
        clear(&[TEXT_SINK]);
    }

    #[test]
    fn absent_sends_nothing_and_a_webhook_needs_somewhere_to_post() {
        let _guard = env_guard();
        clear(&[SINK, WEBHOOK_URL]);
        assert_eq!(Sink::from_env().unwrap(), Sink::None);

        set(SINK, "smtp");
        assert_eq!(Sink::from_env().unwrap(), Sink::Smtp);

        set(SINK, "webhook");
        assert!(
            Sink::from_env().is_err(),
            "a webhook with no url was accepted"
        );
        set(WEBHOOK_URL, "https://gateway.example/send");
        assert_eq!(
            Sink::from_env().unwrap(),
            Sink::Webhook {
                url: "https://gateway.example/send".to_owned()
            }
        );

        set(SINK, "smoke-signal");
        assert!(Sink::from_env().is_err());
        clear(&[SINK, WEBHOOK_URL]);
    }
}
