use chrono::{DateTime, Duration, Utc};
use models::entities::backchannel::{BackchannelRequestModel, BackchannelState};
use models::entities::client::ClientModel;
use serde_json::Value;

pub const GRANT: &str = "urn:openid:params:grant-type:ciba";
/// The client bag key opting a client in, naming its delivery mode. Poll is
/// the one mode this build delivers.
pub const DELIVERY_FLAG: &str = "ciba.delivery_mode";

pub const DEFAULT_EXPIRY: i64 = 300;
pub const MAX_EXPIRY: i64 = 600;
pub const POLL_INTERVAL: i32 = 5;
const BINDING_MESSAGE_CEILING: usize = 64;

/// Why an initiation is refused, in RFC 6749 §5.2 words.
#[derive(Debug, PartialEq)]
pub struct Unopened {
    pub error: &'static str,
    pub detail: &'static str,
}

impl Unopened {
    fn invalid(detail: &'static str) -> Self {
        Self {
            error: "invalid_request",
            detail,
        }
    }
}

/// Whether the operator opted this client into the decoupled flow, and into
/// the one delivery mode this build speaks.
pub fn allows_ciba(client: &ClientModel) -> bool {
    matches!(
        client
            .configs
            .as_ref()
            .and_then(|bag| bag.get(DELIVERY_FLAG))
            .and_then(models::entities::attributes::AttributeValue::as_str),
        Some("poll")
    )
}

/// One identity hint, exactly: a name or address in `login_hint`, or a prior
/// identity token in `id_token_hint`. Two hints are a contradiction waiting
/// to be resolved wrongly, and none is nobody.
#[derive(Debug, PartialEq)]
pub enum Hint {
    Named(String),
    IdToken(String),
}

/// What an initiation asks, read fail-closed.
#[derive(Debug)]
pub struct Asked {
    pub scope: String,
    pub hint: Hint,
    pub binding_message: Option<String>,
    pub expiry: Duration,
}

pub fn read_initiation(
    scope: Option<&str>,
    login_hint: Option<&str>,
    id_token_hint: Option<&str>,
    binding_message: Option<&str>,
    requested_expiry: Option<&str>,
) -> Result<Asked, Unopened> {
    let blank = |held: Option<&str>| {
        held.map(str::trim)
            .filter(|it| !it.is_empty())
            .map(str::to_owned)
    };
    let hint = match (blank(login_hint), blank(id_token_hint)) {
        (Some(named), None) => Hint::Named(named),
        (None, Some(token)) => Hint::IdToken(token),
        (Some(_), Some(_)) => {
            return Err(Unopened::invalid("one hint, not two"));
        }
        (None, None) => {
            return Err(Unopened::invalid(
                "login_hint or id_token_hint names who signs in",
            ));
        }
    };
    let binding_message = blank(binding_message);
    if binding_message
        .as_ref()
        .is_some_and(|held| held.chars().count() > BINDING_MESSAGE_CEILING)
    {
        return Err(Unopened {
            error: "invalid_binding_message",
            detail: "the binding message is for a small screen",
        });
    }
    let expiry = match blank(requested_expiry) {
        None => DEFAULT_EXPIRY,
        Some(asked) => match asked.parse::<i64>() {
            Ok(seconds) if seconds >= 1 => seconds.min(MAX_EXPIRY),
            _ => return Err(Unopened::invalid("requested_expiry is a positive number")),
        },
    };
    Ok(Asked {
        scope: blank(scope).unwrap_or_else(|| "openid".to_owned()),
        hint,
        binding_message,
        expiry: Duration::seconds(expiry),
    })
}

/// Where a poll stands, in the protocol's own words.
#[derive(Debug, PartialEq)]
pub enum Polled {
    /// Mint: the person said yes, and this is the one collection.
    Approved,
    Pending,
    SlowDown,
    Denied,
    Expired,
    /// Unknown, replayed, or another client's: one face.
    Gone,
}

impl Polled {
    pub fn error(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Approved => None,
            Self::Pending => Some(("authorization_pending", "nobody has decided yet")),
            Self::SlowDown => Some(("slow_down", "poll at the interval you were given")),
            Self::Denied => Some(("access_denied", "the person declined")),
            Self::Expired => Some(("expired_token", "the request expired undecided")),
            Self::Gone => Some(("invalid_grant", "no such request stands")),
        }
    }
}

/// Fold one poll against the row, before anything is minted. The caller
/// stamps the poll; this reads the stamps.
pub fn polled(
    request: Option<&BackchannelRequestModel>,
    client_id: &str,
    previous_poll: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Polled {
    let Some(request) = request else {
        return Polled::Gone;
    };
    if request.client_id != client_id {
        return Polled::Gone;
    }
    if request.expires_at <= now {
        return Polled::Expired;
    }
    match request.state {
        BackchannelState::Denied => Polled::Denied,
        BackchannelState::Approved => Polled::Approved,
        BackchannelState::Pending => {
            let hammered = previous_poll.is_some_and(|last| {
                now.signed_duration_since(last).num_seconds() < i64::from(request.interval_secs)
            });
            if hammered {
                Polled::SlowDown
            } else {
                Polled::Pending
            }
        }
    }
}

/// One pending request as the person's device shows it: what they need to
/// recognise the operation, and nothing that lets the device impersonate
/// the client.
pub fn shown_pending(digest: &[u8], request: &BackchannelRequestModel) -> Value {
    serde_json::json!({
        "request": data_encoding::BASE64URL_NOPAD.encode(digest),
        "client_id": request.client_id,
        "scope": request.scope,
        "binding_message": request.binding_message,
        "expires_at": request.expires_at.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(state: BackchannelState, interval: i32) -> BackchannelRequestModel {
        BackchannelRequestModel {
            tenant: "acme".into(),
            realm_id: "main".into(),
            client_id: "app".into(),
            user_id: Some("ada".into()),
            scope: "openid".into(),
            binding_message: None,
            state,
            interval_secs: interval,
            last_polled_at: None,
            approved_at: None,
            expires_at: Utc::now() + Duration::seconds(300),
            created_at: None,
        }
    }

    #[test]
    fn an_initiation_reads_whole_or_refuses_whole() {
        let asked = read_initiation(
            Some("openid profile"),
            Some(" ada@example.test "),
            None,
            Some("Virement 240"),
            Some("120"),
        )
        .expect("a whole ask reads");
        assert_eq!(asked.hint, Hint::Named("ada@example.test".into()));
        assert_eq!(asked.expiry, Duration::seconds(120));

        assert!(
            read_initiation(None, None, None, None, None).is_err(),
            "no hint held"
        );
        assert!(
            read_initiation(None, Some("ada"), Some("x.y.z"), None, None).is_err(),
            "two hints held"
        );
        assert_eq!(
            read_initiation(None, Some("ada"), None, Some(&"m".repeat(65)), None)
                .unwrap_err()
                .error,
            "invalid_binding_message"
        );
        assert_eq!(
            read_initiation(None, Some("ada"), None, None, Some("9999"))
                .unwrap()
                .expiry,
            Duration::seconds(MAX_EXPIRY),
            "the ceiling did not hold"
        );
    }

    #[test]
    fn a_poll_folds_to_the_protocol_words() {
        let now = Utc::now();
        assert_eq!(polled(None, "app", None, now), Polled::Gone);
        assert_eq!(
            polled(
                Some(&request(BackchannelState::Pending, 5)),
                "other",
                None,
                now
            ),
            Polled::Gone,
            "another client read somebody's request"
        );
        assert_eq!(
            polled(
                Some(&request(BackchannelState::Pending, 5)),
                "app",
                None,
                now
            ),
            Polled::Pending
        );
        assert_eq!(
            polled(
                Some(&request(BackchannelState::Pending, 5)),
                "app",
                Some(now - Duration::seconds(2)),
                now
            ),
            Polled::SlowDown
        );
        assert_eq!(
            polled(
                Some(&request(BackchannelState::Pending, 5)),
                "app",
                Some(now - Duration::seconds(6)),
                now
            ),
            Polled::Pending
        );
        assert_eq!(
            polled(
                Some(&request(BackchannelState::Denied, 5)),
                "app",
                None,
                now
            ),
            Polled::Denied
        );
        let mut stale = request(BackchannelState::Approved, 5);
        stale.expires_at = now - Duration::seconds(1);
        assert_eq!(
            polled(Some(&stale), "app", None, now),
            Polled::Expired,
            "an expired approval still minted"
        );
    }
}
