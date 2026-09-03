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

pub const NOTIFICATION_ENDPOINT_FLAG: &str = "ciba.notification_endpoint";
/// The user attribute holding the sha256 hex of their user_code, when they
/// set one.
pub const USER_CODE_DIGEST: &str = "ciba.user_code_digest";

#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    Poll,
    /// The client is told at this endpoint when the person has decided.
    Ping {
        endpoint: String,
    },
}

impl Delivery {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Poll => "poll",
            Self::Ping { .. } => "ping",
        }
    }
}

/// How the operator opted this client in, when they did. Ping without an
/// https endpoint is half an opt-in, which is none.
/// The algorithm this client registered for signed backchannel requests,
/// CIBA §7.1: registered, every initiation from it must arrive signed.
pub fn signing_alg_of(client: &ClientModel) -> Option<crypto::provider::SignAlg> {
    client
        .configs
        .as_ref()?
        .get("ciba.request_signing_alg")?
        .as_str()?
        .parse()
        .ok()
}

/// What a login hint token names: the account, or the address, that the
/// client vouches for by signing.
#[derive(Debug)]
pub enum Hinted {
    Subject(String),
    Email(String),
}

/// Open a login hint token, this deployment's shape of CIBA §7.1's
/// structured hint: signed by the client with its published keys, naming
/// `sub` or `email`. A token that cannot be verified is a protocol fault
/// told to the client; a verified token naming nobody is the ghost's
/// business, decided by the caller.
pub fn read_hint_token(
    client: &ClientModel,
    algorithm: crypto::provider::SignAlg,
    token: &str,
) -> Result<Hinted, Unopened> {
    let malformed = |detail: &'static str| Unopened {
        error: "invalid_request",
        detail,
    };
    let keys = client
        .jwks
        .as_ref()
        .ok_or(malformed("this client published no keys"))?;
    let jwk = crate::request_object::key_named(keys, token, algorithm)
        .map_err(|_| malformed("no published key signs this hint"))?;
    let verifier = crate::token::verifier_for(algorithm, &jwk)
        .ok_or(malformed("no published key signs this hint"))?;
    let payload = crypto::jose::jwt::decode_with_verifier(token, &*verifier)
        .map_err(|_| malformed("the hint's signature does not hold"))?
        .0;
    let text = |named: &str| {
        payload
            .claim(named)
            .and_then(Value::as_str)
            .filter(|held| !held.is_empty())
            .map(str::to_owned)
    };
    match (text("sub"), text("email")) {
        (Some(subject), None) => Ok(Hinted::Subject(subject)),
        (None, Some(address)) => Ok(Hinted::Email(address)),
        _ => Err(malformed("the hint names sub or email, one of the two")),
    }
}

/// Open a signed initiation, CIBA §7.1.1: verified against the client's
/// published keys at exactly the algorithm it registered, and the binding
/// claims are required here, not merely honoured when present.
pub fn read_signed_request(
    client: &ClientModel,
    algorithm: crypto::provider::SignAlg,
    token: &str,
    issuer: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Map<String, Value>, Unopened> {
    let malformed = |detail: &'static str| Unopened {
        error: "invalid_request",
        detail,
    };
    let keys = client
        .jwks
        .as_ref()
        .ok_or(malformed("this client published no keys"))?;
    let jwk = crate::request_object::key_named(keys, token, algorithm)
        .map_err(|_| malformed("no published key signs this request"))?;
    let verifier = crate::token::verifier_for(algorithm, &jwk)
        .ok_or(malformed("no published key signs this request"))?;
    let payload = crypto::jose::jwt::decode_with_verifier(token, &*verifier)
        .map_err(|_| malformed("the request's signature does not hold"))?
        .0;

    let text = |named: &str| payload.claim(named).and_then(Value::as_str);
    let instant = |named: &str| payload.claim(named).and_then(Value::as_i64);
    if text("iss") != Some(client.client_id.as_str()) || text("aud") != Some(issuer) {
        return Err(malformed("the request names another client or server"));
    }
    if text("jti").is_none_or(str::is_empty) {
        return Err(malformed("the request carries no identifier"));
    }
    let stamp = now.timestamp();
    match (instant("exp"), instant("nbf"), instant("iat")) {
        (Some(exp), Some(nbf), Some(_)) if stamp <= exp && stamp >= nbf => {}
        _ => return Err(malformed("the request is outside its own window")),
    }
    Ok(payload.claims_set().clone())
}

pub fn delivery_of(client: &ClientModel) -> Option<Delivery> {
    let held = |key: &str| {
        client
            .configs
            .as_ref()
            .and_then(|bag| bag.get(key))
            .and_then(models::entities::attributes::AttributeValue::as_str)
    };
    match held(DELIVERY_FLAG) {
        Some("poll") => Some(Delivery::Poll),
        Some("ping") => {
            let endpoint = held(NOTIFICATION_ENDPOINT_FLAG)?;
            (endpoint.starts_with("https://") || endpoint.starts_with("http://")).then(|| {
                Delivery::Ping {
                    endpoint: endpoint.to_owned(),
                }
            })
        }
        _ => None,
    }
}

pub fn allows_ciba(client: &ClientModel) -> bool {
    delivery_of(client).is_some()
}

/// One identity hint, exactly: a name or address in `login_hint`, or a prior
/// identity token in `id_token_hint`. Two hints are a contradiction waiting
/// to be resolved wrongly, and none is nobody.
#[derive(Debug, PartialEq)]
pub enum Hint {
    Named(String),
    IdToken(String),
    /// CIBA §7.1's structured hint, in this deployment's shape: a token the
    /// client signed with its published keys, naming `sub` or `email`.
    HintToken(String),
}

/// What an initiation asks, read fail-closed.
#[derive(Debug)]
pub struct Asked {
    pub scope: String,
    pub hint: Hint,
    pub binding_message: Option<String>,
    pub expiry: Duration,
}

#[derive(Debug)]
pub struct AskedNotification {
    pub token: Option<String>,
}

pub fn read_initiation(
    scope: Option<&str>,
    login_hint: Option<&str>,
    id_token_hint: Option<&str>,
    login_hint_token: Option<&str>,
    binding_message: Option<&str>,
    requested_expiry: Option<&str>,
    // The realm's lifetime for these requests, when it set one: it becomes
    // both the default and the ceiling, so a client may ask for less, never
    // more. Unset keeps the built default and ceiling.
    realm_expiry: Option<i32>,
) -> Result<Asked, Unopened> {
    let blank = |held: Option<&str>| {
        held.map(str::trim)
            .filter(|it| !it.is_empty())
            .map(str::to_owned)
    };
    let hint = match (
        blank(login_hint),
        blank(id_token_hint),
        blank(login_hint_token),
    ) {
        (Some(named), None, None) => Hint::Named(named),
        (None, Some(token), None) => Hint::IdToken(token),
        (None, None, Some(token)) => Hint::HintToken(token),
        (None, None, None) => {
            return Err(Unopened::invalid(
                "login_hint, login_hint_token or id_token_hint names who signs in",
            ));
        }
        _ => {
            return Err(Unopened::invalid("one hint, not two"));
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
    let (default_expiry, ceiling) = match realm_expiry {
        Some(held) => (i64::from(held), i64::from(held)),
        None => (DEFAULT_EXPIRY, MAX_EXPIRY),
    };
    let expiry = match blank(requested_expiry) {
        None => default_expiry,
        Some(asked) => match asked.parse::<i64>() {
            Ok(seconds) if seconds >= 1 => seconds.min(ceiling),
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

/// Ping mode: the client's own token, required and bounded, §7.1.
pub fn read_notification_token(
    delivery: &Delivery,
    client_notification_token: Option<&str>,
) -> Result<Option<String>, Unopened> {
    let held = client_notification_token
        .map(str::trim)
        .filter(|it| !it.is_empty());
    match delivery {
        Delivery::Poll => Ok(None),
        Delivery::Ping { .. } => match held {
            Some(token) if token.len() <= 1024 => Ok(Some(token.to_owned())),
            Some(_) => Err(Unopened::invalid("client_notification_token is oversized")),
            None => Err(Unopened::invalid(
                "ping delivery carries a client_notification_token",
            )),
        },
    }
}

/// Whether the person's own code stands. A person with no code set has
/// nothing to check; one with a code admits only its match, and the caller
/// turns a miss into a ghost, so nothing is enumerated.
pub fn user_code_stands(
    person_code_digest: Option<&str>,
    offered: Option<&str>,
    digest_hex_of: impl Fn(&str) -> Option<String>,
) -> bool {
    match person_code_digest {
        None => true,
        Some(expected) => offered
            .map(str::trim)
            .filter(|held| !held.is_empty())
            .and_then(digest_hex_of)
            .is_some_and(|hex| hex.eq_ignore_ascii_case(expected)),
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
            delivery: "poll".into(),
            notification_token: None,
            sealed_request: None,
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
            None,
            Some("Virement 240"),
            Some("120"),
            None,
        )
        .expect("a whole ask reads");
        assert_eq!(asked.hint, Hint::Named("ada@example.test".into()));
        assert_eq!(asked.expiry, Duration::seconds(120));

        assert!(
            read_initiation(None, None, None, None, None, None, None).is_err(),
            "no hint held"
        );
        assert!(
            read_initiation(None, Some("ada"), Some("x.y.z"), None, None, None, None).is_err(),
            "two hints held"
        );
        assert_eq!(
            read_initiation(None, None, None, Some("h.i.nt"), None, None, None)
                .unwrap()
                .hint,
            Hint::HintToken("h.i.nt".into())
        );
        // The realm's lifetime is both the default and the ceiling.
        assert_eq!(
            read_initiation(None, Some("ada"), None, None, None, None, Some(90))
                .unwrap()
                .expiry,
            Duration::seconds(90)
        );
        assert_eq!(
            read_initiation(None, Some("ada"), None, None, None, Some("500"), Some(90))
                .unwrap()
                .expiry,
            Duration::seconds(90),
            "a client asked past the realm's ceiling"
        );
        assert_eq!(
            read_initiation(
                None,
                Some("ada"),
                None,
                None,
                Some(&"m".repeat(65)),
                None,
                None
            )
            .unwrap_err()
            .error,
            "invalid_binding_message"
        );
        assert_eq!(
            read_initiation(None, Some("ada"), None, None, None, Some("9999"), None)
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
