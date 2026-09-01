use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::authz::IdentityProviderModel;
use serde_json::{Value, json};

pub const KIND: &str = "caep-push";

pub const SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
pub const CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
pub const ACCOUNT_DISABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
pub const ACCOUNT_PURGED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-purged";

#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("{0}")]
    Missing(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
}

pub fn is_receiver(provider: &IdentityProviderModel) -> bool {
    provider
        .configs
        .as_ref()
        .and_then(|bag| bag.get("kind"))
        .and_then(models::entities::attributes::AttributeValue::as_str)
        == Some(KIND)
}

/// How a receiver takes delivery: told at its endpoint the moment something
/// happens (RFC 8935), or collecting from this transmitter when it likes
/// (RFC 8936).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Push,
    Poll,
}

/// One receiver of this realm's Security Event Tokens: how it takes them,
/// where when pushed, under which audience, and which events it asked for.
/// The bearer on the bag rides sealed, like the outbound connector's: pushed
/// with, or presented back by a collector as its credential.
#[derive(Debug, Clone, PartialEq)]
pub struct Receiver {
    pub delivery: Delivery,
    /// Where a push lands. A collector names none.
    pub endpoint: Option<String>,
    pub audience: String,
    /// Empty means everything this transmitter emits.
    pub events: Vec<String>,
}

impl Receiver {
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, Unusable> {
        let bag = provider
            .configs
            .as_ref()
            .ok_or(Unusable::Missing("a receiver names its endpoint"))?;
        for key in bag.keys() {
            const KNOWN: [&str; 7] = [
                "kind",
                "delivery",
                "endpoint",
                "audience",
                "events",
                crate::outbound::CLEAR_BEARER,
                crate::outbound::SEALED_BEARER,
            ];
            if !KNOWN.contains(&key.as_str()) {
                return Err(Unusable::Malformed("the bag holds a key no receiver reads"));
            }
        }
        let read = |key: &str| {
            bag.get(key)
                .and_then(models::entities::attributes::AttributeValue::as_str)
                .map(str::trim)
                .filter(|held| !held.is_empty())
                .map(str::to_owned)
        };
        let delivery = match read("delivery").as_deref() {
            None | Some("push") => Delivery::Push,
            Some("poll") => Delivery::Poll,
            Some(_) => return Err(Unusable::Malformed("delivery is push or poll")),
        };
        let endpoint = match delivery {
            Delivery::Push => {
                let named = read("endpoint").ok_or(Unusable::Missing(
                    "endpoint names where the events are pushed",
                ))?;
                if !named.starts_with("https://") && !named.starts_with("http://") {
                    return Err(Unusable::Malformed("endpoint is a url"));
                }
                Some(named)
            }
            // A collector comes to this transmitter; an endpoint on it would
            // be a place nothing is ever sent.
            Delivery::Poll => match read("endpoint") {
                None => None,
                Some(_) => {
                    return Err(Unusable::Malformed("a collector names no endpoint"));
                }
            },
        };
        let events: Vec<String> = read("events")
            .map(|held| {
                held.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if events.iter().any(|named| {
            ![
                SESSION_REVOKED,
                CREDENTIAL_CHANGE,
                ACCOUNT_DISABLED,
                ACCOUNT_PURGED,
            ]
            .contains(&named.as_str())
        }) {
            return Err(Unusable::Malformed(
                "events names an event this transmitter does not emit",
            ));
        }
        let audience = match read("audience") {
            Some(named) => named,
            None => endpoint
                .clone()
                .ok_or(Unusable::Missing("a collector names its audience"))?,
        };
        Ok(Self {
            delivery,
            audience,
            endpoint,
            events,
        })
    }

    pub fn wants(&self, uri: &str) -> bool {
        self.events.is_empty() || self.events.iter().any(|named| named == uri)
    }
}

/// What an outbox happening says to the outside, if anything.
///
/// A person appearing or changing while enabled is provisioning traffic, not a
/// security signal, so those map to nothing here; the connectors already carry
/// them. Disabling and deletion are the two account signals RISC names, and
/// sessions and credentials map to their CAEP words.
pub fn security_event(kind: &str, payload: &Value) -> Option<(&'static str, Value)> {
    match kind {
        store::providers::outbox::SESSION_REVOKED => Some((SESSION_REVOKED, json!({}))),
        store::providers::outbox::CREDENTIAL_CHANGED => Some((
            CREDENTIAL_CHANGE,
            json!({ "credential_type": payload["credential_type"] }),
        )),
        store::providers::outbox::USER_DELETED => Some((ACCOUNT_PURGED, json!({}))),
        store::providers::outbox::USER_UPDATED if payload["enabled"] == json!(false) => {
            Some((ACCOUNT_DISABLED, json!({ "reason": "disabled" })))
        }
        _ => None,
    }
}

/// A Security Event Token for one receiver, signed with the realm's preferred
/// key: the one the realm's published set already carries, so a receiver
/// verifies it the way it verifies an identity token.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one event"
)]
pub async fn minted_set(
    transaction: &Transaction<'_>,
    signing: &crate::grant::Signing<'_>,
    issuer: &str,
    receiver: &Receiver,
    event: &store::providers::outbox::OutboxEvent,
    uri: &str,
    body: Value,
    now: DateTime<Utc>,
) -> Result<crate::token::issuance::Minted, crate::grant::Ungranted> {
    let key =
        crate::grant::preferred_key(transaction, signing, crypto::provider::SignAlg::Rs256).await?;
    let mut extra = serde_json::Map::new();
    extra.insert(
        "sub_id".into(),
        json!({ "format": "iss_sub", "iss": issuer, "sub": event.user_id }),
    );
    let mut told = body;
    told["event_timestamp"] = json!(now.timestamp());
    extra.insert("events".into(), json!({ uri: told }));
    crate::token::issuance::mint_token(
        signing.provider,
        &key,
        crate::token::issuance::Minting {
            bound_to: None,
            certified_by: None,
            kind: crate::token::issuance::Kind::SecurityEvent,
            issuer,
            subject: &event.user_id,
            audiences: vec![receiver.audience.clone()],
            party: "",
            session_id: "",
            scope: "",
            // Long enough for a collector that comes by on its own schedule;
            // a pushed one is verified the moment it lands.
            lifespan: chrono::Duration::hours(24),
            now,
            extra,
        },
    )
    .map_err(|_| crate::grant::Ungranted::Unmintable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;

    fn receiver_row(pairs: &[(&str, &str)]) -> IdentityProviderModel {
        IdentityProviderModel {
            internal_id: "in".into(),
            realm_id: "main".into(),
            provider_id: "watcher".into(),
            name: "watcher".into(),
            display_name: String::new(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: Some(
                pairs
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).into())))
                    .collect(),
            ),
            metadata: AuditableModel::from_creator("acme".into(), "root".into()),
        }
    }

    #[test]
    fn a_receiver_parses_whole_or_refuses_whole() {
        let whole = receiver_row(&[
            ("kind", KIND),
            ("endpoint", "https://apps.example/events "),
            ("events", SESSION_REVOKED),
        ]);
        let parsed = Receiver::parse(&whole).unwrap();
        assert_eq!(
            parsed.endpoint.as_deref(),
            Some("https://apps.example/events")
        );
        assert_eq!(parsed.audience, "https://apps.example/events");
        assert!(parsed.wants(SESSION_REVOKED));
        assert!(!parsed.wants(ACCOUNT_PURGED));

        let unfiltered = receiver_row(&[("kind", KIND), ("endpoint", "https://apps.example/e")]);
        assert!(Receiver::parse(&unfiltered).unwrap().wants(ACCOUNT_PURGED));

        // A collector names no endpoint and must say who it is instead.
        let collector = receiver_row(&[
            ("kind", KIND),
            ("delivery", "poll"),
            ("audience", "https://collector.example"),
        ]);
        let parsed = Receiver::parse(&collector).unwrap();
        assert_eq!(parsed.delivery, Delivery::Poll);
        assert!(parsed.endpoint.is_none());
        for broken in [
            receiver_row(&[("kind", KIND), ("delivery", "poll")]),
            receiver_row(&[
                ("kind", KIND),
                ("delivery", "poll"),
                ("audience", "a"),
                ("endpoint", "https://x"),
            ]),
            receiver_row(&[
                ("kind", KIND),
                ("delivery", "carrier-pigeon"),
                ("audience", "a"),
            ]),
        ] {
            assert!(Receiver::parse(&broken).is_err());
        }

        for broken in [
            receiver_row(&[("kind", KIND)]),
            receiver_row(&[("kind", KIND), ("endpoint", "ftp://x")]),
            receiver_row(&[("kind", KIND), ("endpoint", "https://x"), ("stray", "y")]),
            receiver_row(&[
                ("kind", KIND),
                ("endpoint", "https://x"),
                ("events", "made-up"),
            ]),
        ] {
            assert!(Receiver::parse(&broken).is_err());
        }
    }

    #[test]
    fn only_security_signals_become_events() {
        use serde_json::json;
        let quiet = json!({ "enabled": true });
        assert!(security_event("user.created", &quiet).is_none());
        assert!(security_event("user.updated", &quiet).is_none());
        assert_eq!(
            security_event("user.updated", &json!({ "enabled": false }))
                .unwrap()
                .0,
            ACCOUNT_DISABLED
        );
        assert_eq!(
            security_event("user.deleted", &quiet).unwrap().0,
            ACCOUNT_PURGED
        );
        assert_eq!(
            security_event("session.revoked", &quiet).unwrap().0,
            SESSION_REVOKED
        );
        assert_eq!(
            security_event(
                "credential.changed",
                &json!({ "credential_type": "password" })
            )
            .unwrap()
            .1["credential_type"],
            "password"
        );
    }
}
