use models::entities::authz::IdentityProviderModel;

pub const KIND: &str = "webhook";
pub const CLEAR_SECRET: &str = "secret";
pub const SEALED_SECRET: &str = "secret_sealed";

#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("{0}")]
    Missing(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
}

pub fn is_webhook(provider: &IdentityProviderModel) -> bool {
    provider
        .configs
        .as_ref()
        .and_then(|bag| bag.get("kind"))
        .and_then(models::entities::attributes::AttributeValue::as_str)
        == Some(KIND)
}

/// One subscribed listener: where it lives and which kinds it asked for.
/// The secret never rides here; it is opened beside the delivery, once.
#[derive(Debug, Clone, PartialEq)]
pub struct Webhook {
    pub url: String,
    filter: Vec<String>,
}

impl Webhook {
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, Unusable> {
        let bag = provider
            .configs
            .as_ref()
            .ok_or(Unusable::Missing("a webhook names its url"))?;
        for key in bag.keys() {
            const KNOWN: [&str; 5] = ["kind", "url", "filter", CLEAR_SECRET, SEALED_SECRET];
            if !KNOWN.contains(&key.as_str()) {
                return Err(Unusable::Malformed("the bag holds a key no webhook reads"));
            }
        }
        let held = |key: &str| {
            bag.get(key)
                .and_then(models::entities::attributes::AttributeValue::as_str)
                .map(str::trim)
                .filter(|held| !held.is_empty())
        };
        let url = held("url")
            .ok_or(Unusable::Missing("a webhook names its url"))?
            .to_owned();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(Unusable::Malformed("a webhook url is http(s)"));
        }
        // The filter is spelled, never defaulted: a listener that wants
        // everything says `*`, so a forgotten filter is a refusal rather
        // than a firehose nobody asked for.
        let filter: Vec<String> = held("filter")
            .ok_or(Unusable::Missing("a webhook names the kinds it wants"))?
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if !bag.contains_key(CLEAR_SECRET) && !bag.contains_key(SEALED_SECRET) {
            return Err(Unusable::Missing("a webhook carries a signing secret"));
        }
        Ok(Webhook { url, filter })
    }

    /// Whether this listener asked for the kind: the capability grammar,
    /// exact or a prefix ending in `*`, and `*` alone deliberately admits
    /// everything, because a spelled firehose is an honest subscription.
    pub fn wants(&self, kind: &str) -> bool {
        self.filter
            .iter()
            .any(|held| crate::capability::admits(held, kind))
    }
}

/// The signature a delivery carries: HMAC-SHA256 over the exact body, in
/// the header form consumers already know from every webhook they hold.
pub fn signature(
    provider: &dyn crypto::provider::CryptoProvider,
    secret: &str,
    body: &[u8],
) -> Option<String> {
    let key = secrecy::SecretBox::new(Box::new(secret.as_bytes().to_vec()));
    let mac = provider
        .hmac()
        .hmac(crypto::provider::HmacAlg::Hs256, &key, body)
        .ok()?;
    Some(format!("sha256={}", data_encoding::HEXLOWER.encode(&mac)))
}

#[cfg(test)]
mod tests {
    use models::auditable::AuditableModel;
    use models::entities::attributes::{AttributeValue, AttributesMap};

    use super::*;

    fn provider(bag: &[(&str, &str)]) -> IdentityProviderModel {
        let mut configs = AttributesMap::default();
        for (key, value) in bag {
            configs.insert((*key).to_owned(), AttributeValue::Str((*value).to_owned()));
        }
        IdentityProviderModel {
            internal_id: "w-1".into(),
            realm_id: "r".into(),
            provider_id: "hooks".into(),
            name: "hooks".into(),
            display_name: String::new(),
            description: String::new(),
            enabled: Some(true),
            trust_email: None,
            configs: Some(configs),
            metadata: AuditableModel::from_creator("t".into(), "test".into()),
        }
    }

    /// Whole or not at all: a missing url, a missing filter, a missing
    /// secret, or a stray key each refuse the row rather than running half
    /// a subscription.
    #[test]
    fn a_webhook_parses_whole_or_refuses_whole() {
        let whole = provider(&[
            ("kind", KIND),
            ("url", "https://siem.example/hook"),
            ("filter", "user.* session.revoked"),
            (CLEAR_SECRET, "a-secret-of-decent-length"),
        ]);
        let parsed = Webhook::parse(&whole).unwrap();
        assert_eq!(parsed.url, "https://siem.example/hook");

        for broken in [
            provider(&[("kind", KIND), ("filter", "*"), (CLEAR_SECRET, "s")]),
            provider(&[("kind", KIND), ("url", "https://a"), (CLEAR_SECRET, "s")]),
            provider(&[("kind", KIND), ("url", "https://a"), ("filter", "*")]),
            provider(&[
                ("kind", KIND),
                ("url", "ftp://a"),
                ("filter", "*"),
                (CLEAR_SECRET, "s"),
            ]),
            provider(&[
                ("kind", KIND),
                ("url", "https://a"),
                ("filter", "*"),
                (CLEAR_SECRET, "s"),
                ("stray", "x"),
            ]),
        ] {
            assert!(Webhook::parse(&broken).is_err());
        }
    }

    /// The capability grammar, plus the one divergence: `*` alone admits
    /// everything here, because a subscription to everything is a thing a
    /// SIEM honestly asks for.
    #[test]
    fn the_filter_admits_by_the_readers_grammar() {
        let hook = |filter: &str| {
            Webhook::parse(&provider(&[
                ("kind", KIND),
                ("url", "https://a"),
                ("filter", filter),
                (CLEAR_SECRET, "s"),
            ]))
            .unwrap()
        };
        let narrow = hook("user.* session.revoked");
        assert!(narrow.wants("user.created"));
        assert!(narrow.wants("session.revoked"));
        assert!(!narrow.wants("credential.changed"));
        assert!(hook("*").wants("credential.changed"));
    }
}
