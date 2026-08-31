use crypto::provider::SignAlg;
use models::entities::authz::IdentityProviderModel;
use serde_json::Value;

pub const KIND_KEY: &str = "kind";
pub const KIND: &str = "workload";

/// Whether this provider row is a trusted platform rather than a brokered
/// login: the kind lives in the bag, since provider_id is the row's alias.
pub fn is_workload(provider: &IdentityProviderModel) -> bool {
    provider
        .configs
        .as_ref()
        .and_then(|bag| bag.get(KIND_KEY))
        .and_then(models::entities::attributes::AttributeValue::as_str)
        == Some(KIND)
}
pub const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("{0}")]
    Missing(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
}

/// One platform an operator trusts, and the exact border of that trust.
#[derive(Debug, Clone, PartialEq)]
pub struct Trusted {
    pub issuer: String,
    pub jwks_uri: String,
    /// The audience a token must have been minted for. A token asked for
    /// somebody else's exchange does not enter here.
    pub audience: String,
    /// Exact subjects, or prefixes ending in `*`.
    pub subject_patterns: Vec<String>,
    /// The client whose service account the workload acts as.
    pub client_id: String,
    pub allowed_algs: Vec<SignAlg>,
}

impl Trusted {
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, Unusable> {
        let bag = provider
            .configs
            .as_ref()
            .ok_or(Unusable::Missing("a trusted platform names its issuer"))?;
        for key in bag.keys() {
            const KNOWN: [&str; 7] = [
                KIND_KEY,
                "issuer",
                "jwks_uri",
                "audience",
                "subject_patterns",
                "client_id",
                "allowed_algs",
            ];
            if !KNOWN.contains(&key.as_str()) {
                return Err(Unusable::Malformed("the bag holds a key no platform reads"));
            }
        }
        let text = |key: &'static str, said: &'static str| {
            bag.get(key)
                .and_then(models::entities::attributes::AttributeValue::as_str)
                .map(str::trim)
                .filter(|held| !held.is_empty())
                .map(str::to_owned)
                .ok_or(Unusable::Missing(said))
        };
        let jwks_uri = text("jwks_uri", "jwks_uri names where the keys live")?;
        if !jwks_uri.starts_with("https://") && !jwks_uri.starts_with("http://") {
            return Err(Unusable::Malformed("jwks_uri is a url"));
        }
        let patterns: Vec<String> = text(
            "subject_patterns",
            "subject_patterns names which workloads may enter",
        )?
        .split_whitespace()
        .map(str::to_owned)
        .collect();
        if patterns.iter().any(|held| {
            held.strip_suffix('*')
                .is_some_and(|prefix| prefix.is_empty())
        }) {
            return Err(Unusable::Malformed(
                "a bare * would admit every workload the platform has",
            ));
        }
        let allowed_algs = match bag
            .get("allowed_algs")
            .and_then(models::entities::attributes::AttributeValue::as_str)
        {
            None => vec![SignAlg::Rs256],
            Some(named) => {
                let algs: Option<Vec<SignAlg>> = named
                    .split_whitespace()
                    .map(|each| each.parse().ok())
                    .collect();
                algs.filter(|held| !held.is_empty())
                    .ok_or(Unusable::Malformed("allowed_algs names signing algorithms"))?
            }
        };
        Ok(Self {
            issuer: text("issuer", "issuer names the platform")?,
            jwks_uri,
            audience: text("audience", "audience names who the token must be for")?,
            subject_patterns: patterns,
            client_id: text(
                "client_id",
                "client_id names whose powers the workload takes",
            )?,
            allowed_algs,
        })
    }

    pub fn admits(&self, subject: &str) -> bool {
        self.subject_patterns
            .iter()
            .any(|pattern| match pattern.strip_suffix('*') {
                Some(prefix) => subject.starts_with(prefix),
                None => subject == pattern,
            })
    }
}

/// The claims a platform token must carry, checked after its signature.
pub fn asserted_subject(
    trusted: &Trusted,
    claims: &serde_json::Map<String, Value>,
    now: i64,
) -> Result<String, &'static str> {
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss") != Some(trusted.issuer.as_str()) {
        return Err("the issuer is not the trusted one");
    }
    let audience_holds = match claims.get("aud") {
        Some(Value::String(one)) => one == &trusted.audience,
        Some(Value::Array(many)) => many
            .iter()
            .any(|one| one.as_str() == Some(trusted.audience.as_str())),
        _ => false,
    };
    if !audience_holds {
        return Err("the token was minted for somebody else's exchange");
    }
    let seconds = |value: &Value| {
        value
            .as_i64()
            .or_else(|| value.as_f64().map(|held| held as i64))
    };
    match claims.get("exp").and_then(seconds) {
        Some(expires) if expires > now => {}
        _ => return Err("the token is expired or carries no expiry"),
    }
    if let Some(not_before) = claims.get("nbf").and_then(seconds)
        && not_before > now
    {
        return Err("the token is not yet valid");
    }
    let subject = text("sub")
        .filter(|held| !held.is_empty())
        .ok_or("no subject")?;
    if !trusted.admits(subject) {
        return Err("the workload is outside the trusted patterns");
    }
    Ok(subject.to_owned())
}

/// The unverified issuer, read only to pick which trusted platform to check
/// the token against. Nothing is believed until the signature holds.
pub fn peeked_issuer(assertion: &str) -> Option<String> {
    let mut pieces = assertion.split('.');
    let payload = pieces.nth(1)?;
    let decoded = data_encoding::BASE64URL_NOPAD
        .decode(payload.as_bytes())
        .ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    claims["iss"].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;
    use serde_json::json;

    fn provider(bag: &[(&str, &str)]) -> IdentityProviderModel {
        IdentityProviderModel {
            internal_id: "wif".into(),
            realm_id: "main".into(),
            provider_id: "the-forge".into(),
            name: "github".into(),
            display_name: String::new(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: Some(
                bag.iter()
                    .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).into())))
                    .collect(),
            ),
            metadata: AuditableModel::from_creator("acme".into(), "root".into()),
        }
    }

    fn whole() -> IdentityProviderModel {
        provider(&[
            ("kind", "workload"),
            ("issuer", "https://token.actions.githubusercontent.com"),
            (
                "jwks_uri",
                "https://token.actions.githubusercontent.com/.well-known/jwks",
            ),
            ("audience", "https://id.example/realms/main"),
            (
                "subject_patterns",
                "repo:acme/api:ref:refs/heads/main repo:acme/tools:*",
            ),
            ("client_id", "deployer"),
        ])
    }

    #[test]
    fn a_bag_parses_whole_and_the_border_holds() {
        let trusted = Trusted::parse(&whole()).expect("a whole bag parses");
        assert!(trusted.admits("repo:acme/api:ref:refs/heads/main"));
        assert!(!trusted.admits("repo:acme/api:ref:refs/heads/feature"));
        assert!(trusted.admits("repo:acme/tools:ref:refs/tags/v1"));
        assert!(!trusted.admits("repo:intruder/api:ref:refs/heads/main"));
        assert_eq!(trusted.allowed_algs, vec![SignAlg::Rs256]);

        assert!(Trusted::parse(&provider(&[("issuer", "x")])).is_err());
        assert!(
            Trusted::parse(&provider(&[
                ("issuer", "https://x"),
                ("jwks_uri", "https://x/jwks"),
                ("audience", "a"),
                ("subject_patterns", "*"),
                ("client_id", "c"),
            ]))
            .is_err(),
            "a bare star held"
        );
    }

    #[test]
    fn the_claims_are_held_to_the_line() {
        let trusted = Trusted::parse(&whole()).unwrap();
        let now = 1_000_000;
        let good = json!({
            "iss": "https://token.actions.githubusercontent.com",
            "aud": "https://id.example/realms/main",
            "sub": "repo:acme/api:ref:refs/heads/main",
            "exp": now + 300,
        });
        assert_eq!(
            asserted_subject(&trusted, good.as_object().unwrap(), now).unwrap(),
            "repo:acme/api:ref:refs/heads/main"
        );
        for (broken, _named) in [
            (
                json!({ "iss": "https://elsewhere", "aud": "https://id.example/realms/main", "sub": "repo:acme/api:ref:refs/heads/main", "exp": now + 300 }),
                "issuer",
            ),
            (
                json!({ "iss": "https://token.actions.githubusercontent.com", "aud": "sts.amazonaws.com", "sub": "repo:acme/api:ref:refs/heads/main", "exp": now + 300 }),
                "audience",
            ),
            (
                json!({ "iss": "https://token.actions.githubusercontent.com", "aud": "https://id.example/realms/main", "sub": "repo:acme/api:ref:refs/heads/main", "exp": now - 1 }),
                "expiry",
            ),
            (
                json!({ "iss": "https://token.actions.githubusercontent.com", "aud": "https://id.example/realms/main", "sub": "repo:fork/api:ref:refs/heads/main", "exp": now + 300 }),
                "pattern",
            ),
        ] {
            assert!(
                asserted_subject(&trusted, broken.as_object().unwrap(), now).is_err(),
                "{broken}"
            );
        }
    }
}
