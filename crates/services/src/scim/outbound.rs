use models::entities::authz::IdentityProviderModel;

pub const KIND: &str = "scim-outbound";
pub const CLEAR_BEARER: &str = "bearer";
pub const SEALED_BEARER: &str = "bearer_sealed";

#[derive(Debug, thiserror::Error)]
pub enum Unusable {
    #[error("{0}")]
    Missing(&'static str),
    #[error("{0}")]
    Malformed(&'static str),
}

pub fn is_outbound(provider: &IdentityProviderModel) -> bool {
    provider
        .configs
        .as_ref()
        .and_then(|bag| bag.get("kind"))
        .and_then(models::entities::attributes::AttributeValue::as_str)
        == Some(KIND)
}

/// One application this realm provisions into: its SCIM root, and the
/// bearer it expects, sealed at rest.
#[derive(Debug, Clone, PartialEq)]
pub struct Connector {
    pub base_url: String,
}

impl Connector {
    pub fn parse(provider: &IdentityProviderModel) -> Result<Self, Unusable> {
        let bag = provider
            .configs
            .as_ref()
            .ok_or(Unusable::Missing("a connector names its SCIM root"))?;
        for key in bag.keys() {
            const KNOWN: [&str; 4] = ["kind", "base_url", CLEAR_BEARER, SEALED_BEARER];
            if !KNOWN.contains(&key.as_str()) {
                return Err(Unusable::Malformed(
                    "the bag holds a key no connector reads",
                ));
            }
        }
        let base_url = bag
            .get("base_url")
            .and_then(models::entities::attributes::AttributeValue::as_str)
            .map(str::trim)
            .filter(|held| !held.is_empty())
            .ok_or(Unusable::Missing("base_url names the SCIM root"))?
            .trim_end_matches('/')
            .to_owned();
        if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
            return Err(Unusable::Malformed("base_url is a url"));
        }
        Ok(Self { base_url })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::attributes::AttributeValue;

    #[test]
    fn a_connector_parses_whole_or_refuses_whole() {
        let mut provider = IdentityProviderModel {
            internal_id: "out".into(),
            realm_id: "main".into(),
            provider_id: "mirror".into(),
            name: "mirror".into(),
            display_name: String::new(),
            description: String::new(),
            enabled: Some(true),
            trust_email: Some(false),
            configs: Some(
                [
                    ("kind", KIND),
                    ("base_url", "https://apps.example/scim/v2/"),
                    ("bearer_sealed", "…"),
                ]
                .into_iter()
                .map(|(key, value)| (key.to_owned(), AttributeValue::Str(value.into())))
                .collect(),
            ),
            metadata: AuditableModel::from_creator("acme".into(), "root".into()),
        };
        assert_eq!(
            Connector::parse(&provider).unwrap().base_url,
            "https://apps.example/scim/v2"
        );
        provider
            .configs
            .as_mut()
            .unwrap()
            .insert("stray".into(), AttributeValue::Str("x".into()));
        assert!(Connector::parse(&provider).is_err());
    }
}
