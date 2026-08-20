//! Where this deployment answers from, and the issuer built out of it.
//!
//! `iss` is the one string an IAM can never change, since every relying party
//! compares it byte for byte. Keycloak carried an `/auth` prefix on everything
//! and dropping it in 17 made every deployment rewrite its issuer, so this one
//! is `{origin}/realms/{realm}` and carries no product name and no version.

use crate::ConfigError;

const ORIGIN: &str = "PUBLIC_ORIGIN";
const LOGIN_UI: &str = "LOGIN_UI_URL";

/// Where a browser is sent to authenticate.
///
/// Not served here. The login screens are an application of their own, and this
/// server's job is to say which login is being answered, not to render it.
///
/// Optional, and absent means interactive login cannot start. A default would be
/// a URL nobody chose, which is worse than a refusal that names the setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginUi(Option<String>);

impl LoginUi {
    pub fn from_env() -> Result<Self, ConfigError> {
        match crate::optional(LOGIN_UI) {
            None => Ok(LoginUi(None)),
            Some(named) => match PublicOrigin::parse(&named) {
                Some(_) => Ok(LoginUi(Some(named.trim().trim_end_matches('/').to_owned()))),
                None => Err(ConfigError::Invalid {
                    key: format!("{}{LOGIN_UI}", crate::PREFIX),
                    expected: "absolute http(s) url".to_owned(),
                }),
            },
        }
    }

    /// Build from a value from anywhere, for a test that mounts a plane.
    pub fn parse(value: &str) -> Option<Self> {
        PublicOrigin::parse(value).map(|origin| LoginUi(Some(origin.as_str().to_owned())))
    }

    /// Where a login is answered, or nothing when none is configured.
    ///
    /// No identifier in it. Which login is being answered rides in a cookie,
    /// because a URL reaches logs, `Referer` headers and history.
    pub fn answering(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// Where callers reach this deployment. Not the listen address: behind a proxy
/// that is a port nobody dials, and an issuer built from it is one no client can
/// discover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicOrigin(String);

impl PublicOrigin {
    /// Required rather than defaulted. A guess here is not a wrong hostname for
    /// one request, it is the issuer baked into every token this deployment ever
    /// mints, and those tokens outlive the correction.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::parse(&crate::required(ORIGIN)?).ok_or_else(|| ConfigError::Invalid {
            key: format!("{}{ORIGIN}", crate::PREFIX),
            expected: "absolute http(s) origin, no query and no fragment".to_owned(),
        })
    }

    /// A trailing slash is dropped rather than refused: `https://host/` and
    /// `https://host` are one origin to an operator and two issuers to a relying
    /// party.
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim().trim_end_matches('/');
        let rest = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))?;

        // A query or a fragment would land inside every issuer built from this.
        let usable = !rest.is_empty()
            && !rest.starts_with('/')
            && !rest.contains(['?', '#', ' ', '\t'])
            && !rest.contains("//");
        usable.then(|| PublicOrigin(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// What a token minted for this realm states as its issuer. The protocol
    /// paths under it are published by discovery and may move; this one is
    /// quoted in every token in flight.
    pub fn issuer(&self, realm_id: &str) -> String {
        format!("{}/realms/{realm_id}", self.0)
    }

    /// The realm an issuer names, when this deployment minted it.
    ///
    /// The prefix check is the point: without it `iss` is a string the gate
    /// routes on and nobody verifies, so anything ending in a realm name held
    /// here would resolve, whoever wrote it.
    pub fn realm_of<'a>(&self, issuer: &'a str) -> Option<&'a str> {
        let realm = issuer
            .strip_prefix(self.0.as_str())?
            .strip_prefix("/realms/")?;

        // Exactly one segment, or `main/../other` reaches a realm the issuer
        // does not name.
        (!realm.is_empty() && !realm.contains('/')).then_some(realm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_is_absolute_and_carries_nothing_a_client_cannot_quote() {
        assert!(PublicOrigin::parse("https://id.example").is_some());
        assert!(PublicOrigin::parse("http://localhost:8080").is_some());
        assert!(
            PublicOrigin::parse("https://id.example/auth").is_some(),
            "a path prefix is a deployment choice, not a malformed origin"
        );

        for refused in [
            "id.example",
            "ftp://id.example",
            "https://",
            "https:///realms",
            "https://id.example?x=1",
            "https://id.example#f",
            "https://id example",
            "https://id.example//auth",
        ] {
            assert!(
                PublicOrigin::parse(refused).is_none(),
                "{refused} was accepted"
            );
        }
    }

    /// Two spellings of one origin are two issuers to a relying party, and the
    /// comparison is byte for byte.
    #[test]
    fn a_trailing_slash_does_not_make_a_second_issuer() {
        assert_eq!(
            PublicOrigin::parse("https://id.example/")
                .unwrap()
                .issuer("main"),
            PublicOrigin::parse("https://id.example")
                .unwrap()
                .issuer("main"),
        );
        assert_eq!(
            PublicOrigin::parse("https://id.example")
                .unwrap()
                .issuer("main"),
            "https://id.example/realms/main"
        );
    }

    /// The prefix is what makes `iss` load bearing rather than decorative.
    #[test]
    fn an_issuer_this_deployment_did_not_mint_names_no_realm() {
        let origin = PublicOrigin::parse("https://id.example").unwrap();

        assert_eq!(
            origin.realm_of("https://id.example/realms/main"),
            Some("main")
        );
        assert_eq!(
            origin.realm_of("https://elsewhere.example/realms/main"),
            None,
            "a foreign issuer resolved a realm here"
        );
        assert_eq!(
            origin.realm_of("main"),
            None,
            "a bare realm id is not an issuer this deployment mints"
        );
        assert_eq!(
            origin.realm_of("https://id.example/realms/main/../other"),
            None,
            "an issuer walked out of the segment it names"
        );
        assert_eq!(origin.realm_of("https://id.example/realms/"), None);
    }
}
