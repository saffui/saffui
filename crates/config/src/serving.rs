use crate::ConfigError;

const ORIGIN: &str = "PUBLIC_ORIGIN";
const LOGIN_UI: &str = "LOGIN_UI_URL";

/// Where a browser is sent to authenticate.
///
/// Not served here. The login screens are an application of their own, and this
/// server's job is to say which login is being answered, not to render it.
///
/// Optional. Absent, the server renders its own page; named, the browser is
/// sent there instead, and that page answers the same endpoint this one does.
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

    /// No page but this server's own.
    pub fn none() -> Self {
        LoginUi(None)
    }

    /// Where a login is answered, or nothing when this server's page is.
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

    /// The host alone, which is what a relying party identifier is.
    ///
    /// No scheme and no port. WebAuthn scopes a credential to a domain, so
    /// `https://id.example:8443` and `https://id.example` are one party and a
    /// credential enrolled against either answers for both. Including the port
    /// would strand every credential the moment a deployment moved behind a
    /// different one.
    pub fn host(&self) -> &str {
        let rest = self
            .0
            .strip_prefix("https://")
            .or_else(|| self.0.strip_prefix("http://"))
            .unwrap_or(&self.0);
        let host = rest.split('/').next().unwrap_or(rest);
        host.rsplit_once(':').map_or(host, |(before, port)| {
            if port.chars().all(|c| c.is_ascii_digit()) {
                before
            } else {
                host
            }
        })
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
mod ceilings {
    use super::RealmCeiling;

    /// A tenant that named a ceiling is answered by its own, in both
    /// directions: a number below the deployment's is a tenant somebody
    /// deliberately kept small, and one above is a tenant somebody
    /// deliberately let grow.
    #[test]
    fn the_tenant_s_own_number_wins_either_way() {
        let deployment = RealmCeiling(Some(50));
        assert_eq!(deployment.against(Some(3)), Some(3));
        assert_eq!(deployment.against(Some(500)), Some(500));
        assert_eq!(deployment.against(None), Some(50));
    }

    /// Zero means the same thing on a tenant row as in the variable: no
    /// bound. The other reading, refusing every realm, is what the tenant's
    /// own state is for.
    #[test]
    fn a_tenant_lifts_the_bound_with_a_zero() {
        assert_eq!(RealmCeiling(Some(50)).against(Some(0)), None);
        assert_eq!(RealmCeiling(None).against(Some(0)), None);
    }

    /// A deployment that turned the ceiling off still lets a tenant set one.
    #[test]
    fn an_unlimited_deployment_still_honours_a_tenant_that_asked() {
        let deployment = RealmCeiling(None);
        assert_eq!(deployment.against(None), None);
        assert_eq!(deployment.against(Some(2)), Some(2));
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

    /// A relying party is a domain, so the port and the path are not part of it.
    #[test]
    fn a_relying_party_is_the_host_and_nothing_else() {
        for (origin, host) in [
            ("https://id.example", "id.example"),
            ("http://localhost:8080", "localhost"),
            ("https://id.example/auth", "id.example"),
        ] {
            assert_eq!(
                PublicOrigin::parse(origin).unwrap().host(),
                host,
                "{origin}"
            );
        }
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

const EGRESS: &str = "EGRESS";

/// Where this deployment will dial when a client asks it to fetch something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Egress {
    /// Only addresses outside the deployment. The default, because a request
    /// naming an address inside it is how a server is made to fetch on
    /// somebody else's behalf.
    Outward,
    /// Anywhere. For a deployment whose relying parties share its private
    /// network, which is a real topology and not a mistake, and which the
    /// default would refuse.
    Anywhere,
}

impl Egress {
    pub fn from_env() -> Result<Self, ConfigError> {
        match crate::optional(EGRESS).as_deref() {
            None | Some("outward") => Ok(Egress::Outward),
            Some("anywhere") => Ok(Egress::Anywhere),
            Some(_) => Err(ConfigError::Invalid {
                key: format!("{}{EGRESS}", crate::PREFIX),
                expected: "outward or anywhere".to_owned(),
            }),
        }
    }
}

const MAX_REALMS: &str = "MAX_REALMS";

/// How many realms one tenant may hold, where the tenant itself names no
/// ceiling of its own.
///
/// Finite by default, because creating a realm is reachable from a console
/// and an unbounded one is a resource the deployment never chose to give: a
/// single compromised administrator would otherwise fill the store. Fifty is
/// well past what a deployment of this shape uses and well short of a runaway.
///
/// Zero is unlimited, which an operator may choose but this server will not
/// choose for them. A tenant carrying its own `max_realms` is answered by
/// that number instead, higher or lower, since the more specific ceiling is
/// the one somebody wrote down on purpose.
#[derive(Clone, Copy, Debug)]
pub struct RealmCeiling(Option<i64>);

impl RealmCeiling {
    pub fn from_env() -> Result<Self, ConfigError> {
        let ceiling = crate::parse_or(MAX_REALMS, 50_i64)?;
        Ok(Self((ceiling > 0).then_some(ceiling)))
    }

    /// The ceiling that applies, given what the tenant says for itself.
    ///
    /// The tenant's own number wins wherever it wrote one, higher or lower:
    /// a ceiling somebody set for this tenant is the one they meant, and the
    /// deployment's answers for the tenants nobody has thought about.
    ///
    /// Zero is unlimited here too. A number means the same thing wherever a
    /// ceiling is written in this deployment, and the alternative was a zero
    /// that lifts the bound in a variable and refuses every realm in a row.
    pub fn against(self, tenant: Option<i64>) -> Option<i64> {
        match tenant {
            Some(0) => None,
            Some(named) => Some(named),
            None => self.0,
        }
    }
}
