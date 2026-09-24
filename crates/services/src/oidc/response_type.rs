/// The set a `response_type` names. An ordered list would make one request
/// written two ways into two requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResponseType {
    pub code: bool,
    pub id_token: bool,
    pub token: bool,
}

impl ResponseType {
    /// Nothing when a value in it is one no response type uses.
    pub fn read(named: &str) -> Option<Self> {
        let mut asked = ResponseType::default();
        for value in named.split(' ').filter(|value| !value.is_empty()) {
            match value {
                "code" => asked.code = true,
                "id_token" => asked.id_token = true,
                "token" => asked.token = true,
                _ => return None,
            }
        }
        (asked != ResponseType::default()).then_some(asked)
    }

    /// Whether this endpoint mints rather than hands out a reference.
    pub fn mints_here(self) -> bool {
        self.id_token || self.token
    }

    /// What is minted here goes in a fragment: a query reaches every log on
    /// the way and a fragment never leaves the browser.
    pub fn default_mode(self) -> &'static str {
        if self.mints_here() {
            "fragment"
        } else {
            "query"
        }
    }

    /// §3.2.2.11 and §3.3.2.11.
    pub fn needs_at_hash(self) -> bool {
        self.id_token && self.token
    }

    /// §3.3.2.11.
    pub fn needs_c_hash(self) -> bool {
        self.id_token && self.code
    }

    /// §3.2.2.1 and §3.3.2.1: nothing else binds an identity token minted
    /// here to the request that asked for it.
    pub fn needs_nonce(self) -> bool {
        self.id_token
    }

    /// Spelled the way §3 spells it. Empty for a set §3 does not name.
    pub fn as_str(self) -> &'static str {
        match (self.code, self.id_token, self.token) {
            (true, false, false) => "code",
            (false, true, false) => "id_token",
            (false, true, true) => "id_token token",
            (true, true, false) => "code id_token",
            (true, false, true) => "code token",
            (true, true, true) => "code id_token token",
            _ => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_order_carries_nothing() {
        assert_eq!(
            ResponseType::read("code id_token"),
            ResponseType::read("id_token code")
        );
        assert_eq!(
            ResponseType::read("code id_token token"),
            ResponseType::read("token code id_token")
        );
    }

    #[test]
    fn a_value_no_response_type_uses_is_not_one() {
        assert_eq!(ResponseType::read("none"), None);
        assert_eq!(ResponseType::read("code none"), None);
        assert_eq!(ResponseType::read(""), None);
        assert_eq!(ResponseType::read("   "), None);
    }

    #[test]
    fn what_comes_back_here_decides_where_it_goes() {
        let code = ResponseType::read("code").unwrap();
        assert_eq!(code.default_mode(), "query");
        assert!(!code.mints_here());

        for named in ["id_token", "id_token token", "code id_token", "code token"] {
            let asked = ResponseType::read(named).unwrap();
            assert_eq!(asked.default_mode(), "fragment", "{named}");
            assert!(asked.mints_here(), "{named}");
        }
    }

    #[test]
    fn a_hash_is_needed_where_both_come_back_together() {
        let hybrid = ResponseType::read("code id_token token").unwrap();
        assert!(hybrid.needs_at_hash() && hybrid.needs_c_hash());

        let with_code = ResponseType::read("code id_token").unwrap();
        assert!(with_code.needs_c_hash() && !with_code.needs_at_hash());

        let implicit = ResponseType::read("id_token token").unwrap();
        assert!(implicit.needs_at_hash() && !implicit.needs_c_hash());

        // No identity token is minted here, so there is nothing to carry one.
        let coded = ResponseType::read("code token").unwrap();
        assert!(!coded.needs_at_hash() && !coded.needs_c_hash());
    }

    #[test]
    fn an_identity_token_minted_here_is_bound_by_a_nonce() {
        for named in [
            "id_token",
            "id_token token",
            "code id_token",
            "code id_token token",
        ] {
            assert!(ResponseType::read(named).unwrap().needs_nonce(), "{named}");
        }
        for named in ["code", "code token"] {
            assert!(!ResponseType::read(named).unwrap().needs_nonce(), "{named}");
        }
    }
}
