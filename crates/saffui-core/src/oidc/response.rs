//! What the authorization endpoint hands back, and how it travels: OpenID
//! Connect Core 1.0, sections 3.1 to 3.3, OAuth 2.0 Multiple Response Type
//! Encoding Practices, and the Form Post Response Mode.
//!
//! An answer is kept as its parts, never as a joined address: the mode
//! decides what joining means, and an answer posted as a form joins none.

use std::fmt::{self, Write as _};

use super::authorize::write_query_value;
use super::errors::OAuthError;
use crate::clients::{is_on_origin, read_redirect_host};
use crate::settings::PublicOrigin;

/// What a client asks the authorization endpoint to hand back. A set, read
/// in any order: `code id_token` and `id_token code` are one request. The
/// access token alone is not one: nothing in it says who signed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseType {
    Code,
    IdToken,
    IdTokenToken,
    CodeIdToken,
    CodeToken,
    CodeIdTokenToken,
}

impl ResponseType {
    pub const ALL: [Self; 6] = [
        Self::Code,
        Self::IdToken,
        Self::IdTokenToken,
        Self::CodeIdToken,
        Self::CodeToken,
        Self::CodeIdTokenToken,
    ];

    /// Its words in the order OpenID Connect writes them: the one spelling
    /// kept and published.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::IdToken => "id_token",
            Self::IdTokenToken => "id_token token",
            Self::CodeIdToken => "code id_token",
            Self::CodeToken => "code token",
            Self::CodeIdTokenToken => "code id_token token",
        }
    }

    /// Reads the words of a `response_type`, separated by spaces, in any
    /// order. Nothing for a word no type uses, for `token` alone, and for no
    /// word at all.
    #[must_use]
    pub fn read(asked: &str) -> Option<Self> {
        let (mut code, mut id_token, mut token) = (false, false, false);
        for word in asked.split(' ').filter(|word| !word.is_empty()) {
            match word {
                "code" => code = true,
                "id_token" => id_token = true,
                "token" => token = true,
                _ => return None,
            }
        }
        Self::ALL.into_iter().find(|kind| {
            (
                kind.issues_code(),
                kind.issues_id_token(),
                kind.issues_access_token(),
            ) == (code, id_token, token)
        })
    }

    /// Whether the answer carries a code, spent at the token endpoint.
    #[must_use]
    pub fn issues_code(self) -> bool {
        match self {
            Self::Code | Self::CodeIdToken | Self::CodeToken | Self::CodeIdTokenToken => true,
            Self::IdToken | Self::IdTokenToken => false,
        }
    }

    /// Whether the authorization endpoint signs an identity token itself.
    #[must_use]
    pub fn issues_id_token(self) -> bool {
        match self {
            Self::IdToken | Self::IdTokenToken | Self::CodeIdToken | Self::CodeIdTokenToken => true,
            Self::Code | Self::CodeToken => false,
        }
    }

    /// Whether the authorization endpoint signs an access token itself.
    #[must_use]
    pub fn issues_access_token(self) -> bool {
        match self {
            Self::IdTokenToken | Self::CodeToken | Self::CodeIdTokenToken => true,
            Self::Code | Self::IdToken | Self::CodeIdToken => false,
        }
    }

    /// Whether the authorization endpoint signs any token itself.
    #[must_use]
    pub fn issues_token(self) -> bool {
        self.issues_id_token() || self.issues_access_token()
    }

    /// The mode an answer of this type travels in when the request names
    /// none. A token goes after the `#`, which a browser sends nowhere: a
    /// query reaches every log on the way to the client.
    fn default_mode(self) -> ResponseMode {
        match self {
            Self::Code => ResponseMode::Query,
            Self::IdToken
            | Self::IdTokenToken
            | Self::CodeIdToken
            | Self::CodeToken
            | Self::CodeIdTokenToken => ResponseMode::Fragment,
        }
    }
}

/// How an answer reaches the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseMode {
    /// On the query of the redirect URI.
    Query,
    /// After a `#` on the redirect URI.
    Fragment,
    /// Posted to the redirect URI by a page the browser sends on: nothing of
    /// the answer reaches an address bar, a history or a log.
    FormPost,
}

impl ResponseMode {
    pub const ALL: [Self; 3] = [Self::Query, Self::Fragment, Self::FormPost];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Fragment => "fragment",
            Self::FormPost => "form_post",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.name() == name)
    }
}

/// How the answer to a request for `response_type` travels to
/// `redirect_uri`, for a client that declared `declared`: the mode it
/// names, or the default of its type when it names none.
///
/// # Errors
///
/// Returns [`OAuthError::UnsupportedResponseMode`] for a mode this realm
/// does not serve, a query for anything but a code alone, a fragment for a
/// client that declared no type that signs a token, or a form posted to an
/// address whose host a policy cannot name. Refused rather than answered
/// otherwise: an answer put where the client is not reading is one it
/// never sees.
pub fn choose_response_mode(
    asked: Option<&str>,
    response_type: ResponseType,
    declared: &[ResponseType],
    redirect_uri: &str,
) -> Result<ResponseMode, OAuthError> {
    // A parameter sent without a value is one that was not sent (RFC 6749, 3.1).
    let Some(asked) = asked.filter(|asked| !asked.is_empty()) else {
        return Ok(response_type.default_mode());
    };
    match ResponseMode::parse(asked) {
        Some(ResponseMode::Query) if response_type != ResponseType::Code => {
            Err(OAuthError::UnsupportedResponseMode)
        }
        // A code after the `#` follows the browser through each redirection
        // that comes after, to the scripts of the last page: only a client
        // that reads its fragment for tokens is answered there.
        Some(ResponseMode::Fragment) if !declared.iter().any(|kind| kind.issues_token()) => {
            Err(OAuthError::UnsupportedResponseMode)
        }
        Some(ResponseMode::FormPost) if write_form_action_source(redirect_uri).is_none() => {
            Err(OAuthError::UnsupportedResponseMode)
        }
        Some(mode) => Ok(mode),
        None => Err(OAuthError::UnsupportedResponseMode),
    }
}

/// How a refusal of a request travels: as its answer would have, else in
/// the default mode of the type it asked. A client that reads a fragment
/// learns of its refusal there, and what a type sends in a fragment is
/// never sent in a query, a refusal included. A type that cannot be read
/// is refused as a request for a code would be.
#[must_use]
pub fn choose_refusal_mode(
    asked: Option<&str>,
    response_type: Option<ResponseType>,
    declared: &[ResponseType],
    redirect_uri: &str,
) -> ResponseMode {
    let kind = response_type.unwrap_or(ResponseType::Code);
    choose_response_mode(asked, kind, declared, redirect_uri).unwrap_or(kind.default_mode())
}

/// What a page that posts an answer to `redirect_uri` names in its
/// `form-action`, and nowhere else: the address without its query, each
/// character a policy reads as its own syntax percent-encoded (Content
/// Security Policy Level 3, section 2.3.1). Nothing for an address a policy
/// cannot name as it is written: an IPv6 address, a name with an underscore
/// or an empty label, a port left empty, or a host a browser would read
/// otherwise.
fn write_form_action_source(redirect_uri: &str) -> Option<String> {
    let host = read_redirect_host(redirect_uri);
    let nameable = |byte: u8| byte.is_ascii_alphanumeric() || b"-.".contains(&byte);
    if host.split('.').any(str::is_empty) || !host.bytes().all(nameable) {
        return None;
    }
    let address = redirect_uri.split(['?', '#']).next().unwrap_or_default();
    let (scheme, rest) = address.split_once("://")?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if authority.ends_with(':') {
        return None;
    }
    let mut source = format!("{scheme}://{authority}");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/:@!$&()*+=%".contains(&byte) {
            source.push(char::from(byte));
        } else {
            let _ = write!(source, "%{byte:02X}");
        }
    }
    Some(source)
}

/// An answer of the authorization endpoint: where it goes, how, and what it
/// carries, in order.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    redirect_uri: String,
    mode: ResponseMode,
    parameters: Vec<(&'static str, String)>,
}

// Written by hand: an answer carries a code, or tokens.
impl fmt::Debug for AuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.parameters.iter().map(|(name, _)| *name).collect();
        formatter
            .debug_struct("AuthorizationResponse")
            .field("redirect_uri", &self.redirect_uri)
            .field("mode", &self.mode)
            .field("parameters", &names)
            .finish()
    }
}

impl AuthorizationResponse {
    /// The answer to send back: what it carries, then the `state` the client
    /// sent, then the issuer, so that a client talking to several providers
    /// knows who answered (RFC 9207).
    #[must_use]
    pub fn write(
        redirect_uri: &str,
        mode: ResponseMode,
        issuer: &str,
        state: Option<&str>,
        answer: Vec<(&'static str, String)>,
    ) -> Self {
        let mut parameters = answer;
        if let Some(state) = state {
            parameters.push(("state", state.to_owned()));
        }
        parameters.push(("iss", issuer.to_owned()));
        Self {
            redirect_uri: redirect_uri.to_owned(),
            mode,
            parameters,
        }
    }

    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    #[must_use]
    pub fn mode(&self) -> ResponseMode {
        self.mode
    }

    #[must_use]
    pub fn parameters(&self) -> &[(&'static str, String)] {
        &self.parameters
    }

    /// What the page that posts this answer names in its `form-action`, or
    /// nothing when no page may post it: never to an address on `origin`,
    /// whichever way the answer came.
    #[must_use]
    pub fn write_form_action(&self, origin: &PublicOrigin) -> Option<String> {
        if is_on_origin(&self.redirect_uri, origin) {
            return None;
        }
        write_form_action_source(&self.redirect_uri)
    }

    /// The value of one parameter of the answer.
    #[must_use]
    pub fn read_parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(named, _)| *named == name)
            .map(|(_, value)| value.as_str())
    }

    /// Where the browser is sent: the redirect URI with the answer on its
    /// query, or after a `#`. Nothing for a form, whose answer is in no
    /// address.
    #[must_use]
    pub fn write_location(&self) -> Option<String> {
        let mut location = self.redirect_uri.clone();
        let mut separator = match self.mode {
            ResponseMode::Query if self.redirect_uri.contains('?') => '&',
            ResponseMode::Query => '?',
            ResponseMode::Fragment => '#',
            ResponseMode::FormPost => return None,
        };
        for (name, value) in &self.parameters {
            location.push(separator);
            location.push_str(name);
            location.push('=');
            write_query_value(&mut location, value);
            separator = '&';
        }
        Some(location)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationResponse, ResponseMode, ResponseType, choose_refusal_mode,
        choose_response_mode, write_form_action_source,
    };
    use crate::oidc::errors::OAuthError;
    use crate::settings::PublicOrigin;

    const CALLBACK: &str = "https://app.example.org/callback";
    /// A client that declared each type.
    const ALL: &[ResponseType] = &ResponseType::ALL;

    fn ours() -> PublicOrigin {
        PublicOrigin::parse("https://id.example.test").expect("an origin")
    }

    #[test]
    fn a_response_type_is_a_set_of_words_and_the_access_token_alone_is_none() {
        for (written, read) in [
            ("code", ResponseType::Code),
            ("id_token", ResponseType::IdToken),
            ("token id_token", ResponseType::IdTokenToken),
            ("id_token code", ResponseType::CodeIdToken),
            ("token  code", ResponseType::CodeToken),
            ("token id_token code", ResponseType::CodeIdTokenToken),
            ("code code", ResponseType::Code),
        ] {
            assert_eq!(ResponseType::read(written), Some(read), "{written:?}");
        }
        for kind in ResponseType::ALL {
            assert_eq!(ResponseType::read(kind.name()), Some(kind), "{kind:?}");
        }
        for refused in [
            "token",
            "",
            " ",
            "none",
            "code none",
            "Code",
            "code\tid_token",
        ] {
            assert_eq!(ResponseType::read(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn a_token_travels_after_the_hash_unless_the_request_names_another_mode() {
        assert_eq!(
            choose_response_mode(None, ResponseType::Code, ALL, CALLBACK),
            Ok(ResponseMode::Query)
        );
        for kind in ResponseType::ALL
            .into_iter()
            .filter(|kind| *kind != ResponseType::Code)
        {
            assert_eq!(
                choose_response_mode(None, kind, ALL, CALLBACK),
                Ok(ResponseMode::Fragment),
                "{kind:?}"
            );
            assert_eq!(
                choose_response_mode(Some(""), kind, ALL, CALLBACK),
                Ok(ResponseMode::Fragment),
                "{kind:?}"
            );
            assert_eq!(
                choose_response_mode(Some("query"), kind, ALL, CALLBACK),
                Err(OAuthError::UnsupportedResponseMode),
                "a token never travels in a query: {kind:?}"
            );
            assert_eq!(
                choose_response_mode(Some("form_post"), kind, ALL, CALLBACK),
                Ok(ResponseMode::FormPost),
                "{kind:?}"
            );
        }
        for mode in ResponseMode::ALL {
            assert_eq!(
                choose_response_mode(Some(mode.name()), ResponseType::Code, ALL, CALLBACK),
                Ok(mode),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn a_mode_this_realm_does_not_serve_is_refused_and_never_read_as_the_default() {
        for unknown in ["web_message", "jwt", "query.jwt", "Query", "fragment "] {
            assert_eq!(
                choose_response_mode(Some(unknown), ResponseType::Code, ALL, CALLBACK),
                Err(OAuthError::UnsupportedResponseMode),
                "{unknown:?}"
            );
        }
    }

    #[test]
    fn a_refusal_travels_as_the_answer_would_have_and_never_puts_a_token_type_in_a_query() {
        let id_token = Some(ResponseType::IdToken);
        for (asked, kind, travels) in [
            (None, id_token, ResponseMode::Fragment),
            (Some("form_post"), id_token, ResponseMode::FormPost),
            (Some("query"), id_token, ResponseMode::Fragment),
            (Some("web_message"), id_token, ResponseMode::Fragment),
            (
                Some("web_message"),
                Some(ResponseType::Code),
                ResponseMode::Query,
            ),
            (None, None, ResponseMode::Query),
            (Some("fragment"), None, ResponseMode::Fragment),
            (Some("form_post"), None, ResponseMode::FormPost),
            (Some("web_message"), None, ResponseMode::Query),
        ] {
            assert_eq!(
                choose_refusal_mode(asked, kind, ALL, CALLBACK),
                travels,
                "{asked:?} {kind:?}"
            );
        }
    }

    #[test]
    fn a_code_goes_after_the_hash_only_to_a_client_that_declared_a_token() {
        let code_alone = &[ResponseType::Code];
        assert_eq!(
            choose_response_mode(Some("fragment"), ResponseType::Code, code_alone, CALLBACK),
            Err(OAuthError::UnsupportedResponseMode)
        );
        for mode in [ResponseMode::Query, ResponseMode::FormPost] {
            assert_eq!(
                choose_response_mode(Some(mode.name()), ResponseType::Code, code_alone, CALLBACK),
                Ok(mode),
                "{mode:?}"
            );
        }
        for kind in ResponseType::ALL
            .into_iter()
            .filter(|kind| *kind != ResponseType::Code)
        {
            assert_eq!(
                choose_response_mode(
                    Some("fragment"),
                    ResponseType::Code,
                    &[ResponseType::Code, kind],
                    CALLBACK
                ),
                Ok(ResponseMode::Fragment),
                "{kind:?}"
            );
        }
        for kind in [Some(ResponseType::Code), None] {
            assert_eq!(
                choose_refusal_mode(Some("fragment"), kind, code_alone, CALLBACK),
                ResponseMode::Query,
                "told where such a client reads: {kind:?}"
            );
        }
    }

    #[test]
    fn a_form_names_the_address_it_posts_to_and_no_other() {
        for (uri, source) in [
            (CALLBACK, Some(CALLBACK)),
            (
                "https://app.example.org:8443/cb?tenant=a",
                Some("https://app.example.org:8443/cb"),
            ),
            (
                "https://app.example.org/a;form-action%20*,b",
                Some("https://app.example.org/a%3Bform-action%20*%2Cb"),
            ),
            (
                "https://app.example.org/it's",
                Some("https://app.example.org/it%27s"),
            ),
            ("http://localhost:3000/cb", Some("http://localhost:3000/cb")),
            ("http://127.0.0.1/cb", Some("http://127.0.0.1/cb")),
            ("http://[::1]:8080/cb", None),
            ("https://auth_proxy.internal/cb", None),
            ("https://evil.example\\.bank.example.org/cb", None),
            ("myapp://callback", None),
            ("https://app.example.org:/cb", None),
            ("https://app.example.org:", None),
            ("https://.app.example.org/cb", None),
            ("https://app..example.org/cb", None),
            ("https://app.example.org./cb", None),
        ] {
            assert_eq!(write_form_action_source(uri).as_deref(), source, "{uri}");
        }
        assert_eq!(
            choose_response_mode(
                Some("form_post"),
                ResponseType::Code,
                ALL,
                "http://[::1]:8080/cb"
            ),
            Err(OAuthError::UnsupportedResponseMode),
            "a form that a policy cannot hold to its address is not posted"
        );
        assert_eq!(
            choose_refusal_mode(Some("form_post"), None, ALL, "http://[::1]:8080/cb"),
            ResponseMode::Query
        );
    }

    #[test]
    fn an_answer_goes_on_the_query_after_the_hash_or_into_no_address() {
        let answer = |redirect_uri: &str, mode| {
            AuthorizationResponse::write(
                redirect_uri,
                mode,
                "https://id.example.test/realms/acme",
                Some("a b"),
                vec![("code", "c&d".to_owned())],
            )
        };
        let issuer = "iss=https%3A%2F%2Fid.example.test%2Frealms%2Facme";

        assert_eq!(
            answer(CALLBACK, ResponseMode::Query).write_location(),
            Some(format!("{CALLBACK}?code=c%26d&state=a%20b&{issuer}"))
        );
        assert_eq!(
            answer("https://app.example.org/cb?kept=1", ResponseMode::Query).write_location(),
            Some(format!(
                "https://app.example.org/cb?kept=1&code=c%26d&state=a%20b&{issuer}"
            ))
        );
        assert_eq!(
            answer("https://app.example.org/cb?kept=1", ResponseMode::Fragment).write_location(),
            Some(format!(
                "https://app.example.org/cb?kept=1#code=c%26d&state=a%20b&{issuer}"
            ))
        );
        let posted = answer(CALLBACK, ResponseMode::FormPost);
        assert_eq!(posted.write_location(), None);
        assert_eq!(posted.write_form_action(&ours()).as_deref(), Some(CALLBACK));
        assert_eq!(
            posted.parameters(),
            [
                ("code", "c&d".to_owned()),
                ("state", "a b".to_owned()),
                ("iss", "https://id.example.test/realms/acme".to_owned()),
            ],
            "a form carries each value as it is"
        );
    }

    #[test]
    fn no_page_posts_an_answer_to_an_address_of_this_deployment() {
        for redirect_uri in [
            "https://id.example.test/portal/callback",
            "https://id.example.test:8443/realms/acme/oauth2/logout",
        ] {
            let answer = AuthorizationResponse::write(
                redirect_uri,
                ResponseMode::FormPost,
                "https://id.example.test/realms/acme",
                None,
                vec![("code", "c".to_owned())],
            );
            assert_eq!(answer.write_form_action(&ours()), None, "{redirect_uri}");
        }
    }

    #[test]
    fn an_answer_prints_no_value_it_carries() {
        let answer = AuthorizationResponse::write(
            CALLBACK,
            ResponseMode::Fragment,
            "https://id.example.test/realms/acme",
            None,
            vec![("access_token", "eyJ.secret".to_owned())],
        );

        let printed = format!("{answer:?}");

        assert!(!printed.contains("eyJ"), "{printed}");
        assert!(printed.contains("access_token"), "{printed}");
    }
}
