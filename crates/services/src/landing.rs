//! Where an authorization response goes, and how it travels.

/// How the client asked to be answered, OAuth 2.0 Multiple Response Type
/// Encoding Practices §2.1 and the Form Post Response Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseMode {
    /// Appended to the redirect's query. What a code response gets when the
    /// client asks for nothing else.
    #[default]
    Query,
    /// Posted by the browser as a form. What a client behind something that
    /// logs or truncates query strings asks for, and what keeps the response
    /// out of a URL bar, a history and a referrer.
    FormPost,
}

impl ResponseMode {
    pub fn read(named: Option<&str>) -> Option<Self> {
        match named {
            None | Some("query") => Some(ResponseMode::Query),
            Some("form_post") => Some(ResponseMode::FormPost),
            Some(_) => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ResponseMode::Query => "query",
            ResponseMode::FormPost => "form_post",
        }
    }
}

/// An authorization response: where it goes, what it carries, and how.
///
/// The parts rather than a joined URL, because the mode decides what joining
/// means. A response built as a string is one that can only ever be a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landing {
    pub redirect_uri: String,
    pub parameters: Vec<(&'static str, String)>,
    pub mode: ResponseMode,
}

impl Landing {
    pub fn new(redirect_uri: &str, mode: ResponseMode) -> Self {
        Landing {
            redirect_uri: redirect_uri.to_owned(),
            parameters: Vec::new(),
            mode,
        }
    }

    pub fn carrying(mut self, named: &'static str, value: impl Into<String>) -> Self {
        self.parameters.push((named, value.into()));
        self
    }

    /// The same, only when there is something to carry. A parameter the client
    /// did not send is one it must not be answered with.
    pub fn carrying_any(self, named: &'static str, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.carrying(named, value),
            None => self,
        }
    }

    /// Everything on the redirect's query, which is where a `query` response
    /// goes and where a `form_post` one never does.
    pub fn as_query(&self) -> String {
        let separator = if self.redirect_uri.contains('?') {
            '&'
        } else {
            '?'
        };
        let mut built = self.redirect_uri.clone();
        for (at, (named, value)) in self.parameters.iter().enumerate() {
            built.push(if at == 0 { separator } else { '&' });
            built.push_str(named);
            built.push('=');
            built.push_str(&escaped(value));
        }
        built
    }
}

/// RFC 3986 §2.3's unreserved set kept, everything else escaped, which is the
/// safe direction when the value came from a caller.
fn escaped(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mode_nobody_named_is_the_one_a_code_gets() {
        assert_eq!(ResponseMode::read(None), Some(ResponseMode::Query));
        assert_eq!(ResponseMode::read(Some("query")), Some(ResponseMode::Query));
        assert_eq!(
            ResponseMode::read(Some("form_post")),
            Some(ResponseMode::FormPost)
        );
        // Named and unknown is a refusal, not a fall back to the default: a
        // client that asked for a fragment and got a query has its response in
        // a place it is not reading.
        assert_eq!(ResponseMode::read(Some("fragment")), None);
        assert_eq!(ResponseMode::read(Some("")), None);
    }

    #[test]
    fn a_query_keeps_what_the_redirect_already_carried() {
        let landing = Landing::new("https://app.example/cb?kept=1", ResponseMode::Query)
            .carrying("code", "abc")
            .carrying_any("state", Some("a b"))
            .carrying_any("nonce", None);
        assert_eq!(
            landing.as_query(),
            "https://app.example/cb?kept=1&code=abc&state=a%20b"
        );
    }

    #[test]
    fn a_redirect_with_no_query_gets_one() {
        let landing =
            Landing::new("https://app.example/cb", ResponseMode::Query).carrying("error", "denied");
        assert_eq!(landing.as_query(), "https://app.example/cb?error=denied");
    }
}
