//! The command line as a client of the administration API: it proves the
//! secret of its client at the token endpoint of the realm, then calls the
//! administration plane with the token it was given.

use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use saffui_core::authz::admin::ADMIN_SCOPE;
use saffui_core::tenancy::RealmName;
use ureq::Agent;
use zeroize::Zeroizing;

use crate::config::client::{ClientCredentials, Server};

/// How long one call may take, connection included.
const CALL_PATIENCE: Duration = Duration::from_secs(10);
/// The largest answer read from a node, in bytes.
const ANSWER_LIMIT: u64 = 64 * 1024;

/// Why a call to a node did not give what was asked.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CallFailure {
    #[error("authentication failed: the client, its secret or the realm is not known")]
    Unauthenticated,
    #[error("refused: the client may not do this in the realm")]
    Refused,
    #[error("not found")]
    NotFound,
    #[error("the node cannot be reached: {0}")]
    Unreachable(String),
    #[error("the node answered {0}")]
    Unexpected(u16),
}

impl CallFailure {
    /// The exit code of the command line for this failure.
    pub(crate) fn exit_status(&self) -> u8 {
        match self {
            Self::Unauthenticated => 3,
            Self::Refused => 4,
            Self::NotFound => 5,
            Self::Unreachable(_) | Self::Unexpected(_) => 1,
        }
    }
}

/// A session on the administration plane of one realm.
pub(crate) struct AdminSession {
    agent: Agent,
    server: Server,
    realm: RealmName,
    token: Zeroizing<String>,
}

/// An agent that follows no redirection and goes through no proxy: the
/// secret of the client is sent where the operator said, and nowhere else.
fn build_agent(patience: Duration) -> Agent {
    Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(None)
        .timeout_global(Some(patience))
        .build()
        .new_agent()
}

/// One component of a form, as RFC 6749 writes the credentials of the Basic
/// scheme: everything but the unreserved characters percent-encoded.
fn encode_form_component(text: &[u8]) -> Zeroizing<String> {
    // Room for every byte encoded: the text never moves, so no copy is left behind.
    let mut encoded = Zeroizing::new(String::with_capacity(text.len() * 3));
    for &byte in text {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

/// The `Authorization` header of the Basic scheme for these credentials.
fn write_basic_authorization(credentials: &ClientCredentials) -> Zeroizing<String> {
    let client_id = encode_form_component(credentials.client_id.as_bytes());
    let secret = encode_form_component(credentials.secret.expose());
    let mut pair = Zeroizing::new(String::with_capacity(client_id.len() + 1 + secret.len()));
    pair.push_str(&client_id);
    pair.push(':');
    pair.push_str(&secret);
    let mut authorization = Zeroizing::new(String::with_capacity(6 + pair.len().div_ceil(3) * 4));
    authorization.push_str("Basic ");
    STANDARD.encode_string(pair.as_bytes(), &mut authorization);
    authorization
}

/// What the token endpoint said when it gave no token. A 401 is a client, a
/// secret or a realm it does not know; a 400 that names the client known
/// but not allowed is a refusal. Anything else, a 404 from a listener that
/// is not the data plane included, says nothing of the client.
fn judge_token_refusal(status: u16, answer: Option<&str>) -> CallFailure {
    let refused = || {
        answer
            .and_then(|answer| serde_json::from_str::<serde_json::Value>(answer).ok())
            .is_some_and(|answer| {
                matches!(
                    answer["error"].as_str(),
                    Some("invalid_scope" | "unauthorized_client")
                )
            })
    };
    match status {
        401 => CallFailure::Unauthenticated,
        400 if refused() => CallFailure::Refused,
        other => CallFailure::Unexpected(other),
    }
}

/// What the administration plane said, told in the failures of the command line.
fn judge_admin_status(status: u16) -> Result<(), CallFailure> {
    match status {
        200..=299 => Ok(()),
        401 => Err(CallFailure::Unauthenticated),
        403 => Err(CallFailure::Refused),
        404 => Err(CallFailure::NotFound),
        other => Err(CallFailure::Unexpected(other)),
    }
}

fn read_answer(response: &mut ureq::http::Response<ureq::Body>) -> Result<String, CallFailure> {
    response
        .body_mut()
        .with_config()
        .limit(ANSWER_LIMIT)
        .read_to_string()
        .map_err(|error| CallFailure::Unreachable(error.to_string()))
}

/// The access token of a token answer, moved out of it rather than copied.
fn take_access_token(answer: &str) -> Option<Zeroizing<String>> {
    let mut granted: serde_json::Value = serde_json::from_str(answer).ok()?;
    match granted.get_mut("access_token").map(serde_json::Value::take) {
        Some(serde_json::Value::String(token)) => Some(Zeroizing::new(token)),
        _ => None,
    }
}

impl AdminSession {
    /// Proves the secret of the client at the token endpoint of the realm,
    /// and keeps the token it is given for the calls of this command.
    pub(crate) fn sign_in(
        server: Server,
        realm: RealmName,
        credentials: &ClientCredentials,
    ) -> Result<Self, CallFailure> {
        Self::sign_in_within(server, realm, credentials, CALL_PATIENCE)
    }

    fn sign_in_within(
        server: Server,
        realm: RealmName,
        credentials: &ClientCredentials,
        patience: Duration,
    ) -> Result<Self, CallFailure> {
        let agent = build_agent(patience);
        let authorization = write_basic_authorization(credentials);
        let mut response = agent
            .post(server.url(&format!("/realms/{realm}/oauth2/token")))
            .header("Authorization", authorization.as_str())
            .content_type("application/x-www-form-urlencoded")
            .send(format!("grant_type=client_credentials&scope={ADMIN_SCOPE}"))
            .map_err(|error| CallFailure::Unreachable(error.to_string()))?;
        let status = response.status().as_u16();
        if status != 200 {
            // Read only to tell a refusal from the rest.
            let answer = (status == 400)
                .then(|| read_answer(&mut response).ok())
                .flatten();
            return Err(judge_token_refusal(status, answer.as_deref()));
        }
        let answer = Zeroizing::new(read_answer(&mut response)?);
        let token = take_access_token(&answer).ok_or(CallFailure::Unexpected(status))?;
        Ok(Self {
            agent,
            server,
            realm,
            token,
        })
    }

    /// Reads one resource of the realm, by its path under the realm.
    pub(crate) fn read(&self, under_realm: &str) -> Result<String, CallFailure> {
        let path = format!("/admin/v1/realms/{}{under_realm}", self.realm);
        let mut authorization = Zeroizing::new(String::with_capacity(7 + self.token.len()));
        authorization.push_str("Bearer ");
        authorization.push_str(&self.token);
        let mut response = self
            .agent
            .get(self.server.url(&path))
            .header("Authorization", authorization.as_str())
            .call()
            .map_err(|error| CallFailure::Unreachable(error.to_string()))?;
        judge_admin_status(response.status().as_u16())?;
        read_answer(&mut response)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::thread;
    use std::time::{Duration, Instant};

    use saffui_core::secret::Secret;
    use saffui_core::tenancy::RealmName;

    use super::{
        AdminSession, CallFailure, encode_form_component, judge_admin_status, judge_token_refusal,
    };
    use crate::config::client::{ClientCredentials, resolve_server};

    /// A node on this machine that answers the first call it receives with `answer`.
    fn serve_one_answer(answer: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let address = listener.local_addr().expect("an address");
        thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                let lowered = line.to_ascii_lowercase();
                if let Some(value) = lowered.strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
                line.clear();
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            let _ = reader.into_inner().write_all(&answer);
        });
        address
    }

    /// Signs in as `operator` of `acme` at `address`, waiting `patience` at most.
    fn sign_in_at(address: SocketAddr, patience: Duration) -> Result<(), CallFailure> {
        let server = resolve_server(Some(&format!("http://{address}")), |_| None).expect("a node");
        let realm = RealmName::parse("acme").expect("a realm name");
        let credentials = ClientCredentials {
            client_id: "operator".to_owned(),
            secret: Secret::new(b"s3cret".to_vec()),
        };
        AdminSession::sign_in_within(server, realm, &credentials, patience).map(|_| ())
    }

    #[test]
    fn a_form_component_keeps_the_unreserved_characters_and_encodes_the_rest() {
        assert_eq!(
            encode_form_component(b"operator-1.a_b~").as_str(),
            "operator-1.a_b~"
        );
        assert_eq!(encode_form_component(b"a:b c/d").as_str(), "a%3Ab%20c%2Fd");
    }

    #[test]
    fn a_status_of_the_administration_plane_is_told_in_the_exit_codes() {
        assert_eq!(judge_admin_status(200), Ok(()));
        assert_eq!(judge_admin_status(401), Err(CallFailure::Unauthenticated));
        assert_eq!(judge_admin_status(403), Err(CallFailure::Refused));
        assert_eq!(judge_admin_status(404), Err(CallFailure::NotFound));
        assert_eq!(judge_admin_status(503), Err(CallFailure::Unexpected(503)));
    }

    #[test]
    fn the_token_endpoint_tells_a_refused_client_from_an_unknown_one_and_from_a_stranger() {
        assert_eq!(judge_token_refusal(401, None), CallFailure::Unauthenticated);
        for refusal in ["invalid_scope", "unauthorized_client"] {
            let answer = format!(r#"{{"error":"{refusal}"}}"#);
            assert_eq!(
                judge_token_refusal(400, Some(&answer)),
                CallFailure::Refused,
                "{refusal}"
            );
        }
        assert_eq!(
            judge_token_refusal(400, Some(r#"{"error":"invalid_request"}"#)),
            CallFailure::Unexpected(400)
        );
        assert_eq!(judge_token_refusal(400, None), CallFailure::Unexpected(400));
        // A listener that is not the data plane is not a verdict on the realm.
        assert_eq!(judge_token_refusal(404, None), CallFailure::Unexpected(404));
    }

    #[test]
    fn a_redirection_is_told_and_never_followed() {
        let elsewhere = TcpListener::bind("127.0.0.1:0").expect("a port");
        elsewhere.set_nonblocking(true).expect("non-blocking");
        // A 303, which an agent that follows redirections follows with a GET.
        let redirect = format!(
            "HTTP/1.1 303 See Other\r\nLocation: http://{}/realms/acme/oauth2/token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            elsewhere.local_addr().expect("an address")
        );
        let node = serve_one_answer(redirect.into_bytes());

        let told = sign_in_at(node, Duration::from_secs(2));

        let reached = elsewhere.accept().map(|_| ());
        assert_eq!(
            reached.map_err(|error| error.kind()),
            Err(ErrorKind::WouldBlock),
            "the redirection was followed"
        );
        assert_eq!(told, Err(CallFailure::Unexpected(303)));
    }

    #[test]
    fn an_answer_larger_than_the_limit_is_not_read() {
        let body = "a".repeat(65 * 1024);
        let answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let node = serve_one_answer(answer.into_bytes());

        assert!(matches!(
            sign_in_at(node, Duration::from_secs(5)),
            Err(CallFailure::Unreachable(_))
        ));
    }

    #[test]
    fn a_node_that_never_answers_is_given_up_on() {
        // Bound but never accepted: the connection is made, no answer ever comes.
        let silent = TcpListener::bind("127.0.0.1:0").expect("a port");
        let address = silent.local_addr().expect("an address");
        let started = Instant::now();

        let given_up = sign_in_at(address, Duration::from_millis(300));

        let waited = started.elapsed();
        assert!(
            matches!(&given_up, Err(CallFailure::Unreachable(told)) if told.contains("timeout")),
            "{given_up:?}"
        );
        assert!(waited >= Duration::from_millis(300) && waited < Duration::from_secs(5));
    }
}
