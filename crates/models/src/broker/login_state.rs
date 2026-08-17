//! The server side state of an outbound brokered login.
//!
//! Three values are generated when a user is sent to an upstream provider, and
//! all three have to be recognised on the way back. Each defends a different
//! attack.
//!
//! - `state` binds the callback to a login this server started. Without it an
//!   attacker delivers their own authorization code to the victim's browser and
//!   the victim ends up logged in as the attacker.
//! - `nonce` binds the upstream id token to this request, so a token minted for
//!   another session is not replayable here.
//! - the PKCE verifier binds redemption to the party that started the flow
//!   (RFC 7636), so an intercepted code is not redeemable by whoever holds it.
//!
//! The raw `state` travels in a URL and ends up in browser history, proxy logs
//! and `Referer` headers. Only its digest is stored, so reading the table yields
//! nothing replayable against the callback.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};

use crypto::provider::{CryptoProvider, DigestProvider, HashAlg, Result};

/// A value that must not be rendered until it is used.
///
/// The PKCE verifier and the nonce are secret until redemption, and the raw
/// state is secret for the life of the login. All three reach a log the same
/// way: a struct holding one is formatted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerSecret(String);

impl BrokerSecret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Read it. Named so every place one is read is greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BrokerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrokerSecret(<redacted>)")
    }
}

/// Where a brokered login is going, and what local request it is a step of.
///
/// Grouped rather than passed as eight arguments in a row, where two adjacent
/// optional strings of the same type can be swapped and still compile.
#[derive(Debug, Clone)]
pub struct BrokerLoginDestination {
    pub tenant: String,
    pub realm_id: String,
    /// Which upstream this login goes to.
    pub provider_alias: String,
    /// Our callback URI, echoed to the token endpoint.
    pub redirect_uri: String,
    /// Where to resume the local login. A brokered login is a step inside a
    /// local authorization request rather than a request of its own, so what the
    /// local client asked for has to survive the round trip.
    pub client_id: Option<String>,
    pub local_redirect_uri: Option<String>,
    pub local_state: Option<String>,
    /// The organization the local login was scoped to, so a brokered login
    /// cannot widen scope by losing it.
    pub org_id: Option<String>,
}

/// A brokered login in flight, as stored.
///
/// The stored form holds the digest of the state and never the raw value. The
/// raw one exists only in [`BrokerLoginRequest`], which is handed to the
/// redirect builder once and is not persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerLoginState {
    /// Digest of the `state` parameter, hex encoded.
    pub state_hash: String,
    pub tenant: String,
    pub realm_id: String,
    /// The callback carries the alias in its path, but trusting the path alone
    /// would let a callback for one provider be replayed against another
    /// provider's configuration.
    pub provider_alias: String,
    /// Sent upstream, compared against the id token's `nonce` claim.
    pub nonce: BrokerSecret,
    /// PKCE verifier (RFC 7636). Secret until redeemed.
    pub code_verifier: BrokerSecret,
    pub redirect_uri: String,
    pub client_id: Option<String>,
    pub local_redirect_uri: Option<String>,
    pub local_state: Option<String>,
    pub org_id: Option<String>,
    /// Unix epoch seconds.
    pub expires_at: i64,
}

impl BrokerLoginState {
    /// Whether this state is still usable at `now`.
    ///
    /// The store checks expiry in the same statement that consumes the row, so
    /// this is for a caller reasoning about a row it already holds rather than a
    /// substitute for that check. Reading and then using would be a race.
    pub fn is_live(&self, now: i64) -> bool {
        self.expires_at > now
    }
}

/// What the handler needs to build the upstream redirect: the row to persist,
/// plus the values that go on the wire exactly once and are never stored.
#[derive(Debug, Clone)]
pub struct BrokerLoginRequest {
    pub state: BrokerLoginState,
    /// The raw `state` parameter. Only its digest is stored.
    pub raw_state: BrokerSecret,
    /// The PKCE challenge, which is what goes upstream. The verifier stays here
    /// until redemption, and sending the challenge instead is the whole point.
    pub code_challenge: String,
}

impl BrokerLoginRequest {
    /// Start a brokered login.
    ///
    /// The state, the nonce and the verifier are 32 bytes of provider randomness
    /// each, base64url encoded without padding. That is 43 characters, inside
    /// the 43 to 128 RFC 7636 §4.1 allows for a verifier and drawn from its
    /// unreserved set.
    ///
    /// Fails rather than degrades if the generator fails. There is no safe
    /// fallback: a predictable state is a forgeable callback and a predictable
    /// nonce is a replayable id token, so a login that cannot be started is the
    /// only acceptable outcome.
    ///
    /// The randomness and the digest come through the provider rather than from
    /// free functions, so a deployment that put its randomness somewhere else
    /// gets it here too.
    pub fn generate(
        provider: &dyn CryptoProvider,
        destination: BrokerLoginDestination,
        expires_at: i64,
    ) -> Result<Self> {
        let raw_state = random_token(provider)?;
        let nonce = random_token(provider)?;
        let code_verifier = random_token(provider)?;

        // RFC 7636 §4.2: the challenge is BASE64URL(SHA256(ASCII(verifier))),
        // unpadded. `plain` is not offered, since it makes PKCE a no-op against
        // anyone who can read the request.
        let code_challenge = BASE64URL_NOPAD.encode(
            &provider
                .digest()
                .hash(HashAlg::Sha256, code_verifier.as_bytes())?,
        );

        let state_hash = hex_digest(provider.digest(), &raw_state)?;

        Ok(BrokerLoginRequest {
            state: BrokerLoginState {
                state_hash,
                tenant: destination.tenant,
                realm_id: destination.realm_id,
                provider_alias: destination.provider_alias,
                nonce: BrokerSecret::new(nonce),
                code_verifier: BrokerSecret::new(code_verifier),
                redirect_uri: destination.redirect_uri,
                client_id: destination.client_id,
                local_redirect_uri: destination.local_redirect_uri,
                local_state: destination.local_state,
                org_id: destination.org_id,
                expires_at,
            },
            raw_state: BrokerSecret::new(raw_state),
            code_challenge,
        })
    }
}

/// The digest of a raw `state`, hex encoded: how a callback finds the row it
/// must consume.
pub fn state_hash(digest: &dyn DigestProvider, raw_state: &str) -> Result<String> {
    hex_digest(digest, raw_state)
}

fn hex_digest(digest: &dyn DigestProvider, value: &str) -> Result<String> {
    Ok(HEXLOWER.encode(&digest.hash(HashAlg::Sha256, value.as_bytes())?))
}

/// 32 bytes of provider randomness, base64url encoded without padding.
fn random_token(provider: &dyn CryptoProvider) -> Result<String> {
    let mut bytes = [0u8; 32];
    provider.rand().fill(&mut bytes)?;
    Ok(BASE64URL_NOPAD.encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::provider::CryptoConfig;
    use crypto::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .expect("a software provider")
    }

    fn destination() -> BrokerLoginDestination {
        BrokerLoginDestination {
            tenant: "acme".into(),
            realm_id: "acme".into(),
            provider_alias: "google".into(),
            redirect_uri: "https://saffui.example/cb".into(),
            client_id: Some("web".into()),
            local_redirect_uri: Some("https://app.example/cb".into()),
            local_state: Some("local".into()),
            org_id: None,
        }
    }

    /// RFC 7636 Appendix B known answer vector.
    ///
    /// The derivation is the one part of this module with a published expected
    /// output, so it is checked against that rather than against itself. A round
    /// trip would pass with hex, with padding, or with the wrong digest, and all
    /// three produce a challenge the upstream rejects.
    #[test]
    fn the_challenge_matches_the_published_vector() {
        let provider = provider();
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = BASE64URL_NOPAD.encode(
            &provider
                .digest()
                .hash(HashAlg::Sha256, verifier.as_bytes())
                .unwrap(),
        );
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    /// And the generator uses that formula. Without this, it could emit the
    /// challenge hex encoded or padded and the vector above would still pass,
    /// while every redemption failed against a real provider.
    #[test]
    fn the_generator_derives_the_challenge_from_its_own_verifier() {
        let provider = provider();
        let request = BrokerLoginRequest::generate(&provider, destination(), 100).unwrap();

        let expected = BASE64URL_NOPAD.encode(
            &provider
                .digest()
                .hash(
                    HashAlg::Sha256,
                    request.state.code_verifier.expose().as_bytes(),
                )
                .unwrap(),
        );
        assert_eq!(request.code_challenge, expected);
        assert!(
            !request.code_challenge.contains('='),
            "the challenge is unpadded: {}",
            request.code_challenge
        );
    }

    /// Only the digest of the state is stored, so reading the table yields
    /// nothing that can be replayed against the callback.
    #[test]
    fn the_stored_state_is_a_digest_and_not_the_value() {
        let provider = provider();
        let request = BrokerLoginRequest::generate(&provider, destination(), 100).unwrap();

        assert_ne!(request.state.state_hash, request.raw_state.expose());
        assert_eq!(
            request.state.state_hash.len(),
            64,
            "hex of a 256 bit digest"
        );
        assert!(
            request
                .state
                .state_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(
            state_hash(provider.digest(), request.raw_state.expose()).unwrap(),
            request.state.state_hash,
            "a callback finds the row by hashing what it was given"
        );
    }

    /// The three values are drawn independently. Deriving one from another would
    /// make holding the state enough to predict the nonce.
    #[test]
    fn the_three_values_differ_and_are_the_width_the_grammar_allows() {
        let provider = provider();
        let request = BrokerLoginRequest::generate(&provider, destination(), 100).unwrap();

        let raw_state = request.raw_state.expose();
        let nonce = request.state.nonce.expose();
        let verifier = request.state.code_verifier.expose();

        assert_ne!(raw_state, nonce);
        assert_ne!(raw_state, verifier);
        assert_ne!(nonce, verifier);

        for value in [raw_state, nonce, verifier] {
            assert_eq!(value.len(), 43, "32 bytes base64url without padding");
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "{value} leaves the unreserved set"
            );
        }
    }

    /// Two logins started in a row share nothing.
    #[test]
    fn two_logins_share_no_value() {
        let provider = provider();
        let one = BrokerLoginRequest::generate(&provider, destination(), 100).unwrap();
        let other = BrokerLoginRequest::generate(&provider, destination(), 100).unwrap();

        assert_ne!(one.raw_state.expose(), other.raw_state.expose());
        assert_ne!(one.state.nonce.expose(), other.state.nonce.expose());
        assert_ne!(
            one.state.code_verifier.expose(),
            other.state.code_verifier.expose()
        );
        assert_ne!(one.state.state_hash, other.state.state_hash);
    }

    /// The local request survives the round trip. Losing the organization would
    /// widen a login that was scoped to one.
    #[test]
    fn the_local_request_survives_the_round_trip() {
        let provider = provider();
        let scoped = BrokerLoginDestination {
            org_id: Some("org-1".into()),
            ..destination()
        };
        let request = BrokerLoginRequest::generate(&provider, scoped, 100).unwrap();

        assert_eq!(request.state.client_id.as_deref(), Some("web"));
        assert_eq!(
            request.state.local_redirect_uri.as_deref(),
            Some("https://app.example/cb")
        );
        assert_eq!(request.state.local_state.as_deref(), Some("local"));
        assert_eq!(request.state.org_id.as_deref(), Some("org-1"));
        assert_eq!(request.state.provider_alias, "google");
        assert_eq!(request.state.expires_at, 100);
    }

    /// A state is live until its instant, and not at it.
    #[test]
    fn a_state_expires_at_the_instant_it_names() {
        let provider = provider();
        let request = BrokerLoginRequest::generate(&provider, destination(), 1_000).unwrap();

        assert!(request.state.is_live(999));
        assert!(!request.state.is_live(1_000));
        assert!(!request.state.is_live(1_001));
    }

    /// None of the three reaches a log through a formatted struct, which is how
    /// they get there.
    #[test]
    fn nothing_secret_renders() {
        let provider = provider();
        let request = BrokerLoginRequest::generate(&provider, destination(), 100).unwrap();

        let rendered = format!("{request:?}");
        for secret in [
            request.raw_state.expose(),
            request.state.nonce.expose(),
            request.state.code_verifier.expose(),
        ] {
            assert!(!rendered.contains(secret), "a secret rendered: {rendered}");
        }
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains(&request.state.state_hash),
            "the digest is not a secret and still renders"
        );
    }
}
