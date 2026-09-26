//! What this realm signs to prove itself to another server's token endpoint:
//! a client assertion, RFC 7523, the way `private_key_jwt` wants it.

use chrono::{DateTime, Utc};
use crypto::jose::jws::{ES256, JwsHeader};
use crypto::jose::jwt::{self, JwtPayload};
use crypto::provider::CryptoProvider;
use models::entities::sim_swap::SimSwapKey;
use secrecy::ExposeSecret;

/// How long an assertion stands. CAMARA refuses one standing past 300
/// seconds; one minute leaves room for a clock that runs slow.
const LIFESPAN: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the assertion could not be signed")]
pub struct Unsigned;

/// An assertion for `client_id`, addressed to the one endpoint it is sent
/// to, with an identifier of its own so a server can refuse it twice.
pub fn client_assertion(
    provider: &dyn CryptoProvider,
    key: &SimSwapKey,
    client_id: &str,
    endpoint: &str,
    now: DateTime<Utc>,
) -> Result<String, Unsigned> {
    let mut drawn = [0u8; 16];
    provider.rand().fill(&mut drawn).map_err(|_| Unsigned)?;
    let jti = data_encoding::HEXLOWER.encode(&drawn);

    let mut header = JwsHeader::new();
    header.set_algorithm("ES256");
    header.set_token_type("JWT");
    header.set_key_id(&key.kid);

    let mut payload = JwtPayload::new();
    payload.set_issuer(client_id);
    payload.set_subject(client_id);
    payload.set_audience(vec![endpoint]);
    payload.set_jwt_id(&jti);
    payload.set_issued_at(&std::time::SystemTime::from(now));
    payload.set_expires_at(&std::time::SystemTime::from(
        now + chrono::Duration::seconds(LIFESPAN),
    ));

    let signer = ES256
        .signer_from_pem(key.private_pem.expose_secret())
        .map_err(|_| Unsigned)?;
    jwt::encode_with_signer(&payload, &header, &signer).map_err(|_| Unsigned)
}
