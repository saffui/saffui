use serde_json::json;

use super::{Disclosure, Refused, digest_of, hash_named, split_presentation, unverified_payload};
use crate::jose::jws::{self, JwsHeader, JwsSigner};
use crate::provider::CryptoProvider;

/// A presentation of an issued SD-JWT holding the disclosures `keep` accepts.
///
/// The holder's side of RFC 9901 §7.2: what a wallet sends, and what this
/// build's tests send when they play one. A disclosure nested in another is
/// only reachable when its parent is kept too; choosing both is the caller's.
pub fn select_disclosures(
    issued: &str,
    keep: impl Fn(&Disclosure) -> bool,
) -> Result<String, Refused> {
    let parts = split_presentation(issued)?;
    if parts.key_binding.is_some() {
        return Err(Refused::KeyBindingUnexpected);
    }
    let mut presentation = format!("{}~", parts.issuer_token);
    for encoded in parts.disclosures {
        if keep(&Disclosure::read(encoded)?) {
            presentation.push_str(encoded);
            presentation.push('~');
        }
    }
    Ok(presentation)
}

/// Append a key binding token to a presentation: `iat`, `aud`, `nonce` and
/// the digest of the presentation as it stands, signed by the holder key and
/// typed `kb+jwt` (RFC 9901 §4.3).
pub fn bind_presentation(
    provider: &dyn CryptoProvider,
    presentation: &str,
    holder: &dyn JwsSigner,
    audience: &str,
    nonce: &str,
    issued_at: i64,
) -> Result<String, Refused> {
    let parts = split_presentation(presentation)?;
    if parts.key_binding.is_some() {
        return Err(Refused::KeyBindingUnexpected);
    }
    let hash = hash_named(unverified_payload(parts.issuer_token)?.get("_sd_alg"))?;
    let claims = json!({
        "iat": issued_at,
        "aud": audience,
        "nonce": nonce,
        "sd_hash": digest_of(provider, hash, parts.hashed)?,
    });
    let mut header = JwsHeader::new();
    header.set_token_type("kb+jwt");
    let token = jws::serialize_compact(claims.to_string().as_bytes(), &header, holder)
        .map_err(|_| Refused::Unsigned)?;
    Ok(format!("{presentation}{token}"))
}
