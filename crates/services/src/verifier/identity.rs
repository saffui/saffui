//! A login asking a person's wallet for the credential the realm knows people
//! by, and reading where that presentation stands. The login reaches this
//! through its port; the request, its signature and its verification stay
//! with the verifier.

use std::future::Future;
use std::pin::Pin;

use auth::login::wallet::{Asked, Presented, Purpose, Unasked, Wallet};
use chrono::{DateTime, Utc};
use serde_json::json;
use store::keyring::Signing;
use store::providers::protocol::login;
use store::providers::protocol::presentations::{self, ForLogin, Standing};
use store::providers::realms::{realm_features, wallet_identity};
use store::tenancy::UnitOfWork;

use super::presentation::{ask_for_login, digest_response_code};

/// The realm's verifier, as a login asks it.
pub struct LoginVerifier<'a> {
    pub signing: Signing<'a>,
    /// The realm's issuer, which its DID and every request's address are
    /// built from.
    pub issuer: String,
    pub now: DateTime<Utc>,
}

impl Wallet for LoginVerifier<'_> {
    fn ask<'a>(
        &'a self,
        transaction: &'a UnitOfWork,
        purpose: Purpose,
        login_session: &'a str,
        user_id: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Asked, Unasked>> + Send + 'a>> {
        Box::pin(async move {
            if !realm_features::runs_for_realm(
                transaction,
                commons::feature::Feature::WalletVerifier,
            )
            .await
            {
                return Err(Unasked::NotOffered);
            }
            let profile = wallet_identity::load(transaction)
                .await
                .map_err(|_| Unasked::Unavailable)?
                .ok_or(Unasked::NotOffered)?;
            let asked = ask_for_login(
                transaction,
                &self.signing,
                &self.issuer,
                &json!({ "credentials": [profile.credential_query] }),
                ForLogin {
                    purpose: purpose.as_str(),
                    login_session,
                    user_id,
                },
                self.now,
            )
            .await
            .map_err(|why| {
                tracing::warn!(%why, "a login could not ask a wallet");
                Unasked::Unavailable
            })?;
            Ok(Asked {
                request_id: asked.request_id,
                uri: asked.uri,
            })
        })
    }

    fn standing<'a>(
        &'a self,
        transaction: &'a UnitOfWork,
        request_id: &'a str,
        login_session: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Presented, ()>> + Send + 'a>> {
        Box::pin(async move {
            let standing =
                presentations::standing_for_login(transaction, request_id, login_session)
                    .await
                    .map_err(|_| ())?;
            Ok(read_presented(standing.as_ref(), self.now))
        })
    }

    fn redeem<'a>(
        &'a self,
        transaction: &'a UnitOfWork,
        request_id: &'a str,
        login_session: &'a str,
        response_code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Presented>, ()>> + Send + 'a>> {
        Box::pin(async move {
            let digest = digest_response_code(self.signing.provider, response_code)?;
            let spent =
                presentations::redeem(transaction, request_id, login_session, &digest, &self.now)
                    .await
                    .map_err(|_| ())?;
            Ok(spent.map(|held| read_presented(Some(&held), self.now)))
        })
    }
}

/// Where the presentation a login waits on stands, read for that login alone:
/// nothing when the login is over or waits on none.
pub async fn read_awaited_presentation(
    transaction: &UnitOfWork,
    login_session: &str,
    now: DateTime<Utc>,
) -> Result<Option<Presented>, Unread> {
    let Some(held) = login::resume(transaction, login_session)
        .await
        .map_err(|_| Unread)?
    else {
        return Ok(None);
    };
    let Some(awaited) = auth::login::wallet::find_waiting_request(&held.notes) else {
        return Ok(None);
    };
    let standing =
        presentations::standing_for_login(transaction, &awaited.request_id, login_session)
            .await
            .map_err(|_| Unread)?;
    Ok(Some(read_presented(standing.as_ref(), now)))
}

/// The store could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the store could not be read")]
pub struct Unread;

/// Where a login's presentation stands, as the login reads it: answered with
/// an identity only when its answer verified and named one, and brought back
/// once the browser that asked spent its code.
pub fn read_presented(standing: Option<&Standing>, now: DateTime<Utc>) -> Presented {
    let Some(held) = standing else {
        return Presented::Lapsed;
    };
    match held.status.as_str() {
        "pending" if held.expires_at > now => Presented::Waiting,
        "pending" => Presented::Lapsed,
        "verified" => held
            .outcome
            .as_ref()
            .and_then(|outcome| outcome.get("identity"))
            .and_then(|identity| {
                let issuer = identity.get("issuer")?.as_str()?.to_owned();
                let digest = identity.get("digest")?.as_str()?.to_owned();
                Some(match held.redeemed_at {
                    Some(_) => Presented::Redeemed { issuer, digest },
                    None => Presented::Identified { issuer, digest },
                })
            })
            .unwrap_or(Presented::Unproven),
        _ => Presented::Unproven,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn standing(
        status: &str,
        outcome: Option<Value>,
        expires_in: i64,
        now: DateTime<Utc>,
    ) -> Standing {
        Standing {
            request_id: "r-1".to_owned(),
            status: status.to_owned(),
            outcome,
            expires_at: now + chrono::Duration::seconds(expires_in),
            answered_at: None,
            created_by: "ada".to_owned(),
            created_at: now,
            redeemed_at: None,
        }
    }

    /// A request is waited on while it is open, run out once it closes or is
    /// gone, and answered with an identity only when it verified naming one:
    /// a refusal, a failure and a verified answer naming nobody prove nothing.
    #[test]
    fn a_login_reads_an_identity_only_off_an_answer_that_verified_one() {
        let now = Utc::now();
        let identity = json!({ "credentials": [], "identity": { "issuer": "did:web:id.example", "digest": "ab" } });
        assert_eq!(read_presented(None, now), Presented::Lapsed);
        assert_eq!(
            read_presented(Some(&standing("pending", None, 60, now)), now),
            Presented::Waiting
        );
        assert_eq!(
            read_presented(Some(&standing("pending", None, 0, now)), now),
            Presented::Lapsed
        );
        assert_eq!(
            read_presented(
                Some(&standing("verified", Some(identity.clone()), -60, now)),
                now
            ),
            Presented::Identified {
                issuer: "did:web:id.example".to_owned(),
                digest: "ab".to_owned(),
            }
        );
        let mut brought_back = standing("verified", Some(identity.clone()), -60, now);
        brought_back.redeemed_at = Some(now);
        assert_eq!(
            read_presented(Some(&brought_back), now),
            Presented::Redeemed {
                issuer: "did:web:id.example".to_owned(),
                digest: "ab".to_owned(),
            }
        );
        let mut refused_back = standing("refused", Some(identity.clone()), -60, now);
        refused_back.redeemed_at = Some(now);
        assert_eq!(
            read_presented(Some(&refused_back), now),
            Presented::Unproven
        );
        for (status, outcome) in [
            ("verified", Some(json!({ "credentials": [] }))),
            (
                "verified",
                Some(json!({ "identity": { "issuer": "did:web:id.example" } })),
            ),
            ("verified", None),
            ("refused", Some(identity.clone())),
            ("failed", Some(identity)),
        ] {
            assert_eq!(
                read_presented(Some(&standing(status, outcome.clone(), 60, now)), now),
                Presented::Unproven,
                "{status} {outcome:?}"
            );
        }
    }
}
