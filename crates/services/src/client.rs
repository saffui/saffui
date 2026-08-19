//! Establishing which client is asking.
//!
//! Ahead of every grant, and separate from all of them: the token endpoint
//! authenticates once and then routes, so a grant added later cannot be added
//! without the check.

use chrono::{DateTime, Utc};
use crypto::constant_time;
use crypto::password::migration::verify_and_plan;
use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use secrecy::{ExposeSecret, SecretBox};
use store::providers::clients::{self, StoredSecret};

/// How a client offered to prove who it is.
#[derive(Debug)]
pub enum Presented {
    /// RFC 6749 §2.3.1, in the `Authorization` header. What the spec requires
    /// every server to support and every client to prefer.
    Basic {
        client_id: String,
        secret: SecretBox<String>,
    },
    /// §2.3.1's alternative, in the form body.
    Post {
        client_id: String,
        secret: SecretBox<String>,
    },
    /// A name and no proof. Only a public client gets anywhere with this.
    Bare { client_id: String },
}

impl Presented {
    pub fn client_id(&self) -> &str {
        match self {
            Presented::Basic { client_id, .. }
            | Presented::Post { client_id, .. }
            | Presented::Bare { client_id } => client_id,
        }
    }

    fn secret(&self) -> Option<&SecretBox<String>> {
        match self {
            Presented::Basic { secret, .. } | Presented::Post { secret, .. } => Some(secret),
            Presented::Bare { .. } => None,
        }
    }
}

/// Why the client was not established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unauthenticated {
    /// Nothing named a client.
    #[error("no client was named")]
    Anonymous,
    /// More than one method at once. RFC 6749 §2.3 forbids it, and the reason
    /// is that a server picking one silently lets a caller present a weak
    /// credential beside a strong one and be judged on whichever is checked.
    #[error("more than one authentication method was used")]
    Ambiguous,
    /// The registration names a method this build does not perform. Refused
    /// rather than falling back to the secret, which would be a downgrade the
    /// operator did not ask for.
    #[error("the client is registered for a method this build does not perform")]
    Unperformable,
    /// No such client, wrong secret, switched off, or a secret past its date.
    /// One answer, because four would enumerate the realm's clients.
    #[error("the client could not be authenticated")]
    Refused,
    #[error("the store could not be read")]
    Unreadable,
}

/// Read what the request offered, and refuse two offers at once.
///
/// The header and the form are separate arguments because refusing both
/// together is the rule, and a function that took one merged value could not
/// see that there had been two.
pub fn read_presented(
    header: Option<(String, SecretBox<String>)>,
    form_client_id: Option<&str>,
    form_secret: Option<SecretBox<String>>,
) -> Result<Presented, Unauthenticated> {
    let form_client_id = form_client_id.filter(|named| !named.is_empty());

    match (header, form_client_id, form_secret) {
        (Some(_), _, Some(_)) => Err(Unauthenticated::Ambiguous),
        // A `client_id` in the form beside a header naming a different one is
        // two claims about who is asking, and honouring the header would
        // authenticate one client for a request written by another.
        (Some((named, _)), Some(also), None) if named != also => Err(Unauthenticated::Ambiguous),
        (Some((client_id, secret)), _, None) => Ok(Presented::Basic { client_id, secret }),
        (None, Some(client_id), Some(secret)) => Ok(Presented::Post {
            client_id: client_id.to_owned(),
            secret,
        }),
        (None, Some(client_id), None) => Ok(Presented::Bare {
            client_id: client_id.to_owned(),
        }),
        (None, None, _) => Err(Unauthenticated::Anonymous),
    }
}

/// Establish the client, or refuse without saying which part failed.
pub async fn authenticate(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    cost: Argon2Params,
    presented: &Presented,
    now: DateTime<Utc>,
) -> Result<ClientModel, Unauthenticated> {
    let loaded = clients::load(transaction, presented.client_id())
        .await
        .map_err(|_| Unauthenticated::Unreadable)?;

    let Some(client) = loaded else {
        // No such client. The work happens anyway, because an endpoint that
        // answers faster for a name nobody registered publishes which names are
        // registered.
        burn(provider, cost, presented);
        return Err(Unauthenticated::Refused);
    };

    // Named before anything is compared, so a client registered for a method
    // this build cannot perform never reaches the branch that would let its
    // secret stand in for that method.
    if client
        .client_authenticator_type
        .as_deref()
        .is_some_and(|named| !matches!(named, "client-secret" | "none"))
    {
        return Err(Unauthenticated::Unperformable);
    }

    if client.enabled == Some(false) {
        burn(provider, cost, presented);
        return Err(Unauthenticated::Refused);
    }

    if client.public_client == Some(true) {
        // A public client holds no secret it could keep, so one offered is
        // either a secret somebody put where anybody can read it or a
        // confidential client's, presented by something that is not it.
        return match presented {
            Presented::Bare { .. } => Ok(client),
            _ => Err(Unauthenticated::Refused),
        };
    }

    let Some(offered) = presented.secret() else {
        return Err(Unauthenticated::Refused);
    };

    if client.secret_expires_at.is_some_and(|expiry| expiry <= now) {
        burn(provider, cost, presented);
        return Err(Unauthenticated::Refused);
    }

    let held = clients::load_secret(transaction, presented.client_id())
        .await
        .map_err(|_| Unauthenticated::Unreadable)?;

    let Some(held) = held else {
        burn(provider, cost, presented);
        return Err(Unauthenticated::Refused);
    };

    match held {
        StoredSecret::Hashed(encoded) => {
            let stored = StoredPassword::Argon2id { encoded }
                .to_legacy_hash()
                .map_err(|_| Unauthenticated::Refused)?;
            verify_and_plan(provider, offered, &stored)
                .is_ok_and(|plan| plan.valid)
                .then_some(client)
                .ok_or(Unauthenticated::Refused)
        }
        // A row an older binary wrote. Checked in constant time, because that is
        // the only defence a plaintext column has, and then replaced: a secret
        // that authenticated once is a secret whose hash can be written, and the
        // row stops being readable from that moment.
        StoredSecret::Plain(plain) => {
            if !constant_time::eq(
                offered.expose_secret().as_bytes(),
                plain.expose().as_bytes(),
            ) {
                return Err(Unauthenticated::Refused);
            }
            convert(transaction, provider, cost, presented.client_id(), offered).await;
            Ok(client)
        }
    }
}

/// Write the hash of a secret that has just proved itself.
///
/// A failure here is not a failure of the authentication. The client presented
/// the right secret and is entitled to be let in; the row simply stays readable
/// until the next attempt, which is where it was a moment ago.
async fn convert(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    cost: Argon2Params,
    client_id: &str,
    offered: &SecretBox<String>,
) {
    let Ok(StoredPassword::Argon2id { encoded }) =
        StoredPassword::hash_argon2id(provider, cost, offered)
    else {
        return;
    };
    let _ = clients::convert_secret(transaction, client_id, &encoded).await;
}

/// Spend what a real check spends.
///
/// A hash comparison, not a byte one. Since V018 the stored secret is an
/// Argon2id string, so an unknown client that only cost a memcmp would answer in
/// a fraction of the time a known one does, which is the timing signal this
/// exists to remove.
fn burn(provider: &dyn CryptoProvider, cost: Argon2Params, presented: &Presented) {
    let offered = presented
        .secret()
        .map(|secret| SecretBox::new(Box::new(secret.expose_secret().to_owned())))
        .unwrap_or_else(|| SecretBox::new(Box::new(String::new())));
    let _ = StoredPassword::hash_argon2id(provider, cost, &offered);
}
