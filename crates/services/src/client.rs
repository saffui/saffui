use chrono::{DateTime, Utc};
use crypto::constant_time;
use crypto::envelope::Envelope;
use crypto::password::migration::verify_and_plan;
use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use secrecy::{ExposeSecret, SecretBox};
use store::keyring::RealmKeyring;
use store::providers::clients::{self, StoredSecret};
use store::tenancy::TenantContext;

/// How a client offered to prove who it is.
#[derive(Debug)]
pub enum Presented {
    /// RFC 6749 §2.3.1, in the `Authorization` header.
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
    /// RFC 7523 §2.2: a JWT the client signed, over the secret only the two of
    /// them hold or with a key only it holds.
    Assertion {
        client_id: String,
        assertion: String,
    },
}

impl Presented {
    pub fn client_id(&self) -> &str {
        match self {
            Presented::Basic { client_id, .. }
            | Presented::Post { client_id, .. }
            | Presented::Bare { client_id }
            | Presented::Assertion { client_id, .. } => client_id,
        }
    }

    fn secret(&self) -> Option<&SecretBox<String>> {
        match self {
            Presented::Basic { secret, .. } | Presented::Post { secret, .. } => Some(secret),
            Presented::Bare { .. } | Presented::Assertion { .. } => None,
        }
    }
}

/// Why the client was not established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unauthenticated {
    /// Nothing named a client.
    #[error("no client was named")]
    Anonymous,
    /// More than one at once. §2.3 forbids it: a server picking one lets a
    /// caller be judged on whichever gets checked.
    #[error("more than one authentication method was used")]
    Ambiguous,
    /// A method this build does not perform. Refused rather than falling back
    /// to the secret, which is a downgrade nobody asked for.
    #[error("the client is registered for a method this build does not perform")]
    Unperformable,
    /// No such client, wrong secret, switched off, or expired. One answer,
    /// because four would enumerate the realm's clients.
    #[error("the client could not be authenticated")]
    Refused,
    #[error("the store could not be read")]
    Unreadable,
}

/// What the form carried of RFC 7521 §4.2.
pub struct Signed<'a> {
    pub kind: &'a str,
    pub assertion: &'a str,
}

/// Read what the request offered, and refuse two offers at once. Separate
/// arguments, because a merged value could not see there had been two.
pub fn read_presented(
    header: Option<(String, SecretBox<String>)>,
    form_client_id: Option<&str>,
    form_secret: Option<SecretBox<String>>,
    signed: Option<Signed<'_>>,
) -> Result<Presented, Unauthenticated> {
    let form_client_id = form_client_id.filter(|named| !named.is_empty());
    if let Some(signed) = signed {
        if header.is_some() || form_secret.is_some() {
            return Err(Unauthenticated::Ambiguous);
        }
        if signed.kind != crate::assertion::JWT_BEARER {
            return Err(Unauthenticated::Unperformable);
        }
        // §9 lets the assertion be the only thing naming the client, so the
        // subject stands in. Read but never trusted: it selects whose keys the
        // signature is checked against, and that check is what decides.
        let named = crate::assertion::subject_of(signed.assertion);
        let client_id = match (form_client_id, named.as_deref()) {
            // Two names for one caller. Refused rather than called malformed:
            // which client is asking is a fact about the credential.
            (Some(form), Some(sub)) if form != sub => return Err(Unauthenticated::Refused),
            (Some(named), _) | (None, Some(named)) => named.to_owned(),
            (None, None) => return Err(Unauthenticated::Anonymous),
        };
        return Ok(Presented::Assertion {
            client_id,
            assertion: signed.assertion.to_owned(),
        });
    }

    match (header, form_client_id, form_secret) {
        (Some(_), _, Some(_)) => Err(Unauthenticated::Ambiguous),
        // Two claims about who is asking. Honouring the header would
        // authenticate one client for another's request.
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

/// Everything the check needs beyond what was presented.
pub struct Establishing<'a> {
    pub provider: &'a dyn CryptoProvider,
    pub cost: Argon2Params,
    pub tenant: &'a TenantContext,
    /// The names this server answers to, which an assertion's `aud` must hold.
    pub audiences: &'a [String],
    /// How a sealed secret is opened. Absent, a client that keeps one cannot
    /// authenticate rather than authenticating without it.
    pub sealing: Option<(&'a RealmKeyring, &'a Envelope)>,
    /// What the proxy said this caller presented, for the method that is
    /// nothing else. Absent is no certificate, not a proxy misread.
    pub certificate: Option<CertificateNames>,
}

/// Which methods this build performs, by the name the column holds.
const PERFORMED: [&str; 5] = [
    "client-secret",
    "none",
    "client-secret-jwt",
    "private-key-jwt",
    "tls-client-auth",
];

/// The names a trusted proxy read off the certificate this caller presented.
/// RFC 8705 §2: for a client registered to authenticate by TLS, one of these
/// matching the one name it registered is the whole authentication.
#[derive(Debug, Clone, Default)]
pub struct CertificateNames {
    pub dns: Vec<String>,
    pub uris: Vec<String>,
}

/// What a client secret is sealed for, so a blob lifted from another column
/// opens as nothing.
pub const SECRET_SCOPE: &str = "client-secret";

/// How long a client's published key set is kept before it is read again.
///
/// Short, because a client that rotates its keys publishes the new ones and
/// then uses them, and a set kept longer than that stops verifying the client
/// it was read for. Not zero, because that is one fetch per request.
pub const KEYS_KEPT: chrono::Duration = chrono::Duration::seconds(30);

/// Where this client publishes its keys, when they are due to be read again.
///
/// Nothing when the client hands its keys over rather than publishing them,
/// and nothing while what was read last is still fresh.
pub async fn keys_due(
    transaction: &Transaction<'_>,
    client_id: &str,
    now: DateTime<Utc>,
) -> Option<String> {
    let (uri, read_at) = clients::published_keys_at(transaction, client_id)
        .await
        .ok()??;
    let uri = uri?;
    match read_at {
        Some(at) if now - at < KEYS_KEPT => None,
        _ => Some(uri),
    }
}

/// Keep the key set just read from where the client publishes it.
pub async fn keep_keys(
    transaction: &Transaction<'_>,
    client_id: &str,
    jwks: &serde_json::Value,
    now: DateTime<Utc>,
) -> bool {
    clients::keep_published_keys(transaction, client_id, jwks, now)
        .await
        .unwrap_or(false)
}

/// Establish the client, or refuse without saying which part failed.
pub async fn authenticate(
    transaction: &Transaction<'_>,
    within: &Establishing<'_>,
    presented: &Presented,
    now: DateTime<Utc>,
) -> Result<ClientModel, Unauthenticated> {
    let (provider, cost) = (within.provider, within.cost);
    let loaded = clients::load(transaction, presented.client_id())
        .await
        .map_err(|_| Unauthenticated::Unreadable)?;

    let Some(client) = loaded else {
        // The work happens anyway: answering faster for an unregistered name
        // publishes which names are registered.
        burn(provider, cost, presented);
        return Err(Unauthenticated::Refused);
    };

    // Before anything is compared, so its secret never stands in for a method
    // this build cannot perform.
    if client
        .client_authenticator_type
        .as_deref()
        .is_some_and(|named| !PERFORMED.contains(&named))
    {
        return Err(Unauthenticated::Unperformable);
    }

    if client.enabled == Some(false) {
        burn(provider, cost, presented);
        return Err(Unauthenticated::Refused);
    }

    if client.public_client == Some(true) {
        // It holds no secret it could keep, so one offered is either readable
        // by anybody or somebody else's.
        return match presented {
            Presented::Bare { .. } => Ok(client),
            _ => Err(Unauthenticated::Refused),
        };
    }

    // The method is the client's registration, not the request's choice: a
    // client registered for an assertion is not authenticated by a secret it
    // still happens to hold, and the reverse would be a downgrade.
    let registered = client
        .client_authenticator_type
        .as_deref()
        .unwrap_or("client-secret");
    // RFC 8705 §2: the certificate the proxy vouched for is the whole
    // credential, matched against the one name the registration holds.
    // Exactly one name registered, or the client is misprovisioned and
    // refused whole; a bare name with no certificate is anybody.
    if registered == "tls-client-auth" {
        if !matches!(presented, Presented::Bare { .. }) {
            return Err(Unauthenticated::Refused);
        }
        let Some(names) = within.certificate.as_ref() else {
            return Err(Unauthenticated::Refused);
        };
        let expected = |key: &str| {
            client
                .configs
                .as_ref()
                .and_then(|bag| bag.get(key))
                .and_then(models::entities::attributes::AttributeValue::as_str)
                .map(str::trim)
                .filter(|held| !held.is_empty())
                .map(str::to_owned)
        };
        let admitted = match (expected("tls.san_dns"), expected("tls.san_uri")) {
            (Some(dns), None) => names.dns.iter().any(|held| held.eq_ignore_ascii_case(&dns)),
            (None, Some(uri)) => names.uris.contains(&uri),
            _ => false,
        };
        if !admitted {
            return Err(Unauthenticated::Refused);
        }
        return Ok(client);
    }
    let signs = matches!(registered, "client-secret-jwt" | "private-key-jwt");
    if signs != matches!(presented, Presented::Assertion { .. }) {
        return Err(Unauthenticated::Refused);
    }
    if let Presented::Assertion { assertion, .. } = presented {
        return by_assertion(transaction, within, &client, registered, assertion, now).await;
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
        // A row an older binary wrote. Constant time is the only defence a
        // plaintext column has, and it stops being one the moment it converts.
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
        // Kept recoverable for a method that recomputes over it, so it is not
        // what a shared-secret comparison reads.
        StoredSecret::Sealed(_) => Err(Unauthenticated::Refused),
    }
}

/// RFC 7523 §2.2, for whichever of the two methods the client registered.
async fn by_assertion(
    transaction: &Transaction<'_>,
    within: &Establishing<'_>,
    client: &ClientModel,
    registered: &str,
    assertion: &str,
    now: DateTime<Utc>,
) -> Result<ClientModel, Unauthenticated> {
    let secret = match registered {
        "private-key-jwt" => None,
        _ => Some(shared_secret(transaction, within, &client.client_id).await?),
    };
    crate::assertion::verify(
        transaction,
        within.provider,
        client,
        assertion,
        within.audiences,
        secret.as_ref(),
        now,
    )
    .await
    .map_err(|why| match why {
        crate::assertion::Unverifiable::Unreadable => Unauthenticated::Unreadable,
        _ => Unauthenticated::Refused,
    })?;
    Ok(client.clone())
}

/// The secret this deployment can read back, for the method that needs it.
async fn shared_secret(
    transaction: &Transaction<'_>,
    within: &Establishing<'_>,
    client_id: &str,
) -> Result<SecretBox<String>, Unauthenticated> {
    let Some(StoredSecret::Sealed(sealed)) = clients::load_secret(transaction, client_id)
        .await
        .map_err(|_| Unauthenticated::Unreadable)?
    else {
        return Err(Unauthenticated::Refused);
    };
    let (ring, envelope) = within.sealing.ok_or(Unauthenticated::Unperformable)?;
    let opened = ring
        .open(envelope, SECRET_SCOPE, client_id, &sealed)
        .await
        .map_err(|_| Unauthenticated::Refused)?;
    let spelled =
        String::from_utf8(opened.expose_secret().clone()).map_err(|_| Unauthenticated::Refused)?;
    Ok(SecretBox::new(Box::new(spelled)))
}

/// Write the hash of a secret that just proved itself.
///
/// A failure here is not one of the authentication: the row stays readable
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

/// Spend what a real check spends. A hash, not a memcmp: against an Argon2id
/// string the difference is the timing signal this exists to remove.
fn burn(provider: &dyn CryptoProvider, cost: Argon2Params, presented: &Presented) {
    let offered = presented
        .secret()
        .map(|secret| SecretBox::new(Box::new(secret.expose_secret().to_owned())))
        .unwrap_or_else(|| SecretBox::new(Box::new(String::new())));
    let _ = StoredPassword::hash_argon2id(provider, cost, &offered);
}
