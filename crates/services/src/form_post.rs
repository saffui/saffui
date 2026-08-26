use chrono::{DateTime, Duration, Utc};
use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use serde_json::Value;
use store::providers::form_post;

use crate::landing::Landing;

/// A response taken back out of the store, its names no longer static.
#[derive(Debug, Clone)]
pub struct Posted {
    pub redirect_uri: String,
    pub fields: Vec<(String, String)>,
}

/// How long a browser has to come back for the response it was handed a ticket
/// for. Long enough for one navigation and no longer: the ticket stands for an
/// authorization code.
const LIFESPAN_SECONDS: i64 = 120;

const TICKET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum Unkeepable {
    #[error("the store could not be written")]
    Unwritable,
}

/// Put a response aside and hand back the ticket that fetches it.
///
/// Written in the caller's transaction, so the ticket is committed with the
/// code it stands for: a ticket that outlived a rolled back login would name a
/// response the redemption cannot find.
pub async fn keep(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    landing: &Landing,
    now: DateTime<Utc>,
) -> Result<String, Unkeepable> {
    let mut drawn = vec![0_u8; TICKET_BYTES];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unkeepable::Unwritable)?;
    let ticket = BASE64URL_NOPAD.encode(&drawn);
    let parameters = Value::Object(
        landing
            .parameters
            .iter()
            .map(|(named, value)| ((*named).to_owned(), Value::from(value.clone())))
            .collect(),
    );
    form_post::keep(
        transaction,
        &hashed(provider, &ticket)?,
        &landing.redirect_uri,
        &parameters,
        now + Duration::seconds(LIFESPAN_SECONDS),
    )
    .await
    .map_err(|_| Unkeepable::Unwritable)?;
    Ok(ticket)
}

/// The response this ticket stands for, taken away as it is read.
pub async fn take(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    ticket: &str,
) -> Result<Option<Posted>, Unkeepable> {
    let Some(waiting) = form_post::take(transaction, &hashed(provider, ticket)?)
        .await
        .map_err(|_| Unkeepable::Unwritable)?
    else {
        return Ok(None);
    };
    let fields = waiting
        .parameters
        .as_object()
        .map(|held| {
            held.iter()
                .filter_map(|(named, value)| {
                    value
                        .as_str()
                        .map(|value| (named.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Posted {
        redirect_uri: waiting.redirect_uri,
        fields,
    }))
}

/// The ticket is stored as a digest: a readable ticket is a readable code.
fn hashed(provider: &dyn CryptoProvider, ticket: &str) -> Result<String, Unkeepable> {
    provider
        .digest()
        .hash(HashAlg::Sha256, ticket.as_bytes())
        .map(|digest| BASE64URL_NOPAD.encode(&digest))
        .map_err(|_| Unkeepable::Unwritable)
}
