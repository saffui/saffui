//! A different subject identifier per sector, OIDC Core §8.
//!
//! Two clients that never share a sector see two identifiers for one account
//! and cannot tell they are looking at the same person by comparing them.

use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use store::providers::pairwise;
use url::Url;

/// How many bytes an identifier is drawn from.
const DRAWN_BYTES: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unpaired {
    /// The client registered nothing that names a sector, and its redirect
    /// URIs name more than one host, so §8.1 has no answer.
    #[error("this client's sector cannot be determined")]
    Unnamed,
    #[error("the store could not be read")]
    Unreadable,
}

/// Whether this client is told a different identifier from every other sector.
pub fn is_pairwise(client: &ClientModel) -> bool {
    client.subject_type.as_deref() == Some("pairwise")
}

/// §8.1: what names this client's sector.
///
/// The registered URI's host when there is one, and otherwise the host every
/// redirect URI shares. Two hosts and no `sector_identifier_uri` is a client
/// that never said which of them it is.
pub fn sector_of(client: &ClientModel) -> Result<String, Unpaired> {
    if let Some(named) = client.sector_identifier_uri.as_deref() {
        return host_of(named).ok_or(Unpaired::Unnamed);
    }
    let mut hosts = client
        .redirect_uris
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|uri| host_of(uri));
    let first = hosts.next().ok_or(Unpaired::Unnamed)?;
    hosts
        .all(|held| held == first)
        .then_some(first)
        .ok_or(Unpaired::Unnamed)
}

fn host_of(uri: &str) -> Option<String> {
    Url::parse(uri).ok()?.host_str().map(str::to_owned)
}

/// What this account is called in front of this client.
///
/// The account's own identifier for a client that is told it, and otherwise
/// the one this sector already holds or one drawn now.
pub async fn subject_for(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    client: &ClientModel,
    user_id: &str,
) -> Result<String, Unpaired> {
    if !is_pairwise(client) {
        return Ok(user_id.to_owned());
    }
    let sector = sector_of(client)?;
    if let Some(held) = pairwise::subject_of(transaction, &sector, user_id)
        .await
        .map_err(|_| Unpaired::Unreadable)?
    {
        return Ok(held);
    }
    let mut drawn = [0u8; DRAWN_BYTES];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unpaired::Unreadable)?;
    pairwise::keep_subject(
        transaction,
        &sector,
        user_id,
        &BASE64URL_NOPAD.encode(&drawn),
    )
    .await
    .map_err(|_| Unpaired::Unreadable)
}

/// The account an identifier stands for, going the other way.
pub async fn account_for(
    transaction: &Transaction<'_>,
    client: Option<&ClientModel>,
    sub: &str,
) -> Result<String, Unpaired> {
    // A client told the account's own identifier is told nothing to look up.
    if !client.is_some_and(is_pairwise) {
        return Ok(sub.to_owned());
    }
    pairwise::account_of(transaction, sub)
        .await
        .map_err(|_| Unpaired::Unreadable)?
        // Nothing wears it, which reads as no such account rather than as the
        // identifier standing for itself.
        .ok_or(Unpaired::Unnamed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::client::ClientCreateModel;

    fn client(redirects: &[&str], sector: Option<&str>) -> ClientModel {
        let mut client = ClientCreateModel {
            name: "app".into(),
            display_name: "app".into(),
            description: String::new(),
            enabled: Some(true),
        }
        .into_model(
            "app".into(),
            "main".into(),
            AuditableModel::from_creator("local".into(), "root".into()),
        );
        client.subject_type = Some("pairwise".into());
        client.redirect_uris = Some(redirects.iter().map(|held| (*held).to_owned()).collect());
        client.sector_identifier_uri = sector.map(str::to_owned);
        client
    }

    /// §8.1: the registered URI's host when there is one, and otherwise the
    /// host every redirect shares.
    #[test]
    fn a_sector_is_what_the_registration_names() {
        assert_eq!(
            sector_of(&client(&["https://one.example/cb"], None)),
            Ok("one.example".to_owned())
        );
        assert_eq!(
            sector_of(&client(
                &["https://one.example/cb", "https://one.example/other"],
                None
            )),
            Ok("one.example".to_owned())
        );
        // Two clients on two hosts naming one document share one sector, which
        // is the whole point of naming it.
        for redirect in ["https://one.example/cb", "https://two.example/cb"] {
            assert_eq!(
                sector_of(&client(
                    &[redirect],
                    Some("https://sector.example/uris.json")
                )),
                Ok("sector.example".to_owned())
            );
        }
    }

    /// Two hosts and nothing naming a sector is a client that never said which
    /// of them it is.
    #[test]
    fn two_hosts_and_no_document_name_no_sector() {
        assert_eq!(
            sector_of(&client(
                &["https://one.example/cb", "https://two.example/cb"],
                None
            )),
            Err(Unpaired::Unnamed)
        );
        assert_eq!(sector_of(&client(&[], None)), Err(Unpaired::Unnamed));
    }

    /// A client told its own identifier has nothing to pair.
    #[test]
    fn a_public_client_is_told_the_account_itself() {
        let mut held = client(&["https://one.example/cb"], None);
        held.subject_type = Some("public".into());
        assert!(!is_pairwise(&held));
        held.subject_type = None;
        assert!(!is_pairwise(&held));
    }
}
