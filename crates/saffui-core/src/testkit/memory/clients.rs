use std::sync::atomic::Ordering;

use async_trait::async_trait;
use time::OffsetDateTime;

use uuid::Uuid;

use super::{HeldRegistration, MemoryUnitOfWork};
use crate::authz::capability::Capability;
use crate::clients::registration::InitialAccessToken;
use crate::clients::store::{ClientStore, ListWindow, RegistrationCounts, RegistrationStore};
use crate::clients::{AssertionAlgorithm, Client, ClientAuthMethod, ClientStanding, KeptProof};
use crate::ports::storage::StorageError;

/// What proves a client, as the double holds it: its state is copied into
/// each unit of work, which [`KeptProof`] refuses to be.
#[derive(Clone, Default)]
pub(crate) struct HeldProof {
    secret_digest: Option<Vec<u8>>,
    sealed_secret: Option<Vec<u8>>,
    jwks: Option<serde_json::Value>,
}

impl HeldProof {
    fn hold(proof: &KeptProof) -> Self {
        Self {
            secret_digest: proof.secret_digest.clone(),
            sealed_secret: proof.sealed_secret.clone(),
            jwks: proof.jwks.clone(),
        }
    }

    fn give(&self) -> KeptProof {
        KeptProof {
            secret_digest: self.secret_digest.clone(),
            sealed_secret: self.sealed_secret.clone(),
            jwks: self.jwks.clone(),
        }
    }
}

/// As the rules of the table: the form of the secret, the keys and the
/// algorithm of a client follow its method, and a public client never acts
/// as itself.
fn fits_method(client: &Client, proof: &HeldProof) -> bool {
    let (digest, sealed) = (proof.secret_digest.is_some(), proof.sealed_secret.is_some());
    let keys = proof.jwks.as_ref();
    let fits = match client.auth_method {
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
            digest && !sealed && keys.is_none()
        }
        ClientAuthMethod::ClientSecretJwt => !digest && sealed && keys.is_none(),
        ClientAuthMethod::PrivateKeyJwt => !digest && !sealed && keys.is_some(),
        ClientAuthMethod::None => {
            !digest && !sealed && keys.is_none() && !client.allows_client_credentials
        }
    };
    let algorithm = matches!(
        (client.auth_method, client.auth_signing_alg),
        (_, None)
            | (
                ClientAuthMethod::ClientSecretJwt,
                Some(AssertionAlgorithm::Hs256)
            )
            | (
                ClientAuthMethod::PrivateKeyJwt,
                Some(AssertionAlgorithm::Signed(_))
            )
    );
    let bounded = keys.is_none_or(|keys| keys.is_object() && keys.to_string().len() <= 32 * 1024);
    fits && algorithm && bounded
}

/// As the trigger of the table: a method changes between the two ways of
/// presenting a secret, and to nothing else.
fn presents_secret(method: ClientAuthMethod) -> bool {
    matches!(
        method,
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost
    )
}

impl MemoryUnitOfWork {
    fn keep_client(&mut self, client: &Client, proof: &KeptProof) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let held = HeldProof::hold(proof);
        if !fits_method(client, &held) {
            return Err(StorageError::Failed);
        }
        let realm = self.scope.realm().as_uuid();
        let clients = self.working.clients.entry(realm).or_default();
        if clients
            .iter()
            .any(|known| known.client_id == client.client_id)
        {
            return Err(StorageError::Taken("client identifier"));
        }
        clients.push(client.clone());
        self.working
            .client_proofs
            .insert((realm, client.client_id.clone()), held);
        Ok(())
    }

    fn find_client(&mut self, client_id: &str) -> Option<&mut Client> {
        self.working
            .clients
            .get_mut(&self.scope.realm().as_uuid())
            .and_then(|clients| {
                clients
                    .iter_mut()
                    .find(|client| client.client_id == client_id)
            })
    }

    fn change_capabilities(
        &mut self,
        client_id: &str,
        capabilities: &[Capability],
    ) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let Some(client) = self.find_client(client_id) else {
            return Ok(false);
        };
        // As the schema does: an application holds no capability.
        if client.allows_authorization_code && !capabilities.is_empty() {
            return Err(StorageError::Failed);
        }
        client.capabilities = capabilities.to_vec();
        Ok(true)
    }

    fn change_secret(
        &mut self,
        client_id: &str,
        secret_digest: Option<&[u8]>,
        sealed_secret: Option<&[u8]>,
    ) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let key = (self.scope.realm().as_uuid(), client_id.to_owned());
        let Some(client) = self.find_client(client_id).cloned() else {
            return Ok(false);
        };
        let changed = HeldProof {
            secret_digest: secret_digest.map(<[u8]>::to_vec),
            sealed_secret: sealed_secret.map(<[u8]>::to_vec),
            ..self
                .working
                .client_proofs
                .get(&key)
                .cloned()
                .unwrap_or_default()
        };
        if !fits_method(&client, &changed) {
            return Err(StorageError::Failed);
        }
        self.working.client_proofs.insert(key, changed);
        Ok(true)
    }

    fn change_auth_method(
        &mut self,
        client_id: &str,
        method: ClientAuthMethod,
    ) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let Some(client) = self.find_client(client_id) else {
            return Ok(false);
        };
        if !presents_secret(client.auth_method) || !presents_secret(method) {
            return Err(StorageError::Failed);
        }
        client.auth_method = method;
        Ok(true)
    }

    fn rewrite_metadata(
        &mut self,
        client: &Client,
        jwks: Option<&serde_json::Value>,
    ) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let key = (self.scope.realm().as_uuid(), client.client_id.clone());
        // As the statement: a client that registered itself, while its
        // registration lasts.
        let lasts = self
            .working
            .registrations
            .get(&key)
            .is_some_and(|held| held.ended_at.is_none());
        let Some(known) = self
            .find_client(&client.client_id)
            .filter(|known| known.self_registered && lasts)
            .cloned()
        else {
            return Ok(false);
        };
        // What the statement writes, and nothing else.
        let rewritten = Client {
            name: client.name.clone(),
            scopes: client.scopes.clone(),
            redirect_uris: client.redirect_uris.clone(),
            post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
            id_token_signed_response_alg: client.id_token_signed_response_alg,
            auth_signing_alg: client.auth_signing_alg,
            ..known
        };
        let proof = HeldProof {
            jwks: jwks.cloned(),
            ..self
                .working
                .client_proofs
                .get(&key)
                .cloned()
                .unwrap_or_default()
        };
        if !fits_method(&rewritten, &proof) {
            return Err(StorageError::Failed);
        }
        if let Some(kept) = self.find_client(&client.client_id) {
            *kept = rewritten;
        }
        self.working.client_proofs.insert(key, proof);
        Ok(true)
    }

    fn turn_off_client(&mut self, client_id: &str) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let Some(client) = self.find_client(client_id) else {
            return Ok(false);
        };
        let was_enabled = client.enabled;
        client.enabled = false;
        Ok(was_enabled)
    }

    fn keep_assertion(
        &mut self,
        client_id: &str,
        token_id: &str,
        kept_until: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        self.refuse_in_snapshot()?;
        let key = (
            self.scope.realm().as_uuid(),
            client_id.to_owned(),
            token_id.to_owned(),
        );
        if self.working.client_assertions.contains_key(&key) {
            return Ok(false);
        }
        self.working.client_assertions.insert(key, kept_until);
        Ok(true)
    }
}

#[async_trait]
impl ClientStore for MemoryUnitOfWork {
    async fn insert_client(
        &mut self,
        client: &Client,
        proof: &KeptProof,
    ) -> Result<(), StorageError> {
        let outcome = self.keep_client(client, proof);
        self.record_refusal(outcome)
    }

    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError> {
        self.reads.clients.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .and_then(|clients| clients.iter().find(|client| client.client_id == client_id))
            .cloned())
    }

    async fn read_client_for_update(
        &mut self,
        client_id: &str,
    ) -> Result<Option<Client>, StorageError> {
        // One unit of work at a time: nothing else writes meanwhile.
        self.read_client(client_id).await
    }

    async fn read_client_for_share(
        &mut self,
        client_id: &str,
    ) -> Result<Option<Client>, StorageError> {
        // One unit of work at a time: nothing else writes meanwhile.
        self.read_client(client_id).await
    }

    async fn read_client_standing(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientStanding>, StorageError> {
        Ok(self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .and_then(|clients| clients.iter().find(|client| client.client_id == client_id))
            .map(|client| ClientStanding {
                enabled: client.enabled,
                self_registered: client.self_registered,
            }))
    }

    async fn read_client_with_proof(
        &mut self,
        client_id: &str,
    ) -> Result<Option<(Client, KeptProof)>, StorageError> {
        let Some(client) = self.read_client(client_id).await? else {
            return Ok(None);
        };
        let proof = self
            .working
            .client_proofs
            .get(&(self.scope.realm().as_uuid(), client_id.to_owned()))
            .map_or_else(|| HeldProof::default().give(), HeldProof::give);
        Ok(Some((client, proof)))
    }

    async fn list_clients(&mut self, window: ListWindow) -> Result<Vec<Client>, StorageError> {
        let mut clients = self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .cloned()
            .unwrap_or_default();
        clients.sort_by(|left, right| left.client_id.cmp(&right.client_id));
        Ok(clients
            .into_iter()
            .skip(usize::try_from(window.first).unwrap_or(usize::MAX))
            .take(usize::try_from(window.max).unwrap_or(usize::MAX))
            .collect())
    }

    async fn count_clients(&mut self) -> Result<u64, StorageError> {
        let held = self
            .working
            .clients
            .get(&self.scope.realm().as_uuid())
            .map_or(0, Vec::len);
        u64::try_from(held).map_err(|_| StorageError::Failed)
    }

    async fn write_client_capabilities(
        &mut self,
        client_id: &str,
        capabilities: &[Capability],
    ) -> Result<bool, StorageError> {
        let outcome = self.change_capabilities(client_id, capabilities);
        self.record_refusal(outcome)
    }

    async fn write_client_secret(
        &mut self,
        client_id: &str,
        secret_digest: Option<&[u8]>,
        sealed_secret: Option<&[u8]>,
    ) -> Result<bool, StorageError> {
        let outcome = self.change_secret(client_id, secret_digest, sealed_secret);
        self.record_refusal(outcome)
    }

    async fn write_client_auth_method(
        &mut self,
        client_id: &str,
        method: ClientAuthMethod,
    ) -> Result<bool, StorageError> {
        let outcome = self.change_auth_method(client_id, method);
        self.record_refusal(outcome)
    }

    async fn write_client_metadata(
        &mut self,
        client: &Client,
        jwks: Option<&serde_json::Value>,
    ) -> Result<bool, StorageError> {
        let outcome = self.rewrite_metadata(client, jwks);
        self.record_refusal(outcome)
    }

    async fn disable_client(&mut self, client_id: &str) -> Result<bool, StorageError> {
        let outcome = self.turn_off_client(client_id);
        self.record_refusal(outcome)
    }

    async fn record_client_assertion(
        &mut self,
        client_id: &str,
        token_id: &str,
        kept_until: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.keep_assertion(client_id, token_id, kept_until);
        self.record_refusal(outcome)
    }
}

#[async_trait]
impl RegistrationStore for MemoryUnitOfWork {
    async fn insert_initial_access_token(
        &mut self,
        token: &InitialAccessToken,
        token_digest: &[u8],
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let tokens = self
            .working
            .initial_tokens
            .entry(self.scope.realm().as_uuid())
            .or_default();
        // As the rules of the table: a digest once in its realm, and at
        // most a hundred uses.
        let fits =
            token.uses_left <= 100 && !tokens.iter().any(|(_, digest)| digest == token_digest);
        if !fits {
            return self.record_refusal(Err(StorageError::Failed));
        }
        tokens.push((token.clone(), token_digest.to_vec()));
        Ok(())
    }

    async fn count_live_initial_access_tokens(
        &mut self,
        now: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let live = self
            .working
            .initial_tokens
            .get(&self.scope.realm().as_uuid())
            .map_or(0, |tokens| {
                tokens
                    .iter()
                    .filter(|(token, _)| token.uses_left > 0 && token.expires_at > now)
                    .count()
            });
        u64::try_from(live).map_err(|_| StorageError::Failed)
    }

    async fn list_initial_access_tokens(
        &mut self,
        window: ListWindow,
    ) -> Result<Vec<InitialAccessToken>, StorageError> {
        let mut tokens: Vec<InitialAccessToken> = self
            .working
            .initial_tokens
            .get(&self.scope.realm().as_uuid())
            .map(|tokens| tokens.iter().map(|(token, _)| token.clone()).collect())
            .unwrap_or_default();
        tokens.sort_by(|one, other| {
            other
                .created_at
                .cmp(&one.created_at)
                .then(one.id.cmp(&other.id))
        });
        Ok(tokens
            .into_iter()
            .skip(usize::try_from(window.first).unwrap_or(usize::MAX))
            .take(usize::try_from(window.max).unwrap_or(usize::MAX))
            .collect())
    }

    async fn spend_initial_access_token(
        &mut self,
        token_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let spendable = self
            .working
            .initial_tokens
            .get_mut(&self.scope.realm().as_uuid())
            .and_then(|tokens| {
                tokens.iter_mut().find(|(token, digest)| {
                    digest == token_digest && token.uses_left > 0 && token.expires_at > now
                })
            });
        Ok(spendable.map(|(token, _)| {
            token.uses_left -= 1;
            token.id
        }))
    }

    async fn find_live_initial_access_token(
        &mut self,
        token_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StorageError> {
        Ok(self
            .working
            .initial_tokens
            .get(&self.scope.realm().as_uuid())
            .and_then(|tokens| {
                tokens.iter().find(|(token, digest)| {
                    digest == token_digest && token.uses_left > 0 && token.expires_at > now
                })
            })
            .map(|(token, _)| token.id))
    }

    async fn delete_initial_access_token(&mut self, token_id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(tokens) = self
            .working
            .initial_tokens
            .get_mut(&self.scope.realm().as_uuid())
        else {
            return Ok(false);
        };
        let before = tokens.len();
        tokens.retain(|(token, _)| token.id != token_id);
        Ok(tokens.len() < before)
    }

    async fn insert_client_registration(
        &mut self,
        client_id: &str,
        token_digest: &[u8],
        registered_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (self.scope.realm().as_uuid(), client_id.to_owned());
        // As the keys of the table: a registration of a client of the realm
        // that registered itself, once.
        let fits = self
            .find_client(client_id)
            .is_some_and(|client| client.self_registered)
            && !self.working.registrations.contains_key(&key);
        if !fits {
            return self.record_refusal(Err(StorageError::Failed));
        }
        let held = HeldRegistration {
            token_digest: Some(token_digest.to_vec()),
            registered_at,
            ended_at: None,
        };
        self.working.registrations.insert(key, held);
        Ok(())
    }

    async fn matches_registration_token(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
    ) -> Result<bool, StorageError> {
        let key = (self.scope.realm().as_uuid(), client_id.to_owned());
        Ok(self
            .working
            .registrations
            .get(&key)
            .and_then(|held| held.token_digest.as_deref())
            .is_some_and(|kept| kept == presented_digest))
    }

    async fn rotate_registration_token(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
        next_digest: &[u8],
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (self.scope.realm().as_uuid(), client_id.to_owned());
        match self.working.registrations.get_mut(&key) {
            Some(held) if held.token_digest.as_deref() == Some(presented_digest) => {
                held.token_digest = Some(next_digest.to_vec());
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn end_client_registration(
        &mut self,
        client_id: &str,
        presented_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (self.scope.realm().as_uuid(), client_id.to_owned());
        match self.working.registrations.get_mut(&key) {
            Some(held) if held.token_digest.as_deref() == Some(presented_digest) => {
                held.token_digest = None;
                held.ended_at = Some(now);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn end_client_registration_as_administrator(
        &mut self,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (self.scope.realm().as_uuid(), client_id.to_owned());
        match self.working.registrations.get_mut(&key) {
            Some(held) if held.ended_at.is_none() => {
                held.token_digest = None;
                held.ended_at = Some(now);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn count_registrations(
        &mut self,
        since: OffsetDateTime,
    ) -> Result<RegistrationCounts, StorageError> {
        let realm = self.scope.realm().as_uuid();
        let of_realm: Vec<&HeldRegistration> = self
            .working
            .registrations
            .iter()
            .filter(|((of, _), _)| *of == realm)
            .map(|(_, held)| held)
            .collect();
        let recent = of_realm
            .iter()
            .filter(|held| held.registered_at >= since)
            .count();
        Ok(RegistrationCounts {
            registered: u64::try_from(of_realm.len()).map_err(|_| StorageError::Failed)?,
            since: u64::try_from(recent).map_err(|_| StorageError::Failed)?,
        })
    }
}
