use std::sync::Arc;

use async_trait::async_trait;
use saffui_core::ports::crypto::{CryptoFailure, PasswordHasher, PasswordHashingFailure};
use saffui_core::secret::Secret;
use secrecy::SecretBox;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::spawn_blocking;

use super::SharedProvider;
use crate::provider::Argon2Params;

/// The Argon2id of the provider, behind the hashing port of the core, on a
/// bounded number of blocking threads: a hash takes its memory for its whole
/// run, and an executor thread that ran one would serve nothing meanwhile.
pub struct BoundedPasswordHasher {
    provider: SharedProvider,
    cost: Argon2Params,
    workers: Arc<Semaphore>,
}

impl BoundedPasswordHasher {
    /// Hashes at the cost the provider takes by default, on at most
    /// `max_concurrent` threads at once.
    ///
    /// # Errors
    ///
    /// Fails when `max_concurrent` is zero or more than a semaphore counts.
    pub fn new(provider: SharedProvider, max_concurrent: usize) -> Result<Self, CryptoFailure> {
        Self::with_cost(provider, Argon2Params::default(), max_concurrent)
    }

    /// Hashes at the given cost. A test passes a small one so as not to wait.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn with_cost(
        provider: SharedProvider,
        cost: Argon2Params,
        max_concurrent: usize,
    ) -> Result<Self, CryptoFailure> {
        if max_concurrent == 0 || max_concurrent > Semaphore::MAX_PERMITS {
            return Err(CryptoFailure);
        }
        Ok(Self {
            provider,
            cost,
            workers: Arc::new(Semaphore::new(max_concurrent)),
        })
    }

    fn take_worker(&self) -> Result<OwnedSemaphorePermit, PasswordHashingFailure> {
        match Arc::clone(&self.workers).try_acquire_owned() {
            Ok(worker) => Ok(worker),
            Err(TryAcquireError::NoPermits) => Err(PasswordHashingFailure::Busy),
            Err(TryAcquireError::Closed) => Err(PasswordHashingFailure::Failed),
        }
    }
}

/// The provider takes a password as text. One that is not text is no
/// password anybody typed.
fn read_as_text(password: &Secret) -> Option<SecretBox<String>> {
    let text = String::from_utf8(password.expose().to_vec()).ok()?;
    Some(SecretBox::new(Box::new(text)))
}

/// The permit goes with the work, not with the caller: a caller that gives
/// up does not free a worker that is still hashing.
async fn run_on_worker<T: Send + 'static>(
    worker: OwnedSemaphorePermit,
    work: impl FnOnce() -> Result<T, PasswordHashingFailure> + Send + 'static,
) -> Result<T, PasswordHashingFailure> {
    spawn_blocking(move || {
        let _worker = worker;
        work()
    })
    .await
    .map_err(|_| PasswordHashingFailure::Failed)?
}

#[async_trait]
impl PasswordHasher for BoundedPasswordHasher {
    async fn hash_password(&self, password: Secret) -> Result<String, PasswordHashingFailure> {
        let worker = self.take_worker()?;
        let (provider, cost) = (Arc::clone(&self.provider), self.cost);
        run_on_worker(worker, move || {
            let text = read_as_text(&password).ok_or(PasswordHashingFailure::Failed)?;
            provider
                .password()
                .hash(&text, cost)
                .map_err(|_| PasswordHashingFailure::Failed)
        })
        .await
    }

    async fn verify_password(
        &self,
        password: Secret,
        stored: String,
    ) -> Result<bool, PasswordHashingFailure> {
        let worker = self.take_worker()?;
        let provider = Arc::clone(&self.provider);
        run_on_worker(worker, move || {
            let Some(text) = read_as_text(&password) else {
                return Ok(false);
            };
            // A stored string that cannot be read matches nothing.
            Ok(provider.password().verify(&text, &stored).unwrap_or(false))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::ports::crypto::{PasswordHasher, PasswordHashingFailure};
    use saffui_core::secret::Secret;

    use super::BoundedPasswordHasher;
    use crate::adapters::open_provider;
    use crate::provider::Argon2Params;

    /// The lightest cost the provider accepts: a test can wait for it.
    const LIGHT: Argon2Params = Argon2Params {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
        output_len: 32,
    };

    fn open_hasher(max_concurrent: usize) -> BoundedPasswordHasher {
        BoundedPasswordHasher::with_cost(
            open_provider().expect("a provider"),
            LIGHT,
            max_concurrent,
        )
        .expect("a hasher")
    }

    fn type_password(text: &str) -> Secret {
        Secret::new(text.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn a_password_verifies_against_its_hash_and_no_other_does() {
        let hasher = open_hasher(2);

        let stored = hasher
            .hash_password(type_password("correct horse battery"))
            .await
            .expect("a hash");
        let again = hasher
            .hash_password(type_password("correct horse battery"))
            .await
            .expect("a hash");

        assert!(
            stored.starts_with("$argon2id$v=19$m=8192,t=1,p=1$"),
            "{stored}"
        );
        assert_ne!(stored, again, "each hash draws its own salt");
        assert_eq!(
            hasher
                .verify_password(type_password("correct horse battery"), stored.clone())
                .await,
            Ok(true)
        );
        assert_eq!(
            hasher
                .verify_password(type_password("correct horse batterz"), stored)
                .await,
            Ok(false)
        );
    }

    #[tokio::test]
    async fn a_stored_string_that_is_not_an_argon2id_hash_matches_nothing() {
        let hasher = open_hasher(2);

        // Not a hash, another variant, and a cost below what the provider accepts.
        for stored in [
            "",
            "plain",
            "$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$AAAA",
            "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$AAAA",
        ] {
            assert_eq!(
                hasher
                    .verify_password(type_password("anything"), stored.to_owned())
                    .await,
                Ok(false),
                "{stored:?}"
            );
        }
        assert_eq!(
            hasher
                .verify_password(Secret::new(vec![0xff, 0xfe]), "plain".to_owned())
                .await,
            Ok(false),
            "bytes that are not text are no password"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hash_asked_for_when_every_worker_is_taken_is_refused_at_once() {
        let heavy = Argon2Params {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
            output_len: 32,
        };
        let hasher = std::sync::Arc::new(
            BoundedPasswordHasher::with_cost(open_provider().expect("a provider"), heavy, 1)
                .expect("a hasher"),
        );
        let busy = std::sync::Arc::clone(&hasher);
        let running = tokio::spawn(async move { busy.hash_password(type_password("first")).await });
        // Lets the first hash take the only worker.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let refused = hasher.hash_password(type_password("second")).await;

        assert_eq!(refused, Err(PasswordHashingFailure::Busy));
        assert!(running.await.expect("the first hash").is_ok());
        assert!(
            BoundedPasswordHasher::new(open_provider().expect("a provider"), 0).is_err(),
            "a hasher without a worker hashes nothing"
        );
    }
}
