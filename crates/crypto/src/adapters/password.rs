use std::sync::Arc;

use async_trait::async_trait;
use saffui_core::ports::crypto::{
    CryptoFailure, HashingGuard, PasswordHasher, PasswordHashingFailure,
};
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
    max_concurrent: usize,
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
            max_concurrent,
        })
    }

    /// How many passwords it hashes at once at most, at work or not: what
    /// the shares of the hashers are cut from.
    #[must_use]
    pub fn count_workers(&self) -> usize {
        self.max_concurrent
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

/// The permit and the guard of the caller go with the work, not with the
/// caller: a caller that gives up frees neither a worker nor its share while
/// the password is hashed.
async fn run_on_worker<T: Send + 'static>(
    worker: OwnedSemaphorePermit,
    guard: HashingGuard,
    work: impl FnOnce() -> Result<T, PasswordHashingFailure> + Send + 'static,
) -> Result<T, PasswordHashingFailure> {
    spawn_blocking(move || {
        // The worker goes back first, then the share: the shares never count fewer
        // hashes than the workers run, and see the node full until one is free.
        let _held = (worker, guard);
        work()
    })
    .await
    .map_err(|_| PasswordHashingFailure::Failed)?
}

#[async_trait]
impl PasswordHasher for BoundedPasswordHasher {
    async fn hash_password(
        &self,
        password: Secret,
        guard: HashingGuard,
    ) -> Result<String, PasswordHashingFailure> {
        let worker = self.take_worker()?;
        let (provider, cost) = (Arc::clone(&self.provider), self.cost);
        run_on_worker(worker, guard, move || {
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
        guard: HashingGuard,
    ) -> Result<bool, PasswordHashingFailure> {
        let worker = self.take_worker()?;
        let provider = Arc::clone(&self.provider);
        run_on_worker(worker, guard, move || {
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::task::{Context, Waker};
    use std::time::Duration;

    use saffui_core::ports::crypto::{HashingGuard, PasswordHasher, PasswordHashingFailure};
    use saffui_core::secret::Secret;
    use secrecy::SecretBox;
    use tokio::sync::Semaphore;

    use super::BoundedPasswordHasher;
    use crate::adapters::{SharedProvider, open_provider};
    use crate::provider::{
        AeadProvider, Argon2Params, CbcProvider, CryptoProvider, DigestProvider, HmacProvider,
        KdfProvider, KeyStoreProvider, KeyTransportProvider, LegacyDigestProvider,
        PasswordProvider, RandProvider, SignerProvider,
    };

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
            .hash_password(type_password("correct horse battery"), Box::new(()))
            .await
            .expect("a hash");
        let again = hasher
            .hash_password(type_password("correct horse battery"), Box::new(()))
            .await
            .expect("a hash");

        assert!(
            stored.starts_with("$argon2id$v=19$m=8192,t=1,p=1$"),
            "{stored}"
        );
        assert_ne!(stored, again, "each hash draws its own salt");
        assert_eq!(
            hasher
                .verify_password(
                    type_password("correct horse battery"),
                    stored.clone(),
                    Box::new(())
                )
                .await,
            Ok(true)
        );
        assert_eq!(
            hasher
                .verify_password(type_password("correct horse batterz"), stored, Box::new(()))
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
                    .verify_password(type_password("anything"), stored.to_owned(), Box::new(()))
                    .await,
                Ok(false),
                "{stored:?}"
            );
        }
        assert_eq!(
            hasher
                .verify_password(
                    Secret::new(vec![0xff, 0xfe]),
                    "plain".to_owned(),
                    Box::new(())
                )
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
        let running = tokio::spawn(async move {
            busy.hash_password(type_password("first"), Box::new(()))
                .await
        });
        // Lets the first hash take the only worker.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let refused = hasher
            .hash_password(type_password("second"), Box::new(()))
            .await;

        assert_eq!(refused, Err(PasswordHashingFailure::Busy));
        assert!(running.await.expect("the first hash").is_ok());
        assert!(
            BoundedPasswordHasher::new(open_provider().expect("a provider"), 0).is_err(),
            "a hasher without a worker hashes nothing"
        );
    }

    /// The passwords of the provider of this machine. As each one is hashed
    /// or verified, it is counted, and the workers then free are noted.
    struct CountingPassword {
        inner: SharedProvider,
        workers: Arc<Semaphore>,
        done: Arc<AtomicUsize>,
        free_at_end: Arc<AtomicUsize>,
    }

    impl CountingPassword {
        fn note_end(&self) {
            self.free_at_end
                .store(self.workers.available_permits(), Ordering::SeqCst);
            self.done.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl PasswordProvider for CountingPassword {
        fn hash(
            &self,
            password: &SecretBox<String>,
            params: Argon2Params,
        ) -> crate::provider::Result<String> {
            let hashed = self.inner.password().hash(password, params);
            self.note_end();
            hashed
        }

        fn verify(
            &self,
            password: &SecretBox<String>,
            encoded: &str,
        ) -> crate::provider::Result<bool> {
            let verified = self.inner.password().verify(password, encoded);
            self.note_end();
            verified
        }

        fn verify_legacy_argon2(
            &self,
            password: &SecretBox<String>,
            encoded: &str,
        ) -> crate::provider::Result<bool> {
            self.inner
                .password()
                .verify_legacy_argon2(password, encoded)
        }

        fn verify_bcrypt(
            &self,
            password: &SecretBox<String>,
            hash: &str,
        ) -> crate::provider::Result<bool> {
            self.inner.password().verify_bcrypt(password, hash)
        }
    }

    /// The provider of this machine, whose passwords are counted.
    struct CountingProvider {
        inner: SharedProvider,
        password: CountingPassword,
    }

    impl CryptoProvider for CountingProvider {
        fn name(&self) -> &str {
            self.inner.name()
        }
        fn version(&self) -> &str {
            self.inner.version()
        }
        fn is_fips_enabled(&self) -> bool {
            self.inner.is_fips_enabled()
        }
        fn hmac(&self) -> &dyn HmacProvider {
            self.inner.hmac()
        }
        fn aead(&self) -> &dyn AeadProvider {
            self.inner.aead()
        }
        fn cbc(&self) -> &dyn CbcProvider {
            self.inner.cbc()
        }
        fn key_transport(&self) -> &dyn KeyTransportProvider {
            self.inner.key_transport()
        }
        fn signer(&self) -> &dyn SignerProvider {
            self.inner.signer()
        }
        fn kdf(&self) -> &dyn KdfProvider {
            self.inner.kdf()
        }
        fn rand(&self) -> &dyn RandProvider {
            self.inner.rand()
        }
        fn password(&self) -> &dyn PasswordProvider {
            &self.password
        }
        fn key_store(&self) -> &dyn KeyStoreProvider {
            self.inner.key_store()
        }
        fn legacy_digest(&self) -> &dyn LegacyDigestProvider {
            self.inner.legacy_digest()
        }
        fn digest(&self) -> &dyn DigestProvider {
            self.inner.digest()
        }
        #[cfg(feature = "pq-hybrid")]
        fn pq_signature(&self) -> &dyn crate::provider::PqSignatureProvider {
            self.inner.pq_signature()
        }
        #[cfg(feature = "pq-hybrid")]
        fn pq_kem(&self) -> &dyn crate::provider::PqKemProvider {
            self.inner.pq_kem()
        }
    }

    /// The guard of a caller. As it is dropped, it tells how many passwords
    /// were hashed by then and how many workers were free; it is alive as long
    /// as its token is.
    struct Watch {
        done: Arc<AtomicUsize>,
        workers: Arc<Semaphore>,
        told: mpsc::Sender<(usize, usize)>,
        _alive: Arc<()>,
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            let seen = (
                self.done.load(Ordering::SeqCst),
                self.workers.available_permits(),
            );
            let _ = self.told.send(seen);
        }
    }

    /// What a caller asks of the hasher.
    #[derive(Clone, Copy, Debug)]
    enum Asked {
        Hash,
        Verification,
    }

    /// The only blocking thread is held, so that the password waits to be
    /// hashed; the caller hangs up meanwhile. The worker is held until the
    /// password is hashed, and the guard of the caller until the worker is
    /// given back.
    #[test]
    fn a_worker_is_held_until_the_password_is_hashed_and_given_back_before_the_guard_of_its_caller()
    {
        const WORKERS: usize = 2;
        for asked in [Asked::Hash, Asked::Verification] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .max_blocking_threads(1)
                .build()
                .expect("a runtime");
            let _inside = runtime.enter();
            let workers = Arc::new(Semaphore::new(WORKERS));
            let done = Arc::new(AtomicUsize::new(0));
            let free_at_end = Arc::new(AtomicUsize::new(0));
            let inner = open_provider().expect("a provider");
            let typed = SecretBox::new(Box::new("correct horse battery".to_owned()));
            let stored = inner.password().hash(&typed, LIGHT).expect("a hash");
            // Built by its fields: the provider sees the workers of the hasher.
            let hasher = BoundedPasswordHasher {
                provider: Arc::new(CountingProvider {
                    inner: Arc::clone(&inner),
                    password: CountingPassword {
                        inner,
                        workers: Arc::clone(&workers),
                        done: Arc::clone(&done),
                        free_at_end: Arc::clone(&free_at_end),
                    },
                }),
                cost: LIGHT,
                workers: Arc::clone(&workers),
                max_concurrent: WORKERS,
            };
            let alive = Arc::new(());
            let (told, seen) = mpsc::channel();
            let guard: HashingGuard = Box::new(Watch {
                done: Arc::clone(&done),
                workers: Arc::clone(&workers),
                told,
                _alive: Arc::clone(&alive),
            });
            let (release, held) = mpsc::channel::<()>();
            let blocker = runtime.spawn_blocking(move || held.recv());
            let password = type_password("correct horse battery");
            let mut context = Context::from_waker(Waker::noop());

            // Polled once, then dropped: a caller that hangs up.
            let pending = match asked {
                Asked::Hash => hasher
                    .hash_password(password, guard)
                    .as_mut()
                    .poll(&mut context)
                    .is_pending(),
                Asked::Verification => hasher
                    .verify_password(password, stored, guard)
                    .as_mut()
                    .poll(&mut context)
                    .is_pending(),
            };

            assert!(
                pending,
                "{asked:?}: the password waits for a blocking thread"
            );
            assert_eq!(
                Arc::strong_count(&alive),
                2,
                "{asked:?}: the guard waits with the work"
            );
            assert_eq!(
                workers.available_permits(),
                WORKERS - 1,
                "{asked:?}: and so does the worker"
            );
            release.send(()).expect("the blocking thread let go");

            assert_eq!(
                seen.recv_timeout(Duration::from_mins(1)),
                Ok((1, WORKERS)),
                "{asked:?}: the guard went once the password was hashed and its worker given back"
            );
            assert_eq!(
                free_at_end.load(Ordering::SeqCst),
                WORKERS - 1,
                "{asked:?}: the worker was held until the password was hashed"
            );
            drop(blocker);
        }
    }
}
