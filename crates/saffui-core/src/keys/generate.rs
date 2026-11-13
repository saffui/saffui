use serde_json::json;

use super::{KeyStatus, SIGNING_KEY_PURPOSE, SealedSigningKey, SigningKey};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::crypto::{
    GeneratedSigningKey, KeyMakingFailure, KeyMakingGuard, SealPlace, SignatureAlgorithm,
    WrappedDataKey,
};
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

/// The keys a realm is born with. ES256 signs its access tokens, and RS256
/// is the one algorithm every relying party reads (OpenID Connect Core,
/// section 15.1).
pub const FIRST_ALGORITHMS: [SignatureAlgorithm; 2] =
    [SignatureAlgorithm::Es256, SignatureAlgorithm::Rs256];

/// Makes a key pair for `algorithm`, `guard` kept until it is made. Called
/// before any unit of work opens: an RSA key takes long enough to keep a
/// transaction, and its locks, waiting.
///
/// # Errors
///
/// Returns [`ErrorCode::KeyMakingBusy`] when every key maker is at work, or
/// [`ErrorCode::CryptoUnavailable`] when the key cannot be made.
pub(crate) async fn generate_signing_key(
    app: &App,
    algorithm: SignatureAlgorithm,
    guard: KeyMakingGuard,
) -> Result<GeneratedSigningKey, Failure> {
    app.signer
        .generate_key(algorithm, guard)
        .await
        .map_err(|failure| match failure {
            KeyMakingFailure::Busy => Failure::new(ErrorCode::KeyMakingBusy),
            KeyMakingFailure::Failed => {
                Failure::with_detail(ErrorCode::CryptoUnavailable, "a signing key cannot be made")
            }
        })
}

/// Makes the first keys of a realm, one per algorithm it is born with.
///
/// # Errors
///
/// As [`generate_signing_key`].
pub async fn generate_first_keys(app: &App) -> Result<Vec<GeneratedSigningKey>, Failure> {
    let mut made = Vec::with_capacity(FIRST_ALGORITHMS.len());
    for algorithm in FIRST_ALGORITHMS {
        // A new tenant makes no other key meanwhile: nothing to hold.
        made.push(generate_signing_key(app, algorithm, Box::new(())).await?);
    }
    Ok(made)
}

/// Seals the private half of a key made for the realm of `scope`, under its
/// data key and for the row the key is kept in, and returns the key, active.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the key cannot be sealed,
/// or [`ErrorCode::RandomUnavailable`].
pub(crate) fn seal_signing_key(
    app: &App,
    scope: RealmScope,
    data_key: &WrappedDataKey,
    made: GeneratedSigningKey,
) -> Result<SealedSigningKey, Failure> {
    let id = mint_id(app)?;
    let place = SealPlace {
        tenant: scope.tenant().as_uuid(),
        realm: scope.realm().as_uuid(),
        purpose: SIGNING_KEY_PURPOSE,
        row: id,
    };
    Ok(SealedSigningKey {
        key: SigningKey {
            id,
            key_id: made.key_id,
            algorithm: made.algorithm,
            status: KeyStatus::Active,
            public_jwk: made.public_jwk,
            created_at: app.now(),
        },
        sealed_private_key: app
            .sealer
            .seal(data_key, &place, &made.private_key)
            .map_err(|_| {
                Failure::with_detail(
                    ErrorCode::CryptoUnavailable,
                    "a signing key cannot be sealed",
                )
            })?,
    })
}

/// Gives a new realm its data key and the keys made for it, in the unit of
/// work that creates the realm: a realm never exists without them.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when a key cannot be sealed, or
/// the storage failure.
pub async fn create_first_keys(
    app: &App,
    work: &mut dyn UnitOfWork,
    made: Vec<GeneratedSigningKey>,
) -> Result<(), Failure> {
    let scope = work.scope();
    let data_key = app
        .sealer
        .make_data_key(scope.tenant().as_uuid(), scope.realm().as_uuid(), 1)
        .map_err(|_| {
            Failure::with_detail(ErrorCode::CryptoUnavailable, "a data key cannot be made")
        })?;
    work.insert_data_key(&data_key).await?;
    for generated in made {
        let sealed = seal_signing_key(app, scope, &data_key, generated)?;
        work.insert_signing_key(&sealed).await?;
        let key = sealed.key;
        let created = json!({ "kid": key.key_id, "alg": key.algorithm.name() });
        record_event(app, work, EventKind::SigningKeyCreated, created).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::Value;

    use super::FIRST_ALGORITHMS;
    use crate::authz::admin::authorize_admin_call;
    use crate::authz::capability::Capability;
    use crate::keys::rotate::rotate_signing_key;
    use crate::ports::crypto::{
        CryptoFailure, GeneratedSigningKey, KeyMakingFailure, KeyMakingGuard, SignatureAlgorithm,
        Signer,
    };
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
    use crate::tenancy::realm::{NewRealm, provision_first_realm};
    use crate::testkit::crypto::WeakSigner;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_administrator;
    use crate::testkit::memory::MemoryStorage;

    /// A signer that notes, for each key it is asked for, how many units of
    /// work were open while it was made.
    struct WatchingSigner {
        storage: Arc<MemoryStorage>,
        seen: Mutex<Vec<(SignatureAlgorithm, usize)>>,
        signer: WeakSigner,
    }

    #[async_trait]
    impl Signer for WatchingSigner {
        fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool {
            self.signer.signs_in(algorithm)
        }

        async fn generate_key(
            &self,
            algorithm: SignatureAlgorithm,
            guard: KeyMakingGuard,
        ) -> Result<GeneratedSigningKey, KeyMakingFailure> {
            let open = self.storage.count_live_units_of_work();
            self.seen.lock().expect("the notes").push((algorithm, open));
            self.signer.generate_key(algorithm, guard).await
        }

        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            private_key: &Secret,
            message: &[u8],
        ) -> Result<Vec<u8>, CryptoFailure> {
            self.signer.sign(algorithm, private_key, message)
        }

        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            public_jwk: &Value,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoFailure> {
            self.signer
                .verify(algorithm, public_jwk, message, signature)
        }
    }

    #[test]
    fn a_key_is_made_before_the_unit_of_work_that_keeps_it_opens() {
        let (mut app, storage) = MemoryStorage::wire();
        let watching = Arc::new(WatchingSigner {
            storage: Arc::clone(&storage),
            seen: Mutex::default(),
            signer: WeakSigner::default(),
        });
        app.signer = watching.clone();

        let provisioned = complete(provision_first_realm(
            &app,
            NewRealm {
                tenant_name: "Acme",
                realm_name: "acme",
            },
        ))
        .expect("a realm");
        assert_eq!(
            *watching.seen.lock().expect("the notes"),
            FIRST_ALGORITHMS.map(|algorithm| (algorithm, 0)),
            "the keys of a realm are made while no unit of work is open"
        );
        let scope = RealmScope::bind(provisioned.tenant.id, provisioned.realm.id);
        let token = complete(create_administrator(
            &app,
            "acme",
            scope,
            "operator",
            &[Capability::KeyWrite],
        ));
        let operator = complete(authorize_admin_call(
            &app,
            "acme",
            Some(&token),
            Capability::KeyWrite,
        ))
        .expect("an operator");

        complete(rotate_signing_key(
            &app,
            &operator,
            SignatureAlgorithm::Rs256,
        ))
        .expect("a key");

        assert_eq!(
            watching.seen.lock().expect("the notes").last(),
            Some(&(SignatureAlgorithm::Rs256, 0)),
            "a rotation makes its key while no unit of work is open"
        );
        assert_eq!(storage.count_live_units_of_work(), 0);
    }
}
