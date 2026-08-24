mod support;

use std::sync::Arc;

use crypto::envelope::Envelope;
use crypto::provider::CryptoConfig;
use crypto::provider::SignAlg;
use crypto::provider::openssl::OpenSslProvider;
use models::entities::keys::{KeyStatus, KeyUse, RealmSigningKey};
use store::keyring;
use store::providers::realm_keys;
use store::tenancy::TenantContext;
use support::Fixture;

const KEK: &str = "a-deployment-wrapping-key-of-decent-length";
const PRIVATE: &[u8] = b"-----BEGIN PRIVATE KEY-----not really one-----END PRIVATE KEY-----";

fn envelope() -> Envelope {
    let provider = OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider");
    Envelope::new(Arc::new(provider), KEK).expect("an envelope")
}

fn key(kid: &str, algorithm: SignAlg, status: KeyStatus, priority: i64) -> RealmSigningKey {
    RealmSigningKey {
        tenant: "acme".into(),
        realm_id: "main".into(),
        kid: kid.into(),
        algorithm,
        key_use: KeyUse::Sig,
        status,
        priority,
        private_pem: PRIVATE.to_vec(),
        public_jwk: serde_json::json!({"kty": "EC", "crv": "P-256", "kid": kid}),
        created_at: 1_700_000_000,
    }
}

/// The doctrine from the ring, applied to the first column that uses it: read
/// the raw bytes and check they are sealed, not merely that they come back.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_private_half_lands_sealed_and_comes_back_whole() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();

    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-1", SignAlg::Es256, KeyStatus::Active, 10),
    )
    .await
    .unwrap();

    let stored: Vec<u8> = transaction
        .query_one(
            "SELECT private_pem FROM realm_signing_keys WHERE kid = 'kid-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        crypto::envelope::is_sealed(&stored),
        "the private half was stored unsealed"
    );
    assert!(
        !stored.windows(PRIVATE.len()).any(|w| w == PRIVATE),
        "the private key is present in the column"
    );

    let loaded = realm_keys::active(&transaction, &ring, &envelope, KeyUse::Sig, None)
        .await
        .unwrap()
        .expect("the realm signs with nothing");
    assert_eq!(loaded.kid, "kid-1");
    assert_eq!(loaded.private_pem, PRIVATE);
    assert_eq!(loaded.algorithm, SignAlg::Es256);
    assert_eq!(
        loaded.key_type(),
        "EC",
        "the key type is read from the algorithm"
    );
}

/// Two keys of one algorithm signing would have tokens signed under whichever
/// was read first; one per algorithm is what discovery's RS256 needs.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_key_signs_per_use_and_algorithm() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();

    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-1", SignAlg::Es256, KeyStatus::Active, 10),
    )
    .await
    .unwrap();
    // Another algorithm signs beside it; a second key of the same one is
    // refused, so a rotation stays observable.
    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-2", SignAlg::Rs256, KeyStatus::Active, 20),
    )
    .await
    .unwrap();
    assert_eq!(
        realm_keys::active(
            &transaction,
            &ring,
            &envelope,
            KeyUse::Sig,
            Some(SignAlg::Rs256)
        )
        .await
        .unwrap()
        .expect("the RSA key")
        .kid,
        "kid-2"
    );
    assert_eq!(
        realm_keys::active(&transaction, &ring, &envelope, KeyUse::Sig, None)
            .await
            .unwrap()
            .expect("a key")
            .kid,
        "kid-2",
        "asked for any, the highest priority answers"
    );
    // Last: a refused statement ends what the transaction can still answer.
    assert!(
        realm_keys::create(
            &transaction,
            &ring,
            &envelope,
            &key("kid-3", SignAlg::Es256, KeyStatus::Active, 30),
        )
        .await
        .is_err(),
        "a second key of one algorithm was made to sign beside the first"
    );
}

/// Rotation moves signing and leaves verification alone.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_rotated_key_still_verifies_and_stops_signing() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();

    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-1", SignAlg::Es256, KeyStatus::Active, 10),
    )
    .await
    .unwrap();
    // Deliberately lower than the key it replaces: the published order follows
    // priority, and an index that sorts by status first would otherwise put
    // these two in the same order for a different reason.
    realm_keys::rotate(
        &transaction,
        &ring,
        &envelope,
        &key("kid-2", SignAlg::Es256, KeyStatus::Active, 5),
    )
    .await
    .unwrap();

    let signing = realm_keys::active(&transaction, &ring, &envelope, KeyUse::Sig, None)
        .await
        .unwrap()
        .expect("nothing signs after a rotation");
    assert_eq!(signing.kid, "kid-2");

    // The old key is still published, or every token signed before the
    // rotation stops verifying at once.
    let published: Vec<String> = realm_keys::published(&transaction, KeyUse::Sig)
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.kid)
        .collect();
    assert_eq!(
        published,
        vec!["kid-1".to_owned(), "kid-2".to_owned()],
        "the published set is ordered by priority, not by which key signs"
    );

    let old = realm_keys::by_kid(&transaction, &ring, &envelope, "kid-1")
        .await
        .unwrap()
        .expect("the rotated key is gone");
    assert_eq!(old.status, KeyStatus::Passive);
}

/// A disabled key neither signs nor verifies, and is not published.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_disabled_key_is_not_published() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();

    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-1", SignAlg::Es256, KeyStatus::Active, 10),
    )
    .await
    .unwrap();
    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-old", SignAlg::Rs256, KeyStatus::Passive, 1),
    )
    .await
    .unwrap();

    assert_eq!(
        realm_keys::published(&transaction, KeyUse::Sig)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(realm_keys::disable(&transaction, "kid-old").await.unwrap());

    let published = realm_keys::published(&transaction, KeyUse::Sig)
        .await
        .unwrap();
    assert_eq!(
        published.iter().map(|k| k.kid.clone()).collect::<Vec<_>>(),
        vec!["kid-1".to_owned()]
    );
    // The published view reads its key type from the algorithm too, or a client
    // reading the JWKS is told to use a family the key does not belong to.
    assert_eq!(published[0].key_type, "EC");
    assert_eq!(published[0].algorithm, SignAlg::Es256);
    assert!(
        !realm_keys::disable(&transaction, "kid-absent")
            .await
            .unwrap()
    );
}

/// The catalogue is the schema's, and it depends on what the key is for.
///
/// Written raw, because the provider takes a typed algorithm and cannot express
/// either wrong row. Each attempt runs in its own transaction, since a refused
/// write aborts the one it was made in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_refuses_an_algorithm_that_does_not_fit_the_use() {
    let fixture = Fixture::with_user().await;

    let cases = [
        (
            "'HS256', 'sig'",
            "a symmetric algorithm was accepted for a published key",
        ),
        (
            "'RSA-OAEP', 'sig'",
            "an encryption algorithm was accepted for a signing key",
        ),
        (
            "'ES256', 'enc'",
            "a signing algorithm was accepted for an encryption key",
        ),
    ];

    for (index, (values, what)) in cases.iter().enumerate() {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let statement = format!(
            "INSERT INTO realm_signing_keys \
                 (tenant, realm_id, kid, algorithm, key_use, status, private_pem, \
                  public_jwk, created_at) \
             VALUES ('acme', 'main', 'bad-{index}', {values}, 'passive', '\\x00'::bytea, \
                     '{{}}'::jsonb, 0)"
        );
        let refused = transaction.execute(statement.as_str(), &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// A key of one realm does not open in another, and is not seen there.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    realm_keys::create(
        &transaction,
        &ring,
        &envelope,
        &key("kid-1", SignAlg::Es256, KeyStatus::Active, 10),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        realm_keys::published(&transaction, KeyUse::Sig)
            .await
            .unwrap()
            .is_empty(),
        "another realm published this realm's keys"
    );
}
