//! A realm's data encryption key, its generations, and what they seal.

mod support;

use std::sync::Arc;

use crypto::envelope::Envelope;
use crypto::provider::CryptoConfig;
use crypto::provider::openssl::OpenSslProvider;
use crypto::secrecy::ExposeSecret;
use store::error::StoreError;
use store::keyring;
use store::tenancy::TenantContext;
use support::Fixture;

const KEK: &str = "a-deployment-wrapping-key-of-decent-length";

fn envelope(kek: &str) -> Envelope {
    let provider = OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider");
    Envelope::new(Arc::new(provider), kek).expect("an envelope")
}

/// The row holds the wrapped key and never the key.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_gets_one_generation_and_only_one() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        keyring::provision(&transaction, &envelope, "acme", "main")
            .await
            .unwrap(),
        "the realm was given no generation"
    );
    assert!(
        !keyring::provision(&transaction, &envelope, "acme", "main")
            .await
            .unwrap(),
        "a second generation was minted beside the first"
    );

    let (version, status, kek_id): (i32, String, String) = {
        let row = transaction
            .query_one("SELECT version, status::text, kek_id FROM realm_deks", &[])
            .await
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
    };
    assert_eq!(version, 1);
    assert_eq!(status, "active");
    assert_eq!(kek_id, envelope.kek_id().unwrap());
}

/// The test that matters: the column is read raw and checked to be sealed.
///
/// A round trip alone passes when the sealing is computed and then dropped, and
/// the plaintext written instead. Only reading what actually landed catches it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_lands_in_the_column_is_sealed_and_not_the_secret() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
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

    let secret = b"a client secret nobody should read";
    let sealed = ring
        .seal(&envelope, "client-secret", "client-1", secret)
        .await
        .unwrap();

    assert!(
        crypto::envelope::is_sealed(&sealed),
        "what would be stored is not sealed"
    );
    assert!(
        !sealed.windows(secret.len()).any(|window| window == secret),
        "the plaintext is present in what would be stored"
    );
    assert_eq!(crypto::envelope::dek_version(&sealed), Some(1));

    let opened = ring
        .open(&envelope, "client-secret", "client-1", &sealed)
        .await
        .unwrap();
    assert_eq!(opened.expose_secret().as_slice(), secret);
}

/// The scope is authenticated, not merely used.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sealed_value_opens_in_one_place_only() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
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

    let sealed = ring
        .seal(&envelope, "client-secret", "client-1", b"secret")
        .await
        .unwrap();

    assert!(
        ring.open(&envelope, "client-secret", "client-2", &sealed)
            .await
            .is_err(),
        "a secret of one row opened as another row's"
    );
    assert!(
        ring.open(&envelope, "realm-signing-key", "client-1", &sealed)
            .await
            .is_err(),
        "a secret of one kind opened as another kind"
    );
}

/// Rotation moves writes and leaves reads alone.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_retired_generation_still_opens_what_it_sealed() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();

    let old_ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let sealed_before = old_ring
        .seal(&envelope, "client-secret", "client-1", b"written before")
        .await
        .unwrap();

    assert_eq!(
        keyring::rotate(&transaction, &envelope, "acme", "main")
            .await
            .unwrap(),
        2
    );

    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    assert_eq!(
        ring.active_version(),
        2,
        "writes did not move to the new generation"
    );

    let opened = ring
        .open(&envelope, "client-secret", "client-1", &sealed_before)
        .await
        .expect("what the retired generation sealed cannot be read");
    assert_eq!(opened.expose_secret().as_slice(), b"written before");

    let sealed_after = ring
        .seal(&envelope, "client-secret", "client-2", b"written after")
        .await
        .unwrap();
    assert_eq!(crypto::envelope::dek_version(&sealed_after), Some(2));

    // And the retired row says when it stopped taking writes.
    let (status, retired): (String, Option<chrono::DateTime<chrono::Utc>>) = {
        let row = transaction
            .query_one(
                "SELECT status::text, retired_at FROM realm_deks WHERE version = 1",
                &[],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert_eq!(status, "retired");
    assert!(retired.is_some());
}

/// Rewrapping touches the key rows and no ciphertext, which is the whole reason
/// the key is stored wrapped rather than derived.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_new_wrapping_key_rewrites_the_key_rows_and_nothing_else() {
    let fixture = Fixture::with_user().await;
    let first = envelope(KEK);
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &first, "acme", "main")
        .await
        .unwrap();

    let ring = keyring::load(&transaction, &first, "acme", "main")
        .await
        .unwrap();
    let sealed = ring
        .seal(
            &first,
            "client-secret",
            "client-1",
            b"unchanged by a rewrap",
        )
        .await
        .unwrap();

    let second = envelope("a different deployment wrapping key entirely");
    assert_ne!(first.kek_id().unwrap(), second.kek_id().unwrap());

    // The old ring cannot be opened by the new wrapping key until it is rewrapped.
    assert!(
        keyring::load(&transaction, &second, "acme", "main")
            .await
            .is_err(),
        "a generation wrapped under one key unwrapped under another"
    );

    assert_eq!(
        keyring::rewrap(&transaction, &first, &second, "acme", "main")
            .await
            .unwrap(),
        1
    );

    // Running it again finds nothing left to do, so an interrupted sweep is
    // resumed by repeating it.
    assert_eq!(
        keyring::rewrap(&transaction, &first, &second, "acme", "main")
            .await
            .unwrap(),
        0
    );

    let rewrapped = keyring::load(&transaction, &second, "acme", "main")
        .await
        .expect("the rewrapped generation cannot be opened");
    let opened = rewrapped
        .open(&second, "client-secret", "client-1", &sealed)
        .await
        .expect("a rewrap changed what the ciphertext opens to");
    assert_eq!(opened.expose_secret().as_slice(), b"unchanged by a rewrap");

    let stored_kek: String = transaction
        .query_one("SELECT kek_id FROM realm_deks WHERE version = 1", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored_kek, second.kek_id().unwrap());
}

/// A blob naming a generation nobody holds is an error, never an empty secret.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_value_from_a_generation_we_do_not_hold_is_refused() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
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

    let mut sealed = ring
        .seal(&envelope, "client-secret", "client-1", b"secret")
        .await
        .unwrap();
    // Claim a generation that was never minted.
    sealed[4..8].copy_from_slice(&9u32.to_be_bytes());

    match ring
        .open(&envelope, "client-secret", "client-1", &sealed)
        .await
    {
        Err(StoreError::UnknownGeneration { version }) => assert_eq!(version, 9),
        other => panic!("a value from an unheld generation gave {other:?}"),
    }

    match ring
        .open(&envelope, "client-secret", "client-1", b"not sealed at all")
        .await
    {
        Err(StoreError::NotSealed) => {}
        other => panic!("an unsealed value gave {other:?}"),
    }
}

/// The two rules the schema holds and the ring cannot break, asserted with raw
/// statements.
///
/// The ring conflicts rather than minting a second active generation, and
/// retires the old one before minting the next, so neither wrong state is
/// reachable through it. A constraint nothing can reach is a constraint nobody
/// checks. Each attempt runs in its own transaction, since a refused write
/// aborts the one it was made in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_refuses_what_the_ring_never_tries() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let cases = [
        (
            "INSERT INTO realm_deks (tenant, realm_id, version, wrapped_dek, kek_id, status) \
             VALUES ('acme', 'main', 2, '\\x00'::bytea, 'whatever', 'active')",
            "a second generation took writes beside the first",
        ),
        (
            "INSERT INTO realm_deks (tenant, realm_id, version, wrapped_dek, kek_id, status) \
             VALUES ('acme', 'main', 3, '\\x00'::bytea, 'whatever', 'retired')",
            "a retired generation was recorded without saying when it stopped",
        ),
        (
            "UPDATE realm_deks SET retired_at = now() WHERE version = 1",
            "a generation taking writes was given a time it stopped",
        ),
    ];

    for (statement, what) in cases {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let refused = transaction.execute(statement, &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// A realm with no generation cannot seal, and says so.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_without_a_key_says_so() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(matches!(
        keyring::load(&transaction, &envelope, "acme", "main").await,
        Err(StoreError::NoKeyring)
    ));
}

/// Another realm's generations are not this realm's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_generation_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope(KEK);
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        matches!(
            keyring::load(&transaction, &envelope, "acme", "other").await,
            Err(StoreError::NoKeyring)
        ),
        "another realm read this realm's generations"
    );
}
