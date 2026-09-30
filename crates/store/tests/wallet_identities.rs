mod support;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use crypto::provider::CryptoConfig;
use crypto::provider::openssl::OpenSslProvider;
use models::auditable::AuditableModel;
use models::entities::user::UserCreateModel;
use secrecy::ExposeSecret;
use serde_json::json;
use store::error::StoreError;
use store::keyring;
use store::providers::directory::{users, wallet_identities};
use store::providers::realms::wallet_identity::{self, WalletIdentity};
use store::tenancy::TenantContext;
use support::Fixture;

const ISSUER: &str = "did:web:id.example";
const DIGEST: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
const OTHER: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time")
}

/// An identity answers for one account, an account holds one per issuer, and
/// an account gone takes its identities with it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_identity_answers_for_one_account_and_an_account_holds_one_per_issuer() {
    let fixture = Fixture::with_user().await;
    let main = TenantContext::new("acme", "main");
    let transaction = fixture.scoped(&main).await;
    let bob = UserCreateModel {
        user_name: "bob".into(),
        enabled: true,
        email: String::new(),
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
    }
    .into_model(
        "bob".into(),
        "main".into(),
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    users::create(&transaction, &bob).await.unwrap();
    wallet_identities::link(&transaction, "ada", ISSUER, DIGEST, &now())
        .await
        .unwrap();
    wallet_identities::link(&transaction, "bob", "did:web:other.example", DIGEST, &now())
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let transaction = fixture.scoped(&main).await;
    assert_eq!(
        wallet_identities::holder(&transaction, ISSUER, DIGEST)
            .await
            .unwrap()
            .as_deref(),
        Some("ada")
    );
    assert!(
        wallet_identities::holds(&transaction, "ada", ISSUER, DIGEST)
            .await
            .unwrap()
    );
    for (user, issuer, digest) in [
        ("ada", ISSUER, OTHER),
        ("bob", ISSUER, DIGEST),
        ("ada", "did:web:other.example", DIGEST),
    ] {
        assert!(
            !wallet_identities::holds(&transaction, user, issuer, digest)
                .await
                .unwrap(),
            "{user} {issuer} {digest}"
        );
    }
    let linked = wallet_identities::of_user(&transaction, "ada")
        .await
        .unwrap();
    assert_eq!(
        linked
            .iter()
            .map(|held| held.issuer.as_str())
            .collect::<Vec<_>>(),
        [ISSUER]
    );
    drop(transaction);

    for (user, digest, why) in [
        ("bob", DIGEST, "an identity another account holds"),
        ("ada", OTHER, "a second identity from one issuer"),
    ] {
        let transaction = fixture.scoped(&main).await;
        assert!(
            matches!(
                wallet_identities::link(&transaction, user, ISSUER, digest, &now()).await,
                Err(StoreError::AlreadyExists)
            ),
            "{why} was linked"
        );
    }
    let transaction = fixture.scoped(&main).await;
    assert!(
        matches!(
            wallet_identities::link(&transaction, "bob", ISSUER, "NOT-HEX", &now()).await,
            Err(StoreError::BrokenRule { rule }) if rule == "wallet_identity_digest_written"
        ),
        "a digest not written in lowercase hex was kept"
    );
    drop(transaction);

    let transaction = fixture.scoped(&main).await;
    assert!(
        wallet_identities::unlink(&transaction, "ada", ISSUER)
            .await
            .unwrap()
    );
    assert!(
        !wallet_identities::unlink(&transaction, "ada", ISSUER)
            .await
            .unwrap()
    );
    assert_eq!(
        wallet_identities::holder(&transaction, ISSUER, DIGEST)
            .await
            .unwrap(),
        None
    );
    users::delete(&transaction, "bob").await.unwrap();
    assert!(
        wallet_identities::of_user(&transaction, "bob")
            .await
            .unwrap()
            .is_empty(),
        "an account gone left its identity behind"
    );
    transaction.commit().await.unwrap();

    let elsewhere = fixture.scoped(&TenantContext::new("acme", "other")).await;
    assert!(
        wallet_identities::of_user(&elsewhere, "ada")
            .await
            .unwrap()
            .is_empty()
    );
}

fn envelope() -> Envelope {
    let provider = OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider");
    Envelope::new(
        Arc::new(provider),
        "a-deployment-wrapping-key-of-decent-length",
    )
    .expect("an envelope")
}

/// A realm keeps one profile, its key lands sealed and opens whole, and
/// rewriting the profile keeps the key every linked identity was written
/// under.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_profile_rewritten_keeps_its_key() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    keyring::provision(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    let ring = keyring::load(&transaction, &envelope, "acme", "main")
        .await
        .unwrap();
    assert_eq!(wallet_identity::load(&transaction).await.unwrap(), None);
    assert!(
        wallet_identity::open_digest_key(&transaction, &ring, &envelope)
            .await
            .unwrap()
            .is_none()
    );

    let first = WalletIdentity {
        credential_query: json!({ "id": "identity", "format": "ldp_vc" }),
        issuer: ISSUER.to_owned(),
        identifier_path: vec!["credentialSubject".to_owned(), "UIN".to_owned()],
        updated_by: "root".to_owned(),
        updated_at: now(),
    };
    wallet_identity::keep(
        &transaction,
        &ring,
        &envelope,
        &first,
        b"the key drawn first",
    )
    .await
    .unwrap();
    assert_eq!(
        wallet_identity::load(&transaction).await.unwrap(),
        Some(first)
    );
    let stored: Vec<u8> = transaction
        .query_one("SELECT sealed_digest_key FROM realm_wallet_identity", &[])
        .await
        .unwrap()
        .get(0);
    assert!(
        crypto::envelope::is_sealed(&stored),
        "the key was stored unsealed"
    );

    let rewritten = WalletIdentity {
        credential_query: json!({ "id": "identity", "format": "dc+sd-jwt" }),
        issuer: "https://issuer.example".to_owned(),
        identifier_path: vec!["national_id".to_owned()],
        updated_by: "someone".to_owned(),
        updated_at: now(),
    };
    wallet_identity::keep(
        &transaction,
        &ring,
        &envelope,
        &rewritten,
        b"a key drawn again",
    )
    .await
    .unwrap();
    assert_eq!(
        wallet_identity::load(&transaction).await.unwrap(),
        Some(rewritten)
    );
    let opened = wallet_identity::open_digest_key(&transaction, &ring, &envelope)
        .await
        .unwrap()
        .expect("a key");
    assert_eq!(opened.expose_secret().as_slice(), b"the key drawn first");
}
