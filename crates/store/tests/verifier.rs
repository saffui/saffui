mod support;

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use crypto::envelope::Envelope;
use crypto::provider::CryptoConfig;
use crypto::provider::openssl::OpenSslProvider;
use models::auditable::AuditableModel;
use models::entities::realm::RealmCreateModel;
use models::entities::verifier::{
    DrawnVerifierKey, VerifierCertificate, VerifierIdentity, VerifierKeyState, VerifierKeyView,
    VerifierSettings, VerifierSubject,
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;
use store::error::StoreError;
use store::keyring::{self, RealmKeyring};
use store::providers::realms::verifier;
use store::tenancy::{TenantContext, UnitOfWork};
use support::Fixture;

const FIRST: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
const SECOND: &str = "Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk";
const FIRST_LEAF: &str = "oST1OQsEqOeGVjJrgHPaSim113iQI7fDscV2VMlmFeA";
const SECOND_LEAF: &str = "UqclKpel4f3VqiTTW-sG5XiuLvJ90aII3S7f-zJ13lE";

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time")
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

async fn ring_of(transaction: &UnitOfWork, envelope: &Envelope, realm: &str) -> RealmKeyring {
    keyring::provision(transaction, envelope, "acme", realm)
        .await
        .unwrap();
    keyring::load(transaction, envelope, "acme", realm)
        .await
        .unwrap()
}

fn subject() -> VerifierSubject {
    VerifierSubject {
        common_name: "Acme verifier".to_owned(),
        organization: Some("Acme SA".to_owned()),
        organization_identifier: Some("VATFR-12345678901".to_owned()),
        country: Some("FR".to_owned()),
    }
}

fn drawn(kid: &str, private: &[u8], at: DateTime<Utc>) -> DrawnVerifierKey {
    DrawnVerifierKey {
        kid: kid.to_owned(),
        private_pem: SecretBox::new(Box::new(private.to_vec())),
        public_jwk: json!({ "kty": "EC", "crv": "P-256", "kid": kid }),
        subject: subject(),
        request_pem: format!("request for {kid}"),
        created_by: "root".to_owned(),
        created_at: at,
    }
}

fn certificate(leaf: &[u8], leaf_hash: &str, at: DateTime<Utc>) -> VerifierCertificate {
    VerifierCertificate {
        chain: vec![leaf.to_vec(), b"access ca".to_vec()],
        leaf_hash: leaf_hash.to_owned(),
        not_before: at - Duration::hours(1),
        not_after: at + Duration::days(365),
        certified_at: at,
    }
}

fn kids(keys: &[VerifierKeyView]) -> Vec<(&str, VerifierKeyState)> {
    keys.iter()
        .map(|key| (key.kid.as_str(), key.state))
        .collect()
}

/// A key awaits its certificate signing nothing, serves once one is taken
/// for it, and a key certified after it serves in its place, the first
/// dropped. One key awaits at most.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_key_awaits_its_certificate_then_serves_in_place_of_the_last() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let main = TenantContext::new("acme", "main");
    let at = now();
    let transaction = fixture.scoped(&main).await;
    let ring = ring_of(&transaction, &envelope, "main").await;
    assert!(verifier::list_keys(&transaction).await.unwrap().is_empty());
    assert!(
        verifier::hold_awaiting(&transaction)
            .await
            .unwrap()
            .is_none()
    );
    verifier::keep_drawn(&transaction, &ring, &envelope, &drawn(FIRST, b"first", at))
        .await
        .unwrap();
    assert!(
        verifier::open_serving(&transaction, &ring, &envelope)
            .await
            .unwrap()
            .is_none(),
        "a key awaiting its certificate serves"
    );
    let awaiting = verifier::hold_awaiting(&transaction)
        .await
        .unwrap()
        .expect("the key drawn");
    assert_eq!(
        awaiting,
        VerifierKeyView {
            kid: FIRST.to_owned(),
            state: VerifierKeyState::Awaiting,
            public_jwk: json!({ "kty": "EC", "crv": "P-256", "kid": FIRST }),
            subject: subject(),
            request_pem: format!("request for {FIRST}"),
            certificate: None,
            created_by: "root".to_owned(),
            created_at: at,
        }
    );
    let stored = transaction
        .query_one(
            "SELECT sealed_key, sealed_version FROM realm_verifier_keys",
            &[],
        )
        .await
        .unwrap();
    let sealed: Vec<u8> = stored.get(0);
    assert!(
        crypto::envelope::is_sealed(&sealed),
        "the key was stored unsealed"
    );
    assert_eq!(stored.get::<_, i32>(1), ring.active_version() as i32);
    // Sealed for its own purpose and row: it opens as nothing else, not even
    // as one of the realm's signing keys of the same identifier.
    assert!(
        ring.open(&envelope, "verifier-key", FIRST, &sealed)
            .await
            .is_ok()
    );
    for (purpose, id) in [("realm-signing-key", FIRST), ("verifier-key", SECOND)] {
        assert!(
            ring.open(&envelope, purpose, id, &sealed).await.is_err(),
            "the key opened as {purpose} {id}"
        );
    }
    transaction.commit().await.unwrap();

    let transaction = fixture.scoped(&main).await;
    assert_eq!(
        verifier::keep_drawn(
            &transaction,
            &ring,
            &envelope,
            &drawn(SECOND, b"second", at)
        )
        .await,
        Err(StoreError::AlreadyExists),
        "a second key awaits"
    );
    drop(transaction);

    let transaction = fixture.scoped(&main).await;
    let first = certificate(b"first leaf", FIRST_LEAF, at);
    assert!(
        verifier::certify(&transaction, FIRST, &first)
            .await
            .unwrap()
    );
    assert!(
        !verifier::certify(&transaction, FIRST, &first)
            .await
            .unwrap(),
        "a key was certified twice"
    );
    let serving = verifier::open_serving(&transaction, &ring, &envelope)
        .await
        .unwrap()
        .expect("the key certified");
    assert_eq!(
        (
            serving.kid.as_str(),
            serving.private_pem.expose_secret().as_slice(),
            &serving.certificate
        ),
        (FIRST, b"first".as_slice(), &first)
    );
    verifier::keep_drawn(
        &transaction,
        &ring,
        &envelope,
        &drawn(SECOND, b"second", at),
    )
    .await
    .unwrap();
    assert_eq!(
        kids(&verifier::list_keys(&transaction).await.unwrap()),
        [
            (FIRST, VerifierKeyState::Serving),
            (SECOND, VerifierKeyState::Awaiting)
        ]
    );

    let second = certificate(b"second leaf", SECOND_LEAF, at);
    assert!(
        verifier::certify(&transaction, SECOND, &second)
            .await
            .unwrap()
    );
    let held = verifier::list_keys(&transaction).await.unwrap();
    assert_eq!(kids(&held), [(SECOND, VerifierKeyState::Serving)]);
    assert_eq!(held[0].certificate.as_ref(), Some(&second));
    let serving = verifier::open_serving(&transaction, &ring, &envelope)
        .await
        .unwrap()
        .expect("the key certified");
    assert_eq!(serving.private_pem.expose_secret().as_slice(), b"second");

    assert!(verifier::withdraw(&transaction, SECOND).await.unwrap());
    assert!(!verifier::withdraw(&transaction, SECOND).await.unwrap());
    assert!(verifier::list_keys(&transaction).await.unwrap().is_empty());
}

/// How a realm presents itself is kept whole, and rewritten whole.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_settings_are_kept_and_rewritten_whole() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    assert_eq!(verifier::load_settings(&transaction).await.unwrap(), None);
    let europe = VerifierSettings {
        identity: VerifierIdentity::X509Hash,
        registrar_dataset: Some(json!({
            "identifier": [{ "type": "http://data.europa.eu/eudi/id/LEI-code", "identifier": "529900T8BM49AURSDO55" }],
            "registryURI": "https://registrar.example/rp/acme",
        })),
        registration_certificate: Some("eyJ0eXAiOiJyYy13cnArand0In0.e30.c2ln".to_owned()),
        updated_by: "root".to_owned(),
        updated_at: now(),
    };
    verifier::keep_settings(&transaction, &europe)
        .await
        .unwrap();
    assert_eq!(
        verifier::load_settings(&transaction).await.unwrap(),
        Some(europe)
    );
    let plain = VerifierSettings {
        identity: VerifierIdentity::DidWeb,
        registrar_dataset: None,
        registration_certificate: None,
        updated_by: "someone".to_owned(),
        updated_at: now() + Duration::seconds(1),
    };
    verifier::keep_settings(&transaction, &plain).await.unwrap();
    assert_eq!(
        verifier::load_settings(&transaction).await.unwrap(),
        Some(plain)
    );
}

/// What one realm keeps of its verifier another never reads, opens nor
/// withdraws.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_never_reads_another_realms_verifier() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let tenant_wide = fixture.scoped(&TenantContext::tenant_wide("acme")).await;
    let other = RealmCreateModel {
        name: "other".into(),
        display_name: "Other".into(),
        enabled: true,
    }
    .into_model(
        "other".into(),
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    store::providers::realms::create(&tenant_wide, &other)
        .await
        .unwrap();
    tenant_wide.commit().await.unwrap();

    let at = now();
    let main = fixture.scoped(&TenantContext::new("acme", "main")).await;
    let ring = ring_of(&main, &envelope, "main").await;
    verifier::keep_drawn(&main, &ring, &envelope, &drawn(FIRST, b"first", at))
        .await
        .unwrap();
    assert!(
        verifier::certify(&main, FIRST, &certificate(b"first leaf", FIRST_LEAF, at))
            .await
            .unwrap()
    );
    verifier::keep_drawn(&main, &ring, &envelope, &drawn(SECOND, b"second", at))
        .await
        .unwrap();
    verifier::keep_settings(
        &main,
        &VerifierSettings {
            identity: VerifierIdentity::X509Hash,
            registrar_dataset: None,
            registration_certificate: None,
            updated_by: "root".to_owned(),
            updated_at: at,
        },
    )
    .await
    .unwrap();
    main.commit().await.unwrap();

    let elsewhere = fixture.scoped(&TenantContext::new("acme", "other")).await;
    let ring = ring_of(&elsewhere, &envelope, "other").await;
    assert_eq!(verifier::load_settings(&elsewhere).await.unwrap(), None);
    assert!(verifier::list_keys(&elsewhere).await.unwrap().is_empty());
    assert!(verifier::hold_awaiting(&elsewhere).await.unwrap().is_none());
    assert!(
        verifier::open_serving(&elsewhere, &ring, &envelope)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !verifier::certify(
            &elsewhere,
            SECOND,
            &certificate(b"second leaf", SECOND_LEAF, at)
        )
        .await
        .unwrap()
    );
    assert!(!verifier::withdraw(&elsewhere, FIRST).await.unwrap());
    elsewhere.commit().await.unwrap();

    let main = fixture.scoped(&TenantContext::new("acme", "main")).await;
    assert_eq!(
        kids(&verifier::list_keys(&main).await.unwrap()),
        [
            (FIRST, VerifierKeyState::Serving),
            (SECOND, VerifierKeyState::Awaiting)
        ]
    );
}

/// The schema holds a key whole: a certificate's parts present together and
/// only on a key in service, one key serving per realm, and every value in
/// the form it is read back in; and the settings name an identity it knows.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_holds_a_key_and_the_settings_whole() {
    let fixture = Fixture::with_user().await;
    let envelope = envelope();
    let main = TenantContext::new("acme", "main");
    let at = now();
    let setup = fixture.scoped(&main).await;
    let ring = ring_of(&setup, &envelope, "main").await;
    verifier::keep_drawn(&setup, &ring, &envelope, &drawn(FIRST, b"first", at))
        .await
        .unwrap();
    assert!(
        verifier::certify(&setup, FIRST, &certificate(b"first leaf", FIRST_LEAF, at))
            .await
            .unwrap()
    );
    verifier::keep_drawn(&setup, &ring, &envelope, &drawn(SECOND, b"second", at))
        .await
        .unwrap();
    verifier::keep_settings(
        &setup,
        &VerifierSettings {
            identity: VerifierIdentity::DidWeb,
            registrar_dataset: None,
            registration_certificate: None,
            updated_by: "root".to_owned(),
            updated_at: at,
        },
    )
    .await
    .unwrap();
    setup.commit().await.unwrap();

    let certified = "chain = ARRAY['\\x01'::bytea], \
                     leaf_hash = 'oST1OQsEqOeGVjJrgHPaSim113iQI7fDscV2VMlmFeA', \
                     not_before = now(), not_after = now(), certified_at = now()";
    for (table, which, set, refused) in [
        (
            "realm_verifier_keys",
            "state = 'awaiting'",
            "state = 'serving'".to_owned(),
            "verifier_key_certified_whole",
        ),
        (
            "realm_verifier_keys",
            "state = 'awaiting'",
            certified.to_owned(),
            "verifier_key_certified_whole",
        ),
        (
            "realm_verifier_keys",
            "state = 'serving'",
            "leaf_hash = NULL".to_owned(),
            "verifier_key_certified_whole",
        ),
        (
            "realm_verifier_keys",
            "state = 'serving'",
            "certified_at = NULL".to_owned(),
            "verifier_key_certified_whole",
        ),
        (
            "realm_verifier_keys",
            "state = 'awaiting'",
            format!("state = 'serving', {certified}"),
            "realm_verifier_keys_one_serving",
        ),
        (
            "realm_verifier_keys",
            "state = 'serving'",
            "state = 'retired'".to_owned(),
            "verifier_key_state_known",
        ),
        (
            "realm_verifier_keys",
            "state = 'serving'",
            "chain = ARRAY[]::bytea[]".to_owned(),
            "verifier_key_chain_bounded",
        ),
        (
            "realm_verifier_keys",
            "state = 'serving'",
            "chain = array_fill('\\x01'::bytea, ARRAY[10])".to_owned(),
            "verifier_key_chain_bounded",
        ),
        (
            "realm_verifier_keys",
            "state = 'serving'",
            "leaf_hash = 'b2e7f1'".to_owned(),
            "verifier_key_hash_written",
        ),
        (
            "realm_verifier_keys",
            "state = 'awaiting'",
            "kid = 'k-1'".to_owned(),
            "verifier_key_kid_written",
        ),
        (
            "realm_verifier_keys",
            "state = 'awaiting'",
            "request_pem = repeat('x', 8193)".to_owned(),
            "verifier_key_request_bounded",
        ),
        (
            "realm_verifier_settings",
            "true",
            "identity = 'x509_san_dns'".to_owned(),
            "verifier_identity_known",
        ),
        (
            "realm_verifier_settings",
            "true",
            "registrar_dataset = '[]'".to_owned(),
            "verifier_dataset_an_object",
        ),
        (
            "realm_verifier_settings",
            "true",
            "registrar_dataset = jsonb_build_object('purpose', repeat('x', 16384))".to_owned(),
            "verifier_dataset_an_object",
        ),
        (
            "realm_verifier_settings",
            "true",
            "registration_certificate = ''".to_owned(),
            "verifier_registration_bounded",
        ),
    ] {
        let transaction = fixture.scoped(&main).await;
        let written = transaction
            .execute(&format!("UPDATE {table} SET {set} WHERE {which}"), &[])
            .await;
        let refusal = written.expect_err(&set);
        assert_eq!(
            refusal.as_db_error().and_then(|said| said.constraint()),
            Some(refused),
            "{set}: {refusal:?}"
        );
    }
}
