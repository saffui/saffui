mod support;

use chrono::{DateTime, Duration, Utc};
use models::auditable::AuditableModel;
use models::entities::credential_issuers::{CredentialIssuer, IssuerTrust};
use models::entities::realm::RealmCreateModel;
use serde_json::json;
use store::providers::realms::credential_issuers;
use store::providers::realms::status_lists::{self, DueList, KeptReading, ListSigners};
use store::tenancy::{TenantContext, UnitOfWork};
use support::Fixture;

const LIST: &str = "https://issuer.example/statuslists/1";

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time")
}

async fn name_issuer(transaction: &UnitOfWork, issuer_id: &str) {
    credential_issuers::name(
        transaction,
        &CredentialIssuer {
            issuer_id: issuer_id.into(),
            name: issuer_id.into(),
            issuer: format!("https://{issuer_id}.example"),
            trust: IssuerTrust::Metadata {
                keys: vec![json!({ "kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "k1" })],
                read_from: format!("https://{issuer_id}.example/.well-known/jwt-vc-issuer"),
                read_at: now(),
            },
            created_by: "admin".into(),
            created_at: now(),
        },
    )
    .await
    .expect("an issuer named");
}

fn reading<'a>(
    format: &'a str,
    statuses: &'a [u8],
    issued_at: Option<DateTime<Utc>>,
    at: DateTime<Utc>,
) -> KeptReading<'a> {
    KeptReading {
        issuer_id: "i1",
        uri: LIST,
        format,
        statuses,
        bits: (format == "token").then_some(1),
        purposes: None,
        issued_at,
        read_at: at,
        usable_until: at + Duration::hours(24),
        due_at: at + Duration::hours(1),
    }
}

/// A list is written down by its first citation, claimed by one reader when
/// due, and read one byte at a time once a reading is kept.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_list_is_written_down_once_claimed_once_and_read_a_byte_at_a_time() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    name_issuer(&transaction, "i1").await;
    let now = now();

    assert_eq!(
        status_lists::read_cited(&transaction, "i1", LIST, "token", 0)
            .await
            .unwrap(),
        None
    );
    for _ in 0..2 {
        assert!(
            status_lists::write_down(&transaction, "i1", LIST, "token", &now, 10)
                .await
                .unwrap()
        );
    }
    let cited = status_lists::read_cited(&transaction, "i1", LIST, "token", 0)
        .await
        .unwrap()
        .expect("the list written down");
    assert_eq!(
        (cited.reading, cited.failed, cited.cited_at),
        (None, false, now)
    );

    let again_at = now + Duration::minutes(5);
    let claimed = status_lists::claim_due(&transaction, &now, &again_at, 20)
        .await
        .unwrap();
    assert_eq!(
        claimed,
        vec![DueList {
            issuer_id: "i1".into(),
            uri: LIST.into(),
            format: "token".into(),
            issuer: "https://i1.example".into(),
            signers: ListSigners::Keys(vec![
                json!({ "kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "k1" })
            ]),
            issued_at: None,
        }]
    );
    assert!(
        status_lists::claim_due(&transaction, &now, &again_at, 20)
            .await
            .unwrap()
            .is_empty(),
        "a claimed list was claimed twice"
    );
    assert_eq!(
        status_lists::claim_due(
            &transaction,
            &again_at,
            &(again_at + Duration::minutes(5)),
            20
        )
        .await
        .unwrap()
        .len(),
        1,
        "a list not read was not tried again"
    );

    status_lists::note_unread(&transaction, "i1", LIST, "token", "nothing could be read")
        .await
        .unwrap();
    let tried = || async {
        status_lists::read_cited(&transaction, "i1", LIST, "token", 0)
            .await
            .unwrap()
            .expect("the list written down")
    };
    let failed = tried().await;
    assert_eq!((failed.reading, failed.failed), (None, true));
    assert!(
        status_lists::keep_reading(
            &transaction,
            &reading("token", &[0xb9, 0xa3], Some(now), now)
        )
        .await
        .unwrap()
    );
    assert!(
        !tried().await.failed,
        "a reading kept left the failure said"
    );
    let byte_at = |index| {
        let transaction = &transaction;
        async move {
            status_lists::read_cited(transaction, "i1", LIST, "token", index)
                .await
                .unwrap()
                .and_then(|cited| cited.reading)
                .expect("a reading")
        }
    };
    let first = byte_at(0).await;
    assert_eq!(
        (first.octets, first.bits, first.byte, first.usable_until),
        (2, Some(1), Some(0xb9), now + Duration::hours(24))
    );
    assert_eq!(byte_at(7).await.byte, Some(0xb9));
    assert_eq!(byte_at(8).await.byte, Some(0xa3));
    assert_eq!(byte_at(16).await.byte, None);

    // Four statuses to a byte: the fifth is in the second.
    let wide = KeptReading {
        bits: Some(2),
        ..reading("token", &[0xc9, 0x44, 0xf9], Some(now), now)
    };
    assert!(
        status_lists::keep_reading(&transaction, &wide)
            .await
            .unwrap()
    );
    assert_eq!(byte_at(4).await.byte, Some(0x44));
    assert_eq!(byte_at(11).await.byte, Some(0xf9));
    assert_eq!(byte_at(12).await.byte, None);
}

/// An older writing of a list served again does not replace a newer one, and
/// why a reading was not kept is said without losing the one kept.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_older_writing_never_replaces_the_one_kept() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    name_issuer(&transaction, "i1").await;
    let now = now();
    assert!(
        status_lists::write_down(&transaction, "i1", LIST, "token", &now, 10)
            .await
            .unwrap()
    );
    assert!(
        status_lists::keep_reading(&transaction, &reading("token", &[1], Some(now), now))
            .await
            .unwrap()
    );
    let earlier = Some(now - Duration::seconds(1));
    assert!(
        !status_lists::keep_reading(&transaction, &reading("token", &[0], earlier, now))
            .await
            .unwrap()
    );
    for (issued_at, byte) in [(Some(now), 2), (Some(now + Duration::seconds(1)), 3)] {
        assert!(
            status_lists::keep_reading(&transaction, &reading("token", &[byte], issued_at, now))
                .await
                .unwrap()
        );
    }

    status_lists::note_unread(&transaction, "i1", LIST, "token", "nothing could be read")
        .await
        .unwrap();
    let row = transaction
        .query_one(
            "SELECT failure, statuses FROM credential_status_lists WHERE uri = $1",
            &[&LIST],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, Option<String>>(0).as_deref(),
        Some("nothing could be read")
    );
    assert_eq!(row.get::<_, Vec<u8>>(1), [3]);
    assert!(
        status_lists::keep_reading(
            &transaction,
            &reading("token", &[4], Some(now + Duration::seconds(2)), now)
        )
        .await
        .unwrap()
    );
    let failure: Option<String> = transaction
        .query_one(
            "SELECT failure FROM credential_status_lists WHERE uri = $1",
            &[&LIST],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(failure, None, "a reading kept left the old failure");
}

/// A realm writes down as many lists as it keeps and no more; the sweep
/// forgets the ones no credential cited for long, and an issuer forgotten
/// takes its lists with it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_keeps_a_bounded_number_of_lists_and_forgets_the_uncited() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    name_issuer(&transaction, "i1").await;
    name_issuer(&transaction, "i2").await;
    let now = now();
    let list = |at: usize| format!("{LIST}/{at}");
    for at in 0..2 {
        assert!(
            status_lists::write_down(&transaction, "i1", &list(at), "bitstring", &now, 2)
                .await
                .unwrap()
        );
    }
    assert!(
        !status_lists::write_down(&transaction, "i2", &list(2), "bitstring", &now, 2)
            .await
            .unwrap(),
        "a third list was written down past the bound"
    );
    assert!(
        status_lists::write_down(&transaction, "i1", &list(1), "bitstring", &now, 2)
            .await
            .unwrap(),
        "a list already kept was refused at the bound"
    );

    let month_ago = now - Duration::days(31);
    status_lists::note_cited(&transaction, "i1", &list(0), "bitstring", &month_ago)
        .await
        .unwrap();
    assert_eq!(
        status_lists::drop_uncited(&transaction, now - Duration::days(30))
            .await
            .unwrap(),
        1
    );
    assert!(
        status_lists::read_cited(&transaction, "i1", &list(0), "bitstring", 0)
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        credential_issuers::forget(&transaction, "i1")
            .await
            .unwrap()
    );
    assert!(
        status_lists::read_cited(&transaction, "i1", &list(1), "bitstring", 0)
            .await
            .unwrap()
            .is_none(),
        "an issuer forgotten left its lists behind"
    );
}

/// What one realm wrote down another never reads nor claims.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_never_reads_or_claims_another_realms_lists() {
    let fixture = Fixture::with_user().await;
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

    let now = now();
    let main = fixture.scoped(&TenantContext::new("acme", "main")).await;
    name_issuer(&main, "i1").await;
    assert!(
        status_lists::write_down(&main, "i1", LIST, "token", &now, 10)
            .await
            .unwrap()
    );
    main.commit().await.unwrap();

    let elsewhere = fixture.scoped(&TenantContext::new("acme", "other")).await;
    assert!(
        status_lists::read_cited(&elsewhere, "i1", LIST, "token", 0)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        status_lists::claim_due(&elsewhere, &now, &now, 20)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The schema holds a reading whole: statuses, when they were read and until
/// when they hold, together, with the bits of a token list or the purposes of
/// a bitstring one and never the other's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_holds_a_reading_whole() {
    let fixture = Fixture::with_user().await;
    let setup = fixture.scoped(&TenantContext::new("acme", "main")).await;
    name_issuer(&setup, "i1").await;
    let now = now();
    for format in ["token", "bitstring"] {
        assert!(
            status_lists::write_down(&setup, "i1", LIST, format, &now, 10)
                .await
                .unwrap()
        );
    }
    setup.commit().await.unwrap();

    for (format, set, refused) in [
        ("token", "statuses = '\\x01'", "status_list_read_whole"),
        (
            "token",
            "statuses = '\\x01', read_at = now(), usable_until = now()",
            "status_list_read_whole",
        ),
        ("token", "bits = 3", "status_list_bits_of_a_token"),
        ("bitstring", "bits = 1", "status_list_bits_of_a_token"),
        (
            "token",
            "purposes = ARRAY['revocation']",
            "status_list_purposes_of_a_bitstring",
        ),
        (
            "bitstring",
            "purposes = ARRAY[]::text[]",
            "status_list_purposes_of_a_bitstring",
        ),
        (
            "bitstring",
            "statuses = '\\x01', read_at = now(), usable_until = now()",
            "status_list_read_whole",
        ),
        (
            "token",
            "statuses = ''::bytea, read_at = now(), usable_until = now(), bits = 1",
            "status_list_statuses_bounded",
        ),
        (
            "token",
            "failure = repeat('x', 201)",
            "status_list_failure_bounded",
        ),
        ("token", "format = 'list'", "status_list_format_known"),
    ] {
        let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
        let written = transaction
            .execute(
                &format!("UPDATE credential_status_lists SET {set} WHERE format = $1"),
                &[&format],
            )
            .await;
        let refusal = written.expect_err(set);
        assert_eq!(
            refusal.as_db_error().and_then(|said| said.constraint()),
            Some(refused),
            "{set}: {refusal:?}"
        );
    }
}
