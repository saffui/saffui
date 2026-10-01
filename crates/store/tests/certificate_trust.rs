mod support;

use chrono::{DateTime, Duration, Utc};
use models::auditable::AuditableModel;
use models::entities::credential_issuers::{CredentialIssuer, IssuerTrust};
use models::entities::realm::RealmCreateModel;
use models::entities::trust_anchors::{TrustAnchor, TrustAnchorRole};
use serde_json::json;
use store::error::StoreError;
use store::providers::realms::revocation_lists::{
    self, DueRevocationList, KeptRevocations, ListPlace, NamedList,
};
use store::providers::realms::status_lists::{self, ListSigners};
use store::providers::realms::{credential_issuers, trust_anchors};
use store::tenancy::{TenantContext, UnitOfWork};
use support::Fixture;

const LIST: &str = "https://ca.example/root.crl";
const DIGEST: &str = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11";

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time")
}

async fn deposit(transaction: &UnitOfWork, anchor_id: &str) {
    trust_anchors::deposit(
        transaction,
        &TrustAnchor {
            anchor_id: anchor_id.into(),
            role: TrustAnchorRole::CredentialIssuer,
            certificate: format!("certificate of {anchor_id}").into_bytes(),
            fingerprint: format!(
                "{:0>64}",
                anchor_id
                    .bytes()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            subject: format!("CN={anchor_id}"),
            key_identifier: None,
            not_after: now() + Duration::days(365),
            created_by: "admin".into(),
            created_at: now(),
        },
    )
    .await
    .expect("an authority deposited");
}

fn by_certificate(issuer_id: &str, anchors: &[&str], types: &[&str]) -> CredentialIssuer {
    CredentialIssuer {
        issuer_id: issuer_id.into(),
        name: issuer_id.into(),
        issuer: format!("https://{issuer_id}.example"),
        trust: IssuerTrust::Certificate {
            anchors: anchors.iter().map(|anchor| (*anchor).to_owned()).collect(),
            credential_types: types.iter().map(|vct| (*vct).to_owned()).collect(),
        },
        created_by: "admin".into(),
        created_at: now(),
    }
}

fn by_metadata(issuer_id: &str) -> CredentialIssuer {
    CredentialIssuer {
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
    }
}

/// An issuer trusted by certificate is kept with the authorities and the types
/// named for it, read back the same, given other authorities and types, and an
/// authority it is trusted through is withdrawn only once no issuer is.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_issuer_is_trusted_through_the_authorities_named_for_it() {
    let fixture = Fixture::with_user().await;
    let main = TenantContext::new("acme", "main");
    let transaction = fixture.scoped(&main).await;
    for anchor in ["a1", "a2", "a3"] {
        deposit(&transaction, anchor).await;
    }
    let certified = by_certificate("i1", &["a2", "a1"], &["urn:eudi:pid:1"]);
    credential_issuers::name(&transaction, &certified)
        .await
        .unwrap();
    credential_issuers::name(&transaction, &by_metadata("i2"))
        .await
        .unwrap();
    // Another issuer trusted through one of the same authorities: each is
    // read back with its own.
    credential_issuers::name(&transaction, &by_certificate("i4", &["a2"], &["urn:x"]))
        .await
        .unwrap();
    let held = credential_issuers::load(&transaction, "i1")
        .await
        .unwrap()
        .expect("the issuer");
    assert_eq!(
        held,
        by_certificate("i1", &["a1", "a2"], &["urn:eudi:pid:1"])
    );
    assert_eq!(
        credential_issuers::by_issuer(&transaction, "https://i1.example")
            .await
            .unwrap(),
        Some(held)
    );
    assert_eq!(
        credential_issuers::anchor_certificates(&transaction, "i1")
            .await
            .unwrap(),
        [b"certificate of a1".to_vec(), b"certificate of a2".to_vec()]
    );
    assert!(
        credential_issuers::anchor_certificates(&transaction, "i2")
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        credential_issuers::list(&transaction)
            .await
            .unwrap()
            .iter()
            .map(|named| named.issuer_id.as_str())
            .collect::<Vec<_>>(),
        ["i1", "i2", "i4"]
    );
    assert_eq!(
        credential_issuers::anchor_certificates(&transaction, "i4")
            .await
            .unwrap(),
        [b"certificate of a2".to_vec()]
    );

    let types = ["urn:eudi:pid:1".to_owned(), "urn:eudi:mdl:1".to_owned()];
    assert!(
        credential_issuers::replace_certificate_trust(
            &transaction,
            "i1",
            &["a3".to_owned()],
            &types
        )
        .await
        .unwrap()
    );
    assert_eq!(
        credential_issuers::load(&transaction, "i1")
            .await
            .unwrap()
            .map(|named| named.trust),
        Some(IssuerTrust::Certificate {
            anchors: vec!["a3".to_owned()],
            credential_types: types.to_vec(),
        })
    );
    for issuer_id in ["i2", "nobody"] {
        assert!(
            !credential_issuers::replace_certificate_trust(&transaction, issuer_id, &[], &types)
                .await
                .unwrap(),
            "{issuer_id}"
        );
    }
    assert!(
        !credential_issuers::replace_keys(&transaction, "i1", &[json!({})], "https://x", &now())
            .await
            .unwrap(),
        "an issuer trusted by certificate was given keys"
    );
    assert!(trust_anchors::withdraw(&transaction, "a1").await.unwrap());
    transaction.commit().await.unwrap();

    let transaction = fixture.scoped(&main).await;
    assert_eq!(
        trust_anchors::withdraw(&transaction, "a3").await,
        Err(StoreError::BrokenRule {
            rule: "credential_issuer_anchors_anchor".to_owned()
        }),
        "an authority an issuer is trusted through was withdrawn"
    );
    drop(transaction);
    let transaction = fixture.scoped(&main).await;
    assert!(
        credential_issuers::forget(&transaction, "i1")
            .await
            .unwrap()
    );
    assert!(trust_anchors::withdraw(&transaction, "a3").await.unwrap());
    transaction.commit().await.unwrap();

    let transaction = fixture.scoped(&main).await;
    assert_eq!(
        credential_issuers::name(&transaction, &by_certificate("i3", &["a9"], &["urn:x"])).await,
        Err(StoreError::BrokenRule {
            rule: "credential_issuer_anchors_anchor".to_owned()
        }),
        "an issuer was trusted through an authority the realm does not trust"
    );
}

/// The pass reads a list of an issuer trusted by certificate under the
/// authorities it is trusted through, and one of an issuer trusted by its
/// metadata under its keys.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_status_list_is_read_under_what_its_issuer_is_trusted_by() {
    let fixture = Fixture::with_user().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    for (anchor, issuer_id) in [("a1", "i1"), ("a2", "i3")] {
        deposit(&transaction, anchor).await;
        credential_issuers::name(
            &transaction,
            &by_certificate(issuer_id, &[anchor], &["urn:x"]),
        )
        .await
        .unwrap();
    }
    credential_issuers::name(&transaction, &by_metadata("i2"))
        .await
        .unwrap();
    let at = now();
    for issuer_id in ["i1", "i2", "i3"] {
        assert!(
            status_lists::write_down(&transaction, issuer_id, LIST, "token", &at, 10)
                .await
                .unwrap()
        );
    }
    let mut claimed = status_lists::claim_due(&transaction, &at, &(at + Duration::minutes(5)), 10)
        .await
        .unwrap();
    claimed.sort_by(|one, other| one.issuer_id.cmp(&other.issuer_id));
    assert_eq!(
        claimed
            .into_iter()
            .map(|due| (due.issuer_id, due.signers))
            .collect::<Vec<_>>(),
        [
            (
                "i1".to_owned(),
                ListSigners::Anchors(vec![b"certificate of a1".to_vec()])
            ),
            (
                "i2".to_owned(),
                ListSigners::Keys(vec![
                    json!({ "kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "k1" })
                ])
            ),
            (
                "i3".to_owned(),
                ListSigners::Anchors(vec![b"certificate of a2".to_vec()])
            ),
        ]
    );
}

fn place(issuer_id: &str) -> ListPlace<'_> {
    ListPlace {
        issuer_id,
        uri: LIST,
        authority_digest: DIGEST,
    }
}

/// A reading of the list at `place("i1")` made at `at`, issued at `issued_at`.
fn kept(revoked: &[Vec<u8>], issued_at: DateTime<Utc>, at: DateTime<Utc>) -> KeptRevocations<'_> {
    kept_at(place("i1"), revoked, issued_at, at)
}

fn kept_at<'a>(
    place: ListPlace<'a>,
    revoked: &'a [Vec<u8>],
    issued_at: DateTime<Utc>,
    at: DateTime<Utc>,
) -> KeptRevocations<'a> {
    KeptRevocations {
        place,
        revoked,
        issued_at,
        read_at: at,
        usable_until: at + Duration::hours(6),
        due_at: at + Duration::hours(1),
    }
}

/// A revocation list is written down by the first certificate naming it,
/// claimed by one reader when due, kept with the serials it revokes, never
/// replaced by an older list, and forgotten once no certificate names it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_revocation_list_is_written_down_claimed_and_read_a_serial_at_a_time() {
    let fixture = Fixture::with_user().await;
    let main = TenantContext::new("acme", "main");
    let transaction = fixture.scoped(&main).await;
    credential_issuers::name(&transaction, &by_metadata("i1"))
        .await
        .unwrap();
    let at = now();
    assert_eq!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x01])
            .await
            .unwrap(),
        None
    );
    assert!(
        revocation_lists::write_down(&transaction, &place("i1"), b"authority", &at, 2)
            .await
            .unwrap()
    );
    assert!(
        revocation_lists::write_down(&transaction, &place("i1"), b"authority", &at, 2)
            .await
            .unwrap(),
        "a list written down twice"
    );
    let other = ListPlace {
        uri: "https://ca.example/other.crl",
        ..place("i1")
    };
    assert!(
        revocation_lists::write_down(&transaction, &other, b"authority", &at, 2)
            .await
            .unwrap()
    );
    let full = ListPlace {
        uri: "https://ca.example/third.crl",
        ..place("i1")
    };
    assert!(
        !revocation_lists::write_down(&transaction, &full, b"authority", &at, 2)
            .await
            .unwrap(),
        "a list past the bound written down"
    );
    assert_eq!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x01])
            .await
            .unwrap(),
        Some(NamedList {
            usable_until: None,
            failed: false,
            revokes: false,
            cited_at: at,
        })
    );

    let again = at + Duration::minutes(5);
    let claimed = revocation_lists::claim_due(&transaction, &at, &again, 1)
        .await
        .unwrap();
    assert_eq!(
        claimed,
        [DueRevocationList {
            issuer_id: "i1".into(),
            uri: claimed[0].uri.clone(),
            authority_digest: DIGEST.into(),
            authority: b"authority".to_vec(),
            issued_at: None,
        }]
    );
    let second = revocation_lists::claim_due(&transaction, &at, &again, 10)
        .await
        .unwrap();
    assert_eq!(second.len(), 1, "a claimed list claimed again");
    assert_ne!(second[0].uri, claimed[0].uri);

    let revoked = [vec![0x01], vec![0x02, 0x03]];
    assert!(
        revocation_lists::keep_reading(&transaction, &kept(&revoked, at - Duration::hours(1), at))
            .await
            .unwrap()
    );
    for (serial, revokes) in [
        (&[0x02, 0x03][..], true),
        (&[0x01][..], true),
        (&[0x04][..], false),
    ] {
        assert_eq!(
            revocation_lists::read_named(&transaction, &place("i1"), serial)
                .await
                .unwrap()
                .map(|named| (named.usable_until, named.revokes)),
            Some((Some(at + Duration::hours(6)), revokes)),
            "{serial:?}"
        );
    }
    let fewer = [vec![0x04]];
    assert!(
        !revocation_lists::keep_reading(&transaction, &kept(&fewer, at - Duration::hours(2), at))
            .await
            .unwrap(),
        "an older list kept"
    );
    assert!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x01])
            .await
            .unwrap()
            .is_some_and(|named| named.revokes),
        "an older list undid a revocation"
    );
    assert!(
        revocation_lists::keep_reading(&transaction, &kept(&fewer, at, at))
            .await
            .unwrap()
    );
    assert_eq!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x01])
            .await
            .unwrap()
            .map(|named| named.revokes),
        Some(false),
        "a newer list did not replace what was revoked"
    );
    // A serial still revoked is not written again by the list read anew.
    let written = "SELECT ctid::text FROM certificate_revocations WHERE serial = '\\x04'";
    let before: String = transaction.query_one(written, &[]).await.unwrap().get(0);
    let more = [vec![0x04], vec![0x05]];
    assert!(
        revocation_lists::keep_reading(&transaction, &kept(&more, at, at))
            .await
            .unwrap()
    );
    let after: String = transaction.query_one(written, &[]).await.unwrap().get(0);
    assert_eq!(before, after, "a serial still revoked was written again");
    for (serial, revokes) in [(0x01, false), (0x04, true), (0x05, true)] {
        assert_eq!(
            revocation_lists::read_named(&transaction, &place("i1"), &[serial])
                .await
                .unwrap()
                .map(|named| named.revokes),
            Some(revokes),
            "{serial:#04x}"
        );
    }
    assert!(
        revocation_lists::keep_reading(&transaction, &kept(&fewer, at, at))
            .await
            .unwrap()
    );
    assert_eq!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x05])
            .await
            .unwrap()
            .map(|named| named.revokes),
        Some(false),
        "a serial the list read anew no longer revokes was kept"
    );
    // A serial is revoked by the list of its own place alone: the same
    // address read under another authority or for another issuer, and
    // another address, each revoke what they list and nothing else.
    credential_issuers::name(&transaction, &by_metadata("i2"))
        .await
        .unwrap();
    let another_digest = "bb22".repeat(16);
    let elsewhere = [
        ListPlace {
            authority_digest: &another_digest,
            ..place("i1")
        },
        place("i2"),
        other,
    ];
    let ninth = [vec![0x09]];
    for held in elsewhere {
        assert!(
            revocation_lists::write_down(&transaction, &held, b"authority", &at, 10)
                .await
                .unwrap()
        );
        assert!(
            revocation_lists::keep_reading(&transaction, &kept_at(held, &ninth, at, at))
                .await
                .unwrap()
        );
        for (serial, revokes) in [(0x09, true), (0x04, false)] {
            assert_eq!(
                revocation_lists::read_named(&transaction, &held, &[serial])
                    .await
                    .unwrap()
                    .map(|named| named.revokes),
                Some(revokes),
                "{held:?} {serial:#04x}"
            );
        }
    }
    for (serial, revokes) in [(0x09, false), (0x04, true)] {
        assert_eq!(
            revocation_lists::read_named(&transaction, &place("i1"), &[serial])
                .await
                .unwrap()
                .map(|named| named.revokes),
            Some(revokes),
            "{serial:#04x}"
        );
    }

    revocation_lists::note_unread(&transaction, &place("i1"), "the list could not be read")
        .await
        .unwrap();
    assert!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x04])
            .await
            .unwrap()
            .is_some_and(|named| named.failed && named.revokes && named.usable_until.is_some()),
        "a failure lost the reading kept"
    );
    assert!(
        revocation_lists::keep_reading(&transaction, &kept(&fewer, at, at))
            .await
            .unwrap()
    );
    assert!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x04])
            .await
            .unwrap()
            .is_some_and(|named| !named.failed && named.revokes),
        "a reading kept left the old failure"
    );
    let later = at + Duration::days(1);
    revocation_lists::note_cited(&transaction, &place("i1"), &later)
        .await
        .unwrap();
    assert_eq!(
        revocation_lists::drop_uncited(&transaction, at + Duration::hours(1))
            .await
            .unwrap(),
        3,
        "the lists no certificate named lately were kept"
    );
    assert!(
        revocation_lists::read_named(&transaction, &place("i1"), &[0x04])
            .await
            .unwrap()
            .is_some_and(|named| named.revokes),
        "the list a certificate named lately was forgotten"
    );
    assert!(
        revocation_lists::read_named(&transaction, &other, &[0x01])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        credential_issuers::forget(&transaction, "i1")
            .await
            .unwrap()
    );
    let left: i64 = transaction
        .query_one("SELECT count(*) FROM certificate_revocations", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0, "an issuer forgotten left what its lists revoked");
}

/// What one realm wrote down another never reads nor claims.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_never_reads_another_realms_revocation_lists() {
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

    let at = now();
    let main = fixture.scoped(&TenantContext::new("acme", "main")).await;
    deposit(&main, "a1").await;
    credential_issuers::name(&main, &by_certificate("i1", &["a1"], &["urn:x"]))
        .await
        .unwrap();
    assert!(
        revocation_lists::write_down(&main, &place("i1"), b"authority", &at, 10)
            .await
            .unwrap()
    );
    let revoked = [vec![0x01]];
    assert!(
        revocation_lists::keep_reading(&main, &kept(&revoked, at, at))
            .await
            .unwrap()
    );
    main.commit().await.unwrap();

    let elsewhere = fixture.scoped(&TenantContext::new("acme", "other")).await;
    for table in [
        "realm_credential_issuer_anchors",
        "certificate_revocation_lists",
        "certificate_revocations",
    ] {
        let seen: i64 = elsewhere
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(seen, 0, "{table}");
    }
    assert!(
        revocation_lists::read_named(&elsewhere, &place("i1"), &[0x01])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        revocation_lists::claim_due(&elsewhere, &at, &at, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        credential_issuers::anchor_certificates(&elsewhere, "i1")
            .await
            .unwrap()
            .is_empty()
    );
}

/// The schema holds an issuer's trust whole, and a revocation list's reading.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_holds_trust_and_revocation_whole() {
    let fixture = Fixture::with_user().await;
    let setup = fixture.scoped(&TenantContext::new("acme", "main")).await;
    deposit(&setup, "a1").await;
    credential_issuers::name(&setup, &by_certificate("i1", &["a1"], &["urn:x"]))
        .await
        .unwrap();
    credential_issuers::name(&setup, &by_metadata("i2"))
        .await
        .unwrap();
    assert!(
        revocation_lists::write_down(&setup, &place("i1"), b"authority", &now(), 10)
            .await
            .unwrap()
    );
    setup.commit().await.unwrap();

    for (table, which, set, refused) in [
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "keys = '[{}]'",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "credential_types = '[]'",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "credential_types = NULL",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "read_at = now()",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i2'",
            "credential_types = '[\"urn:x\"]'",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i2'",
            "read_from = NULL",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i2'",
            "keys = '[]'",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "credential_types = (SELECT jsonb_agg(n::text) FROM generate_series(1, 21) n)",
            "credential_issuer_trusted_whole",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i2'",
            "trusted_by = 'ledger'",
            "credential_issuer_trust_known",
        ),
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "credential_types = jsonb_build_array(repeat('x', 8200))",
            "credential_issuer_types_bounded",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "read_at = now()",
            "revocation_list_read_whole",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "issued_at = now(), read_at = now()",
            "revocation_list_read_whole",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "authority_digest = 'AA'",
            "revocation_list_authority_named",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "authority_digest = 'aa11'",
            "revocation_list_authority_named",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "authority = ''::bytea",
            "revocation_list_authority_bounded",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "authority = decode(repeat('00', 16385), 'hex')",
            "revocation_list_authority_bounded",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "uri = ''",
            "revocation_list_uri_bounded",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "uri = repeat('x', 2049)",
            "revocation_list_uri_bounded",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "failure = repeat('x', 201)",
            "revocation_list_failure_bounded",
        ),
    ] {
        let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
        let written = transaction
            .execute(&format!("UPDATE {table} SET {set} WHERE {which}"), &[])
            .await;
        let refusal = written.expect_err(set);
        assert_eq!(
            refusal.as_db_error().and_then(|said| said.constraint()),
            Some(refused),
            "{set}: {refusal:?}"
        );
    }
    // Each bound is kept at its edge.
    for (table, which, set) in [
        (
            "realm_credential_issuers",
            "issuer_id = 'i1'",
            "credential_types = (SELECT jsonb_agg(n::text) FROM generate_series(1, 20) n)",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "authority = decode(repeat('00', 16384), 'hex')",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "uri = repeat('x', 2048)",
        ),
        (
            "certificate_revocation_lists",
            "true",
            "failure = repeat('x', 200)",
        ),
    ] {
        let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
        let written = transaction
            .execute(&format!("UPDATE {table} SET {set} WHERE {which}"), &[])
            .await;
        assert_eq!(written.ok(), Some(1), "{set}");
    }
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    let written = transaction
        .execute(
            "INSERT INTO certificate_revocations \
                 (tenant, realm_id, issuer_id, uri, authority_digest, serial) \
             VALUES ('acme', 'main', 'i1', $1, $2, $3)",
            &[&LIST, &DIGEST, &vec![0x01_u8; 21]],
        )
        .await;
    assert_eq!(
        written
            .expect_err("a serial past twenty octets")
            .as_db_error()
            .and_then(|said| said.constraint()),
        Some("certificate_revocation_serial_bounded")
    );
}
