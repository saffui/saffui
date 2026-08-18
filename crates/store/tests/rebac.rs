//! The relationship tables, against a database.
//!
//! What is asserted here is the shape rather than any engine: the key that
//! keeps two tenants apart, the schema a realm's edges hang from, and the
//! isolation every realm scoped table promises.

mod support;

use store::tenancy::TenantContext;
use support::Fixture;

/// A second realm of the same tenant, for the isolation test.
async fn second_realm(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
        .await;
    let realm = models::entities::realm::RealmCreateModel {
        name: "other".into(),
        display_name: "Other".into(),
        enabled: true,
    }
    .into_model(
        "other".into(),
        models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
    );
    store::providers::realms::create(&transaction, &realm)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A realm with a schema, so tuples have something to hang from.
async fn plant_schema(fixture: &Fixture, tenant: &str, realm: &str) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new(tenant, realm))
        .await;
    transaction
        .execute(
            "INSERT INTO rebac_schemas (tenant, realm_id, format, source, compiled) \
             VALUES ($1, $2, 1, 'definition user {}', '{}'::jsonb)",
            &[&tenant, &realm],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// The tenant leads the key. Left out of it, two tenants that both call a realm
/// `main` share one schema row and one set of edges, and whichever writes last
/// decides for both. This plants the identical realm name under two tenants and
/// asserts each keeps its own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_tenants_that_name_a_realm_alike_keep_their_own() {
    let fixture = Fixture::empty().await;
    let owner = fixture.owner().await;

    for tenant in ["acme", "globex"] {
        owner
            .execute(
                "INSERT INTO tenants (tenant_id, display_name) VALUES ($1, $1)",
                &[&tenant],
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO realms (tenant, realm_id, name, display_name) \
                 VALUES ($1, 'main', 'main', 'Main')",
                &[&tenant],
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO rebac_schemas (tenant, realm_id, format, source, compiled) \
                 VALUES ($1, 'main', 1, 'definition user {}', '{}'::jsonb)",
                &[&tenant],
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO rebac_tuples \
                     (tenant, realm_id, object_type, object_id, relation, subject_type, subject_id) \
                 VALUES ($1, 'main', 'document', 'doc-1', 'viewer', 'user', 'ada')",
                &[&tenant],
            )
            .await
            .unwrap();
    }

    let schemas: i64 = owner
        .query_one("SELECT count(*) FROM rebac_schemas", &[])
        .await
        .unwrap()
        .get(0);
    let edges: i64 = owner
        .query_one("SELECT count(*) FROM rebac_tuples", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(schemas, 2, "one tenant's schema stood in for another's");
    assert_eq!(edges, 2, "the same edge in two tenants was stored once");
}

/// An edge hangs from a schema. Without one there is no relation for it to
/// name, so a realm with edges and no schema is a realm deciding by something
/// nobody wrote.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_edge_needs_a_schema_to_hang_from() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        transaction
            .execute(
                "INSERT INTO rebac_tuples \
                     (tenant, realm_id, object_type, object_id, relation, subject_type, subject_id) \
                 VALUES ('acme', 'main', 'document', 'doc-1', 'viewer', 'user', 'ada')",
                &[],
            )
            .await
            .is_err(),
        "an edge was written into a realm that has no relationship schema"
    );
}

/// A subject named directly and a set of subjects are different edges, and the
/// empty string is what says which. A nullable column would make the difference
/// depend on whether a writer remembered.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_named_subject_and_a_set_of_them_are_two_edges() {
    let fixture = Fixture::with_user().await;
    plant_schema(&fixture, "acme", "main").await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    for subject_relation in ["", "member"] {
        transaction
            .execute(
                "INSERT INTO rebac_tuples \
                     (tenant, realm_id, object_type, object_id, relation, \
                      subject_type, subject_id, subject_relation) \
                 VALUES ('acme', 'main', 'document', 'doc-1', 'viewer', 'group', 'staff', $1)",
                &[&subject_relation],
            )
            .await
            .unwrap();
    }

    let rows: i64 = transaction
        .query_one("SELECT count(*) FROM rebac_tuples", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        rows, 2,
        "the group itself and the group's members were stored as one edge"
    );

    // And the same edge twice is one edge.
    assert!(
        transaction
            .execute(
                "INSERT INTO rebac_tuples \
                     (tenant, realm_id, object_type, object_id, relation, \
                      subject_type, subject_id, subject_relation) \
                 VALUES ('acme', 'main', 'document', 'doc-1', 'viewer', 'group', 'staff', '')",
                &[],
            )
            .await
            .is_err()
    );
}

/// The isolation every realm scoped table promises.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn edges_are_not_visible_from_another_realm() {
    let fixture = Fixture::with_user().await;
    plant_schema(&fixture, "acme", "main").await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO rebac_tuples \
                 (tenant, realm_id, object_type, object_id, relation, subject_type, subject_id) \
             VALUES ('acme', 'main', 'document', 'doc-1', 'viewer', 'user', 'ada')",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    second_realm(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    let seen: i64 = transaction
        .query_one("SELECT count(*) FROM rebac_tuples", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "another realm's edges were visible");
}
