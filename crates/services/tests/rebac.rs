mod support;

use authz::rebac::{CompiledSchema, compile, parse};
use services::rebac::{Budget, CHECK, Object, Subject, Unwalkable, check};
use store::providers::rebac;
use store::tenancy::TenantContext;
use support::Fixture;

const SCHEMA: &str = "
definition user {}

definition group {
    relation member: user | group#member
}

definition folder {
    relation viewer: user | group#member
    permission view = viewer
}

definition document {
    relation parent: folder
    relation owner: user
    relation viewer: user | group#member
    permission view = viewer + owner + view from parent
}
";

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

fn schema() -> CompiledSchema {
    compile(&parse(SCHEMA).expect("it reads")).expect("it compiles")
}

async fn plant(transaction: &deadpool_postgres::Transaction<'_>, compiled: &CompiledSchema) {
    rebac::put_schema(
        transaction,
        &rebac::StoredSchema {
            format: authz::rebac::FORMAT as i32,
            revision: 1,
            source: SCHEMA.to_owned(),
            compiled: serde_json::to_value(compiled).unwrap(),
        },
        Some("root"),
    )
    .await
    .unwrap();
}

fn named(subject_type: &str, subject_id: &str) -> rebac::Subject {
    rebac::Subject {
        subject_type: subject_type.to_owned(),
        subject_id: subject_id.to_owned(),
        subject_relation: String::new(),
    }
}

fn holders(subject_type: &str, subject_id: &str, relation: &str) -> rebac::Subject {
    rebac::Subject {
        subject_type: subject_type.to_owned(),
        subject_id: subject_id.to_owned(),
        subject_relation: relation.to_owned(),
    }
}

async fn relate(
    transaction: &deadpool_postgres::Transaction<'_>,
    object_type: &str,
    object_id: &str,
    relation: &str,
    subject: rebac::Subject,
) {
    rebac::relate(
        transaction,
        object_type,
        object_id,
        relation,
        &subject,
        Some("root"),
    )
    .await
    .unwrap();
}

/// A subject named on the object, a subject reached through a group, and one
/// reached through the object's parent. The three shapes the language exists to
/// express.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_edge_is_followed_directly_through_a_set_and_through_a_parent() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    relate(
        &transaction,
        "document",
        "doc",
        "owner",
        named("user", "ada"),
    )
    .await;
    relate(
        &transaction,
        "document",
        "doc",
        "viewer",
        holders("group", "staff", "member"),
    )
    .await;
    relate(
        &transaction,
        "group",
        "staff",
        "member",
        named("user", "bob"),
    )
    .await;
    relate(
        &transaction,
        "document",
        "doc",
        "parent",
        named("folder", "shared"),
    )
    .await;
    relate(
        &transaction,
        "folder",
        "shared",
        "viewer",
        named("user", "cyd"),
    )
    .await;

    for who in ["ada", "bob", "cyd"] {
        assert!(
            check(
                &transaction,
                &compiled,
                Object {
                    object_type: "document",
                    object_id: "doc"
                },
                "view",
                Subject {
                    subject_type: "user",
                    subject_id: who
                },
                CHECK,
            )
            .await
            .unwrap(),
            "{who} could not see the document"
        );
    }

    assert!(
        !check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "nobody"
            },
            CHECK,
        )
        .await
        .unwrap(),
        "somebody with no edge to the document could see it"
    );
}

/// A relation wider than the walk may look at is refused, not truncated. The
/// subject may be in the part not read, so answering no would be answering from
/// half the edges.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_relation_wider_than_the_ceiling_is_unanswerable() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    for n in 0..5 {
        relate(
            &transaction,
            "document",
            "doc",
            "viewer",
            named("user", &format!("u{n}")),
        )
        .await;
    }

    let narrow = Budget {
        max_fanout: 3,
        ..CHECK
    };
    assert!(matches!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "u4"
            },
            narrow,
        )
        .await,
        Err(Unwalkable::TooWide { .. })
    ));

    // And a relation that fits inside the ceiling is answered, so the ceiling
    // is not simply refusing everything.
    let roomy = Budget {
        max_fanout: 5,
        ..CHECK
    };
    assert!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "u4"
            },
            roomy,
        )
        .await
        .unwrap()
    );
}

/// The other two ceilings, each an error rather than a no.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_walk_that_runs_out_of_budget_says_so() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    // A chain of folders, each the parent of the last.
    relate(
        &transaction,
        "document",
        "doc",
        "parent",
        named("folder", "f0"),
    )
    .await;
    for n in 0..6 {
        relate(
            &transaction,
            "folder",
            &format!("f{n}"),
            "viewer",
            named("user", "nobody-here"),
        )
        .await;
    }

    let shallow = Budget {
        max_depth: 1,
        ..CHECK
    };
    assert!(matches!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "ada"
            },
            shallow,
        )
        .await,
        Err(Unwalkable::TooDeep { .. })
    ));

    let stingy = Budget {
        max_queries: 1,
        ..CHECK
    };
    assert!(matches!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "ada"
            },
            stingy,
        )
        .await,
        Err(Unwalkable::TooManyQueries { .. })
    ));
}

/// The compiled schema carries what may stand in a relation, so an edge naming
/// something else is one that should never have been written. Dropped at
/// compile time, as the reference drops it, this edge would simply be expanded.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_edge_naming_an_undeclared_subject_type_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    // `owner` accepts a user and nothing else.
    relate(
        &transaction,
        "document",
        "doc",
        "owner",
        named("group", "staff"),
    )
    .await;

    assert!(matches!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "ada"
            },
            CHECK,
        )
        .await,
        Err(Unwalkable::Undeclared { .. })
    ));
}

/// A type the schema does not describe is refused before anything is read.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_type_the_schema_does_not_describe_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    assert!(matches!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "spaceship",
                object_id: "x"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "ada"
            },
            CHECK,
        )
        .await,
        Err(Unwalkable::UnknownType { .. })
    ));
}

/// The walk sees what the transaction it was given has written, which is the
/// whole reason it takes one. The engine this replaces gives its store a
/// connection of its own, so a check reads only committed state and nothing can
/// write edges and then verify them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_check_sees_what_its_own_transaction_wrote() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    relate(
        &transaction,
        "document",
        "doc",
        "owner",
        named("user", "ada"),
    )
    .await;

    // Nothing has been committed. A walk on its own connection would see none
    // of this.
    assert!(
        check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "ada"
            },
            CHECK,
        )
        .await
        .unwrap(),
        "the walk could not see the edges written beside it"
    );
}

/// A node reachable by several paths is walked once. Without that a diamond is
/// exponential in its paths, and the only thing between a schema and that is a
/// budget, which turns the blowup into a refusal an author cannot explain.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_node_reached_by_several_paths_is_walked_once() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    // Four groups, each holding the same group, whose one member is not the
    // subject asked about. Walked once each, this is a handful of queries;
    // walked once per path into the shared group, it multiplies.
    for n in 0..4 {
        relate(
            &transaction,
            "document",
            "doc",
            "viewer",
            holders("group", &format!("g{n}"), "member"),
        )
        .await;
        relate(
            &transaction,
            "group",
            &format!("g{n}"),
            "member",
            holders("group", "shared", "member"),
        )
        .await;
    }
    relate(
        &transaction,
        "group",
        "shared",
        "member",
        named("user", "bob"),
    )
    .await;

    // Ten queries is comfortably above one per distinct node and comfortably
    // below one per path.
    let counted = Budget {
        max_queries: 10,
        ..CHECK
    };
    assert!(
        !check(
            &transaction,
            &compiled,
            Object {
                object_type: "document",
                object_id: "doc"
            },
            "view",
            Subject {
                subject_type: "user",
                subject_id: "nobody"
            },
            counted,
        )
        .await
        .unwrap(),
        "the shared group was walked once per path"
    );
}

/// The one door edges come in by. Everything the schema does not describe is
/// refused here, which is the last moment anything can say so: stored, such an
/// edge is never matched, and the grant somebody thought they made was never
/// made.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_edge_the_schema_does_not_describe_is_refused_at_the_door() {
    use services::rebac::{Unwritable, relate as write};

    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    // The ordinary case first, so every refusal below is the arranged one.
    write(
        &transaction,
        "document",
        "doc",
        "owner",
        &named("user", "ada"),
        Some("root"),
    )
    .await
    .expect("an edge the schema describes");

    // A type nothing declares.
    assert!(matches!(
        write(
            &transaction,
            "spaceship",
            "x",
            "owner",
            &named("user", "ada"),
            None
        )
        .await,
        Err(Unwritable::UnknownType { .. })
    ));

    // A relation the type does not have.
    assert!(matches!(
        write(
            &transaction,
            "document",
            "doc",
            "pilots",
            &named("user", "ada"),
            None
        )
        .await,
        Err(Unwritable::NoSuchRelation { .. })
    ));

    // A permission stores no edges. The reference looks the member up and
    // accepts whatever it finds, so this row is stored and never read.
    assert!(
        matches!(
            write(
                &transaction,
                "document",
                "doc",
                "view",
                &named("user", "ada"),
                None
            )
            .await,
            Err(Unwritable::NotARelation { .. })
        ),
        "an edge was written against a permission"
    );

    // `owner` accepts a user and nothing else. Only answerable because the
    // declared types survive compilation.
    assert!(
        matches!(
            write(
                &transaction,
                "document",
                "doc",
                "owner",
                &named("group", "staff"),
                None
            )
            .await,
            Err(Unwritable::NotAccepted { .. })
        ),
        "a relation accepted a subject type it never declared"
    );

    // A userset the relation does not declare. `viewer` takes `group#member`,
    // so the holders of anything else on a group are not what it accepts.
    assert!(
        matches!(
            write(
                &transaction,
                "document",
                "doc",
                "viewer",
                &holders("group", "staff", "nonesuch"),
                None
            )
            .await,
            Err(Unwritable::NotAccepted { .. })
        ),
        "a relation accepted a userset it never declared"
    );

    // And the userset that does exist is written.
    write(
        &transaction,
        "document",
        "doc",
        "viewer",
        &holders("group", "staff", "member"),
        Some("root"),
    )
    .await
    .expect("a userset the schema describes");
}

/// Removing an edge is not validated, and the asymmetry is the point: writing
/// one the schema does not describe makes a grant nobody can use, removing one
/// takes a grant away. A realm whose schema narrowed has edges it can no longer
/// write, and refusing to delete those would leave them stuck.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_edge_the_schema_no_longer_describes_can_still_be_taken_back() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    let compiled = schema();
    plant(&transaction, &compiled).await;

    // Planted the raw way, standing in for an edge written under a wider schema.
    relate(
        &transaction,
        "document",
        "doc",
        "owner",
        named("group", "staff"),
    )
    .await;

    assert!(
        services::rebac::unrelate(
            &transaction,
            "document",
            "doc",
            "owner",
            &named("group", "staff")
        )
        .await
        .unwrap(),
        "an edge the schema no longer describes could not be removed"
    );
}

/// Publishing is one act, so the compiled form is always the compilation of the
/// source beside it. Given the two separately a caller can store a document
/// that is not what the source says, and then a realm shows one schema and
/// decides by another.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_published_schema_is_the_compilation_of_its_own_source() {
    use services::rebac::{Unpublishable, publish};

    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let compiled = publish(&transaction, SCHEMA, Some("root"))
        .await
        .expect("a schema that reads and compiles");

    // What was stored is what was returned, and what the walk will read.
    let stored = rebac::load_schema(&transaction).await.unwrap().unwrap();
    assert_eq!(stored.source, SCHEMA);
    assert_eq!(stored.format, authz::rebac::FORMAT as i32);
    assert_eq!(
        serde_json::from_value::<authz::rebac::CompiledSchema>(stored.compiled).unwrap(),
        compiled,
        "the stored form is not the compilation of the stored source"
    );

    // A source that does not read is refused before anything is stored.
    assert!(matches!(
        publish(&transaction, "definition d {", None).await,
        Err(Unpublishable::Unreadable(_))
    ));

    // And one that reads and does not compile.
    assert!(matches!(
        publish(&transaction, "definition d { permission p = p }", None).await,
        Err(Unpublishable::Faulty(_))
    ));

    // Neither replaced what was there.
    let after = rebac::load_schema(&transaction).await.unwrap().unwrap();
    assert_eq!(
        after.source, SCHEMA,
        "a schema that was refused replaced the one that stood"
    );
}
