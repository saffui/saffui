//! The definitions of authorization of a realm are checked and written under
//! the row that stands for them: every writer of them, and every writer of
//! relations, takes the row in turn, in the order they came, and a writer of
//! another realm waits for nobody.

use std::future::Future;
use std::time::{Duration, Instant};

use pgcore::pool::PoolSettings;
use pgcore::testkit::TestDatabase;
use pgcore::{APP_ROLE, MAINTENANCE_ROLE};
use saffui_core::app::App;
use saffui_core::authz::admin::{AdminCaller, authorize_admin_call};
use saffui_core::authz::capability::Capability;
use saffui_core::authz::policy::{Combine, Effect, NewPolicy, create_policy, list_policies};
use saffui_core::authz::relations::{
    ObjectRef, RelationTuple, SchemaRefusal, SubjectRef, list_relation_subjects, write_relation,
    write_relation_schema,
};
use saffui_core::authz::roles::{
    NewGroup, NewRole, create_group, create_role, delete_group, delete_role,
};
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::ports::storage::StorageError;
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{create_administrator, create_realm};
use serde_json::{Value, json};
use tokio::task::JoinHandle;
use tokio_postgres::Client;

mod support;

/// What a session waits on for a row another holds, and for a table.
const ON_A_ROW: &[&str] = &["transactionid", "tuple"];
const ON_A_TABLE: &[&str] = &["relation"];

const READERS: &str = "definition user {}\ndefinition document {\n  relation reader: user\n}";

async fn connect(database: &TestDatabase, role: &str) -> Client {
    database
        .plan(role)
        .connect_directly()
        .await
        .expect("a connection")
}

/// Waits until a session of the database waits on a lock of one of `kinds`,
/// until `task` is done, or three seconds at most: short of what a unit of
/// work waits for a lock, so that a writer left waiting is not timed out.
/// The observer is of the serving role: it sees what its sessions wait on.
async fn wait_for_waiter<T>(observer: &Client, kinds: &[&str], task: &JoinHandle<T>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !task.is_finished() && Instant::now() < deadline {
        let waiting: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'
                   AND wait_event = ANY($1)",
                &[&kinds],
            )
            .await
            .expect("a count")
            .get(0);
        if waiting > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// `document:q3#reader@user:{user}`.
fn read_by(user: &str) -> RelationTuple {
    let object = |object_type: &str, object_id: &str| ObjectRef {
        object_type: object_type.to_owned(),
        object_id: object_id.to_owned(),
    };
    RelationTuple {
        object: object("document", "q3"),
        relation: "reader".to_owned(),
        subject: SubjectRef {
            object: object("user", user),
            member: None,
        },
    }
}

#[tokio::test]
async fn two_writers_of_the_definitions_of_one_realm_take_turns() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = connect(&database, APP_ROLE).await;
    let scope = create_realm(&app, "definitions-lock").await;
    let other = create_realm(&app, "definitions-lock-other").await;

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    first.lock_definitions().await.expect("the lock");
    let waiting = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut second = app.storage.begin(scope).await.expect("a unit of work");
            second.lock_definitions().await.expect("the lock, in turn");
            second.commit().await.expect("a commit");
        })
    };
    assert!(
        wait_for_waiter(&observer, ON_A_ROW, &waiting).await,
        "the second writer waits for the first"
    );

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    tokio::time::timeout(Duration::from_secs(2), elsewhere.lock_definitions())
        .await
        .expect("a writer of another realm does not wait")
        .expect("the lock");
    elsewhere.commit().await.expect("a commit");

    first.commit().await.expect("a commit");
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the second writer goes on once the first ends")
        .expect("the task");
}

#[tokio::test]
async fn a_writer_of_definitions_waits_for_a_writer_of_relations() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = connect(&database, APP_ROLE).await;
    let scope = create_realm(&app, "definitions-relating").await;

    let mut relating = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        relating.lock_definitions_and_read_schema().await,
        Ok(None),
        "the row, and no schema yet"
    );
    let locking = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.lock_definitions().await.expect("the lock, in turn");
            work.commit().await.expect("a commit");
        })
    };
    assert!(
        wait_for_waiter(&observer, ON_A_ROW, &locking).await,
        "the writer of definitions waits"
    );
    relating.commit().await.expect("a commit");
    tokio::time::timeout(Duration::from_secs(5), locking)
        .await
        .expect("the writer of definitions goes on once the other ends")
        .expect("the task");
}

/// The row is made with each realm, and the migration that made the table
/// gave one to every realm already there.
#[tokio::test]
async fn a_realm_made_before_its_definitions_had_a_row_is_given_one() {
    use pgcore::migrate::{EMBEDDED, apply_pending};

    let before = EMBEDDED
        .iter()
        .position(|migration| migration.name == "0030_policies")
        .expect("the migration of the row");
    let database = TestDatabase::create(&EMBEDDED[..before]).await;
    let (tenant, realm) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
    let owner = connect(&database, "saffui_owner").await;
    owner
        .batch_execute(&format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{tenant}', true),
                    set_config('saffui.realm', '{realm}', true);
             INSERT INTO tenants VALUES ('{tenant}', 'Acme', now());
             INSERT INTO realms VALUES ('{tenant}', '{realm}', 'acme', true, now());
             COMMIT"
        ))
        .await
        .expect("a realm made before the row");
    apply_pending(&database.plan("saffui_owner"), EMBEDDED)
        .await
        .expect("the migrations that follow");

    let serving = connect(&database, APP_ROLE).await;
    serving
        .batch_execute(&format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{tenant}', true),
                    set_config('saffui.realm', '{realm}', true)"
        ))
        .await
        .expect("the scope of the realm");
    let locked = serving
        .query(
            "SELECT 1 FROM authz_definitions WHERE tenant_id = $1 AND realm_id = $2 FOR UPDATE",
            &[&tenant, &realm],
        )
        .await
        .expect("the row, locked by the serving role");
    assert_eq!(locked.len(), 1);
}

/// Each role that may insert a realm makes its row with it, by its own
/// rights: the row of that realm, and, under row security, no other.
#[tokio::test]
async fn a_realm_inserted_by_hand_has_its_row_whoever_inserts_it() {
    use pgcore::migrate::EMBEDDED;
    use tokio_postgres::error::SqlState;

    let database = TestDatabase::create(EMBEDDED).await;
    let tenant = uuid::Uuid::from_u128(1);
    let realm = |number: u128| uuid::Uuid::from_u128(number);
    let scoped = |realm: uuid::Uuid| {
        format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{tenant}', true),
                    set_config('saffui.realm', '{realm}', true);"
        )
    };
    connect(&database, "saffui_owner")
        .await
        .batch_execute(&format!(
            "{} INSERT INTO tenants VALUES ('{tenant}', 'Acme', now());
             INSERT INTO realms VALUES ('{tenant}', '{}', 'by-owner', true, now());
             COMMIT",
            scoped(realm(2)),
            realm(2)
        ))
        .await
        .expect("a realm inserted by the owner");
    let serving = connect(&database, APP_ROLE).await;
    serving
        .batch_execute(&format!(
            "{} INSERT INTO realms VALUES ('{tenant}', '{}', 'by-app', true, now());
             COMMIT",
            scoped(realm(3)),
            realm(3)
        ))
        .await
        .expect("a realm inserted by the serving role");
    let maintenance = connect(&database, MAINTENANCE_ROLE).await;
    maintenance
        .execute(
            "INSERT INTO realms VALUES ($1, $2, 'by-maintenance', true, now())",
            &[&tenant, &realm(4)],
        )
        .await
        .expect("a realm inserted by the maintenance role");

    let rows: Vec<uuid::Uuid> = maintenance
        .query(
            "SELECT realm_id FROM authz_definitions ORDER BY realm_id",
            &[],
        )
        .await
        .expect("the rows")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(rows, [realm(2), realm(3), realm(4)]);

    serving
        .batch_execute(&scoped(realm(3)))
        .await
        .expect("a scoped transaction");
    let planted = serving
        .execute(
            "INSERT INTO authz_definitions VALUES ($1, $2)",
            &[&tenant, &realm(5)],
        )
        .await
        .expect_err("a row for another realm");
    assert_eq!(
        planted.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "row security refuses it"
    );
}

/// An operator of the realm, as the administration plane lets it through.
async fn name_operator(app: &App, scope: RealmScope) -> AdminCaller {
    let capabilities = [Capability::PolicyWrite, Capability::RoleWrite];
    let token = create_administrator(app, "acme", scope, "operator", &capabilities).await;
    authorize_admin_call(app, "acme", Some(&token), Capability::PolicyWrite)
        .await
        .expect("an operator")
}

/// A realm whose row was taken away behind the product refuses whoever
/// would write its definitions or its relations, and keeps nothing of it.
#[tokio::test]
async fn a_realm_without_its_row_refuses_every_writer_and_keeps_nothing() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    write_relation_schema(&app, &caller, READERS)
        .await
        .expect("a schema");
    connect(&database, "saffui_owner")
        .await
        .batch_execute(&format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{}', true),
                    set_config('saffui.realm', '{}', true);
             DELETE FROM authz_definitions;
             COMMIT",
            scope.tenant().as_uuid(),
            scope.realm().as_uuid()
        ))
        .await
        .expect("the row taken away");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.lock_definitions().await, Err(StorageError::Failed));
    drop(work);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.lock_definitions_and_read_schema().await,
        Err(StorageError::Failed)
    );
    drop(work);

    let related = write_relation(&app, &caller, &read_by("ada")).await;
    assert_eq!(
        related.map_err(|failure| failure.code),
        Err(ErrorCode::Internal)
    );
    let written = write_policy(
        &app,
        &caller,
        "invoice",
        json!([{ "role": uuid::Uuid::nil() }]),
    );
    assert_eq!(written.await, Err(ErrorCode::Internal));
    let (readers, _) = list_relation_subjects(&app, scope, &read_by("ada").object, "reader")
        .await
        .expect("the readers");
    assert!(readers.is_empty(), "no relation was kept: {readers:?}");
    let policies = list_policies(&app, scope, "operator")
        .await
        .expect("the policies");
    assert!(policies.is_empty(), "no policy was kept: {policies:?}");
}

/// Plays two writers of one realm against each other. The first stops on
/// `table`, which an operator holds, after it has taken the row of the
/// definitions; the second starts then. Returns whether the second waited
/// on a row, and what each answered.
async fn cross<A, B>(
    database: &TestDatabase,
    table: &str,
    first: impl Future<Output = A> + Send + 'static,
    second: impl Future<Output = B> + Send + 'static,
) -> (bool, A, B)
where
    A: Send + 'static,
    B: Send + 'static,
{
    let observer = connect(database, APP_ROLE).await;
    let operator = connect(database, "saffui_owner").await;
    operator
        .batch_execute(&format!(
            "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .expect("the table held");
    let first = tokio::spawn(first);
    assert!(
        wait_for_waiter(&observer, ON_A_TABLE, &first).await,
        "the first writer reaches the table"
    );
    let second = tokio::spawn(second);
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    operator
        .batch_execute("ROLLBACK")
        .await
        .expect("the table let go");
    let first = first.await.expect("the first writer");
    let second = second.await.expect("the second writer");
    (waited, first, second)
}

fn write_policy(
    app: &App,
    caller: &AdminCaller,
    resource_type: &'static str,
    conditions: Value,
) -> impl Future<Output = Result<(), ErrorCode>> + Send + 'static {
    let (app, caller) = (app.clone(), caller.clone());
    async move {
        let wanted = NewPolicy {
            client_id: "operator",
            name: resource_type,
            resource_type,
            action: "approve",
            effect: Effect::Deny,
            combine: Combine::Any,
            conditions: &conditions,
        };
        create_policy(&app, &caller, wanted)
            .await
            .map(|_| ())
            .map_err(|failure| failure.code)
    }
}

/// Each writer of definitions takes the row before it checks: one that
/// comes while a policy is being written sees it once it is kept. The
/// policy stops on the table of clients, which it reads right after the row.
#[tokio::test]
async fn a_policy_being_written_holds_back_whatever_would_make_it_wrong() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let night = create_group(
        &app,
        &caller,
        NewGroup {
            name: "night-shift",
            description: None,
        },
    )
    .await
    .expect("a group")
    .id;
    let approver = create_role(
        &app,
        &caller,
        NewRole {
            name: "approver",
            client_id: None,
            description: None,
        },
    )
    .await
    .expect("a role")
    .id;

    let removal = {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            delete_group(&app, &caller, night)
                .await
                .map_err(|failure| failure.code)
        }
    };
    let (waited, policy, removed) = cross(
        &database,
        "clients",
        write_policy(&app, &caller, "invoice", json!([{ "group": night }])),
        removal,
    )
    .await;
    assert!(waited, "the removal of the group waits for the policy");
    assert_eq!(policy, Ok(()));
    assert_eq!(removed, Err(ErrorCode::NamedByPolicy));

    let removal = {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            delete_role(&app, &caller, approver)
                .await
                .map_err(|failure| failure.code)
        }
    };
    let (waited, policy, removed) = cross(
        &database,
        "clients",
        write_policy(&app, &caller, "receipt", json!([{ "role": approver }])),
        removal,
    )
    .await;
    assert!(waited, "the removal of the role waits for the policy");
    assert_eq!(policy, Ok(()));
    assert_eq!(removed, Err(ErrorCode::NamedByPolicy));

    let schema = {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            let source = "definition user {}\ndefinition voucher {\n  relation owner: user\n}";
            write_relation_schema(&app, &caller, source)
                .await
                .map(|(_, removed)| removed)
        }
    };
    let (waited, policy, written) = cross(
        &database,
        "clients",
        write_policy(&app, &caller, "voucher", json!([{ "role": approver }])),
        schema,
    )
    .await;
    assert!(waited, "the schema waits for the policy");
    assert_eq!(policy, Ok(()));
    assert_eq!(
        written,
        Err(SchemaRefusal::Failed(Failure::new(
            ErrorCode::ResourceTypeTaken
        ))),
        "a policy decides vouchers"
    );
}

/// Two policies written at once for a client that has room for one: the
/// second waits for the first, counts it, and is refused. Both would stop on
/// the table of policies, where they count.
#[tokio::test]
async fn two_policies_written_at_once_where_one_fits_keep_one() {
    use saffui_core::authz::policy::MAX_POLICIES_PER_CLIENT;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let approver = create_role(
        &app,
        &caller,
        NewRole {
            name: "approver",
            client_id: None,
            description: None,
        },
    )
    .await
    .expect("a role")
    .id;
    let conditions = json!([{ "role": approver }]);
    for index in 1..MAX_POLICIES_PER_CLIENT {
        let name = format!("kept-{index}");
        let wanted = NewPolicy {
            client_id: "operator",
            name: &name,
            resource_type: &name,
            action: "approve",
            effect: Effect::Deny,
            combine: Combine::Any,
            conditions: &conditions,
        };
        create_policy(&app, &caller, wanted)
            .await
            .expect("a policy with room for it");
    }

    let (waited, first, second) = cross(
        &database,
        "authz_policies",
        write_policy(&app, &caller, "last-one", conditions.clone()),
        write_policy(&app, &caller, "one-too-many", conditions.clone()),
    )
    .await;
    assert!(waited, "the second policy waits for the first");
    assert_eq!(first, Ok(()));
    assert_eq!(second, Err(ErrorCode::PolicyInvalid), "no room was left");
    let kept = list_policies(&app, scope, "operator")
        .await
        .expect("the policies");
    assert_eq!(
        kept.len(),
        usize::try_from(MAX_POLICIES_PER_CLIENT).expect("a length")
    );
}

/// A relation is checked against the schema that stands when it is kept.
/// The schema stops on the table of policies, which it reads right after
/// the row, before it is written.
#[tokio::test]
async fn a_relation_written_while_the_schema_narrows_is_checked_against_the_narrower_one() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let wide = "definition user {}\ndefinition team {\n  relation member: user\n}\ndefinition document {\n  relation reader: user | team#member\n}";
    let narrow = "definition user {}\ndefinition team {\n  relation member: user\n}\ndefinition document {\n  relation reader: user\n}";
    write_relation_schema(&app, &caller, wide)
        .await
        .expect("a schema");
    let object = |object_type: &str, object_id: &str| ObjectRef {
        object_type: object_type.to_owned(),
        object_id: object_id.to_owned(),
    };
    let members_read = RelationTuple {
        object: object("document", "q3"),
        relation: "reader".to_owned(),
        subject: SubjectRef {
            object: object("team", "core"),
            member: Some("member".to_owned()),
        },
    };

    let narrowing = {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            write_relation_schema(&app, &caller, narrow)
                .await
                .map(|(_, removed)| removed)
        }
    };
    let relating = {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            write_relation(&app, &caller, &members_read)
                .await
                .map_err(|failure| failure.code)
        }
    };
    let (waited, narrowed, related) = cross(&database, "authz_policies", narrowing, relating).await;
    assert!(waited, "the relation waits for the schema");
    assert_eq!(narrowed, Ok(0));
    assert_eq!(
        related,
        Err(ErrorCode::RelationInvalid),
        "checked against the schema that replaced the one it would have read"
    );
    let (readers, _) = list_relation_subjects(&app, scope, &object("document", "q3"), "reader")
        .await
        .expect("the readers");
    assert!(
        readers.is_empty(),
        "nothing the schema refuses was kept: {readers:?}"
    );
}

/// Six writers of relations, each starting again as soon as it ends, for two
/// seconds: a writer of the schema that comes in the middle takes its turn
/// while they still write, not once they stop. Fewer leave gaps between
/// them, which would let it through in share mode too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writers_of_relations_one_after_another_let_a_writer_of_the_schema_through() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    write_relation_schema(&app, &caller, READERS)
        .await
        .expect("a schema");
    let end = Instant::now() + Duration::from_secs(2);
    let writers: Vec<JoinHandle<u32>> = (0..6)
        .map(|writer| {
            let (app, caller) = (app.clone(), caller.clone());
            tokio::spawn(async move {
                let mut written = 0;
                while Instant::now() < end {
                    let tuple = read_by(&format!("w{writer}-{written}"));
                    write_relation(&app, &caller, &tuple)
                        .await
                        .expect("a relation, in turn");
                    written += 1;
                }
                written
            })
        })
        .collect();

    tokio::time::sleep(Duration::from_secs(1)).await;
    let widened = format!("{READERS}\ndefinition folder {{}}");
    let written = write_relation_schema(&app, &caller, &widened).await;
    let ended = Instant::now();
    assert_eq!(written.map(|(_, removed)| removed), Ok(0));
    assert!(
        ended < end,
        "written {:?} after the writers of relations stopped",
        ended - end
    );
    for writer in writers {
        assert!(writer.await.expect("a writer") > 0);
    }
}

/// Behind a writer of definitions, a writer of relations gives up within
/// about a second, where the pool waits five, and keeps nothing; a writer of
/// definitions waits on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_of_relations_gives_way_soon_behind_a_writer_of_definitions() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = connect(&database, APP_ROLE).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    write_relation_schema(&app, &caller, READERS)
        .await
        .expect("a schema");
    let mut holder = app.storage.begin(scope).await.expect("a unit of work");
    holder.lock_definitions().await.expect("the lock");

    let started = Instant::now();
    let related = write_relation(&app, &caller, &read_by("ada")).await;
    let waited = started.elapsed();
    assert_eq!(
        related.map_err(|failure| failure.code),
        Err(ErrorCode::StorageUnavailable)
    );
    assert!(waited < Duration::from_secs(3), "gave up after {waited:?}");
    let locking = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.lock_definitions().await.expect("the lock, in turn");
            work.commit().await.expect("a commit");
        })
    };
    assert!(
        wait_for_waiter(&observer, ON_A_ROW, &locking).await,
        "a writer of definitions waits"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !locking.is_finished(),
        "and still waits past the wait of a writer of relations"
    );
    holder.commit().await.expect("a commit");
    tokio::time::timeout(Duration::from_secs(5), locking)
        .await
        .expect("it goes on once the first ends")
        .expect("the task");
    let (readers, _) = list_relation_subjects(&app, scope, &read_by("ada").object, "reader")
        .await
        .expect("the readers");
    assert!(readers.is_empty(), "the refused relation was not kept");
}

/// The short wait of a writer of relations is for the row alone: past it,
/// the append of its event waits on the head of the chain as long as its
/// unit of work lets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_row_a_writer_of_relations_waits_as_long_as_its_unit_of_work() {
    use saffui_core::audit::EventKind;
    use saffui_core::audit::append::record_event;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let observer = connect(&database, APP_ROLE).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    write_relation_schema(&app, &caller, READERS)
        .await
        .expect("a schema");
    let mut holder = app.storage.begin(scope).await.expect("a unit of work");
    record_event(&app, holder.as_mut(), EventKind::RealmCreated, json!({}))
        .await
        .expect("the head of the chain, held");

    let relating = {
        let (app, caller) = (app.clone(), caller.clone());
        tokio::spawn(async move {
            write_relation(&app, &caller, &read_by("ada"))
                .await
                .map_err(|failure| failure.code)
        })
    };
    assert!(
        wait_for_waiter(&observer, ON_A_ROW, &relating).await,
        "the relation waits on the head"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !relating.is_finished(),
        "and still waits past the wait it had for the row"
    );
    drop(holder);
    assert_eq!(relating.await.expect("the relation"), Ok(()));
}
