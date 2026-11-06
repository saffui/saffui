//! The definitions of authorization of a realm are checked and written under
//! the row that stands for them: a writer of them waits for another, a writer
//! of relations waits for a writer of them but not for another writer of
//! relations, and a writer of another realm waits for nobody.

use std::future::Future;
use std::time::Duration;

use pgcore::APP_ROLE;
use pgcore::pool::PoolSettings;
use pgcore::testkit::TestDatabase;
use saffui_core::app::App;
use saffui_core::authz::admin::{AdminCaller, authorize_admin_call};
use saffui_core::authz::capability::Capability;
use saffui_core::authz::policy::{Combine, Effect, NewPolicy, create_policy};
use saffui_core::authz::relations::{
    ObjectRef, RelationTuple, SchemaRefusal, SubjectRef, list_relation_subjects, write_relation,
    write_relation_schema,
};
use saffui_core::authz::roles::{
    NewGroup, NewRole, create_group, create_role, delete_group, delete_role,
};
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{create_administrator, create_realm};
use serde_json::{Value, json};

mod support;

/// Long enough for a writer that does not wait to have finished.
const WAIT: Duration = Duration::from_millis(300);

#[tokio::test]
async fn two_writers_of_the_definitions_of_one_realm_take_turns() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
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
    tokio::time::sleep(WAIT).await;
    assert!(
        !waiting.is_finished(),
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
async fn writers_of_relations_share_the_definitions_and_a_writer_of_them_waits_for_both() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "definitions-frozen").await;

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    first
        .freeze_definitions()
        .await
        .expect("the definitions kept");
    let mut second = app.storage.begin(scope).await.expect("a unit of work");
    tokio::time::timeout(Duration::from_secs(2), second.freeze_definitions())
        .await
        .expect("a second writer of relations does not wait")
        .expect("the definitions kept");
    let locking = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.lock_definitions().await.expect("the lock, in turn");
            work.commit().await.expect("a commit");
        })
    };
    tokio::time::sleep(WAIT).await;
    assert!(!locking.is_finished(), "the writer of definitions waits");
    first.commit().await.expect("a commit");
    tokio::time::sleep(WAIT).await;
    assert!(
        !locking.is_finished(),
        "and waits for the second writer of relations too"
    );
    second.commit().await.expect("a commit");
    tokio::time::timeout(Duration::from_secs(5), locking)
        .await
        .expect("the writer of definitions goes on once both end")
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
    let owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
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

    let serving = database
        .plan(APP_ROLE)
        .connect_directly()
        .await
        .expect("a connection");
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

/// An operator of the realm, as the administration plane lets it through.
async fn name_operator(app: &App, scope: RealmScope) -> AdminCaller {
    let capabilities = [Capability::PolicyWrite, Capability::RoleWrite];
    let token = create_administrator(app, "acme", scope, "operator", &capabilities).await;
    authorize_admin_call(app, "acme", Some(&token), Capability::PolicyWrite)
        .await
        .expect("an operator")
}

/// Plays two writers of one realm against each other. The first stops on
/// `table`, which an operator holds, after it has taken the row of the
/// definitions; the second starts then. Returns whether the second waited
/// for the first, and what each answered.
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
    let operator = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    operator
        .batch_execute(&format!(
            "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .expect("the table held");
    let first = tokio::spawn(first);
    tokio::time::sleep(WAIT).await;
    let second = tokio::spawn(second);
    tokio::time::sleep(WAIT).await;
    let waited = !second.is_finished();
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
