//! The bounds of claims are counted under a lock: the mappers of a client
//! under the row of the client, the attributes of a person under the row of
//! the person. Of two writers at the bound, the second waits for the first,
//! then counts what it kept.

use std::future::Future;
use std::time::{Duration, Instant};

use pgcore::APP_ROLE;
use pgcore::pool::PoolSettings;
use pgcore::testkit::TestDatabase;
use saffui_core::app::App;
use saffui_core::authz::admin::{AdminCaller, authorize_admin_call};
use saffui_core::authz::capability::Capability;
use saffui_core::claims::attributes::{read_attributes, write_attributes};
use saffui_core::claims::manage::{create_mapper, list_mappers};
use saffui_core::claims::rules::MAX_MAPPERS_PER_CLIENT;
use saffui_core::claims::{ClaimTarget, Mapper, MapperKind, NewMapper};
use saffui_core::error::ErrorCode;
use saffui_core::ports::storage::StorageError;
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{
    Application, create_administrator, create_person, create_realm, register_application,
};
use serde_json::{Map, Value, json};
use tokio::task::JoinHandle;
use tokio_postgres::Client;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

mod support;

/// What a session waits on for a row another holds, and for a table.
const ON_A_ROW: &[&str] = &["transactionid", "tuple"];
const ON_A_TABLE: &[&str] = &["relation"];

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

/// Plays two writers against each other. The first stops on `table`, which
/// an operator holds, after it has taken its row; the second starts then.
/// Returns whether the second waited on a row, and what each answered.
async fn race_two_writers<A, B>(
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

/// The client `client_id` of the realm, granted `capabilities`, as the
/// administration plane lets it through.
async fn name_operator(
    app: &App,
    scope: RealmScope,
    client_id: &str,
    capabilities: &[Capability],
) -> AdminCaller {
    let token = create_administrator(app, "acme", scope, client_id, capabilities).await;
    authorize_admin_call(app, "acme", Some(&token), capabilities[0])
        .await
        .expect("an operator")
}

/// A mapper of `portal` named `name`, that says the attribute of that name
/// as a claim of that name.
fn write_mapper(
    app: &App,
    caller: &AdminCaller,
    name: String,
) -> impl Future<Output = Result<(), ErrorCode>> + Send + 'static {
    let (app, caller) = (app.clone(), caller.clone());
    async move {
        let wanted = NewMapper {
            name: &name,
            kind: MapperKind::Attribute {
                attribute: name.clone(),
            },
            claim: Some(&name),
            targets: &[ClaimTarget::IdToken],
            scope: Some("profile"),
        };
        create_mapper(&app, &caller, "portal", wanted)
            .await
            .map(|_| ())
            .map_err(|failure| failure.code)
    }
}

fn write_attributes_as(
    app: &App,
    caller: &AdminCaller,
    person: Uuid,
    attributes: Map<String, Value>,
) -> impl Future<Output = Result<(), ErrorCode>> + Send + 'static {
    let (app, caller) = (app.clone(), caller.clone());
    async move {
        write_attributes(&app, &caller, person, &attributes)
            .await
            .map_err(|failure| failure.code)
    }
}

/// `count` attributes named `{prefix}00` and on.
fn name_attributes(prefix: &str, count: usize) -> Map<String, Value> {
    (0..count)
        .map(|index| (format!("{prefix}{index:02}"), json!("x")))
        .collect()
}

/// The mappers stop on their table, which a writer reads right after the
/// row of the client.
#[tokio::test]
async fn two_mappers_written_at_once_where_one_fits_keep_one() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let capabilities = [Capability::ClientWrite, Capability::UserRead];
    let caller = name_operator(&app, scope, "operator", &capabilities).await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(&app, scope, portal).await;
    for index in 1..MAX_MAPPERS_PER_CLIENT {
        write_mapper(&app, &caller, format!("kept-{index:02}"))
            .await
            .expect("a mapper with room for it");
    }

    let (waited, first, second) = race_two_writers(
        &database,
        "client_mappers",
        write_mapper(&app, &caller, "last-one".to_owned()),
        write_mapper(&app, &caller, "one-too-many".to_owned()),
    )
    .await;

    assert!(waited, "the second mapper waits for the first");
    assert_eq!(first, Ok(()));
    assert_eq!(
        second,
        Err(ErrorCode::MapperLimitReached),
        "no room was left"
    );
    let kept = list_mappers(&app, scope, "portal")
        .await
        .expect("the mappers");
    assert_eq!(
        kept.len(),
        usize::try_from(MAX_MAPPERS_PER_CLIENT).expect("a length")
    );
}

/// A writer that may write the attributes policies read leaves 64 of them;
/// a writer that may not counts them with its own once it has the person,
/// and finds one too many. The first stops on the chain, which it writes
/// right after the attributes.
#[tokio::test]
async fn a_writer_of_attributes_counts_what_another_left_while_it_waited() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery")
        .await
        .id;
    let both = name_operator(
        &app,
        scope,
        "operator",
        &[Capability::UserWrite, Capability::PolicyWrite],
    )
    .await;
    let clerk = name_operator(&app, scope, "clerk", &[Capability::UserWrite]).await;
    write_attributes(&app, &both, ada, &name_attributes("policy.p", 32))
        .await
        .expect("the attributes of the policies");
    let mut left = name_attributes("a", 31);
    left.extend(name_attributes("policy.p", 33));

    let (waited, first, second) = race_two_writers(
        &database,
        "audit_events",
        write_attributes_as(&app, &both, ada, left.clone()),
        write_attributes_as(&app, &clerk, ada, name_attributes("b", 32)),
    )
    .await;

    assert!(waited, "the second writer waits for the first");
    assert_eq!(first, Ok(()));
    assert_eq!(
        second,
        Err(ErrorCode::AttributesInvalid),
        "32 of its own and the 33 it may not write are one too many"
    );
    let reader = name_operator(
        &app,
        scope,
        "reader",
        &[Capability::UserRead, Capability::PolicyRead],
    )
    .await;
    assert_eq!(
        read_attributes(&app, &reader, ada).await,
        Ok(left),
        "what the first left stands"
    );
}

/// The schema keeps the attributes of a person an object, whoever writes
/// them: the binary reads anything else as a failure.
#[tokio::test]
async fn the_attributes_of_a_person_are_an_object_whatever_writes_them() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery")
        .await
        .id;
    let session = connect(&database, APP_ROLE).await;
    let open = format!(
        "BEGIN; SELECT set_config('saffui.tenant', '{}', true), \
         set_config('saffui.realm', '{}', true)",
        scope.tenant().as_uuid(),
        scope.realm().as_uuid()
    );

    for document in ["[]", "\"text\"", "1", "null"] {
        session
            .batch_execute(&open)
            .await
            .expect("a scoped transaction");
        let refused = session
            .execute(
                &format!("UPDATE persons SET attributes = '{document}' WHERE person_id = $1"),
                &[&ada],
            )
            .await
            .expect_err("a document that is not an object");
        assert_eq!(
            refused.code(),
            Some(&SqlState::CHECK_VIOLATION),
            "{document}: {refused}"
        );
        session.batch_execute("ROLLBACK").await.expect("a rollback");
    }
}

/// The schema keeps the claim of a mapper in lowercase, whoever writes it:
/// a reader that matches keys without case takes none for a reserved one.
#[tokio::test]
async fn the_claim_of_a_mapper_is_kept_in_lowercase_whatever_writes_it() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(&app, scope, portal).await;
    let make = |id: u128, claim: &str| Mapper {
        id: Uuid::from_u128(id),
        client_id: "portal".to_owned(),
        name: format!("mapper-{id}"),
        kind: MapperKind::Attribute {
            attribute: "mail".to_owned(),
        },
        claim: Some(claim.to_owned()),
        targets: vec![ClaimTarget::IdToken],
        scope: Some("profile".to_owned()),
        created_at: app.now(),
    };

    for (id, claim) in [(1, "Email"), (2, "EMAIL_VERIFIED"), (3, "Sub")] {
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        assert_eq!(
            work.insert_mapper(&make(id, claim)).await,
            Err(StorageError::Failed),
            "{claim}"
        );
    }
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.insert_mapper(&make(4, "mail")).await, Ok(true));
}

/// The mappers of a client come back in the byte order of their names,
/// whatever plan the database picks: here one that reads no index.
#[tokio::test]
async fn the_mappers_of_a_client_are_read_in_the_order_of_their_names_whatever_the_plan() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let name = database.name();
    connect(&database, "saffui_owner")
        .await
        .batch_execute(&format!(
            "ALTER DATABASE {name} SET enable_indexscan = off;
             ALTER DATABASE {name} SET enable_indexonlyscan = off;
             ALTER DATABASE {name} SET enable_bitmapscan = off"
        ))
        .await
        .expect("plans that read no index");
    let scope = create_realm(&app, "acme").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(&app, scope, portal).await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for (id, written) in [(1, "beta"), (2, "Zeta"), (3, "alpha")] {
        let mapper = Mapper {
            id: Uuid::from_u128(id),
            client_id: "portal".to_owned(),
            name: written.to_owned(),
            kind: MapperKind::Attribute {
                attribute: written.to_owned(),
            },
            claim: Some(written.to_lowercase()),
            targets: vec![ClaimTarget::IdToken],
            scope: Some("profile".to_owned()),
            created_at: app.now(),
        };
        assert_eq!(work.insert_mapper(&mapper).await, Ok(true));
    }

    let names: Vec<String> = work
        .list_mappers("portal")
        .await
        .expect("the mappers")
        .into_iter()
        .map(|mapper| mapper.name)
        .collect();

    assert_eq!(names, ["Zeta", "alpha", "beta"]);
}
