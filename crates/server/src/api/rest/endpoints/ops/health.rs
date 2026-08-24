use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use actix_web::{HttpResponse, web};
use deadpool_postgres::Pool;
use serde::Serialize;

/// How long a readiness probe waits on the database before calling it out.
///
/// Shorter than any sane probe period, so a slow answer reads as not ready
/// rather than piling probes up behind one another.
const REACH: Duration = Duration::from_secs(2);

/// What the process knows about itself.
#[derive(Clone)]
pub struct Vitals {
    pool: Pool,
    /// The highest migration this build carries, so a schema ahead of it is a
    /// pod that must not serve: a newer peer has migrated and this one cannot
    /// read what it wrote.
    schema: i32,
    draining: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
}

impl Vitals {
    pub fn new(pool: Pool, schema: i32) -> Self {
        Self {
            pool,
            schema,
            draining: Arc::new(AtomicBool::new(false)),
            started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Say the process is up and may take traffic.
    pub fn started(&self) {
        self.started.store(true, Ordering::Relaxed);
    }

    /// Stop taking new traffic. What a signal handler calls, before it waits
    /// for what is in flight.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    pub fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }
}

#[derive(Serialize)]
struct Answer {
    ready: bool,
    /// Which check said no, for an operator reading a probe log.
    why: Option<&'static str>,
}

/// Alive: the process runs. No input, no output, no database.
///
/// Anything this touches is something that can get the pod restarted, and a
/// restart fixes only the process. It answers while the database is down,
/// because that is what tells an orchestrator to leave this pod alone.
pub async fn alive() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// Ready: this pod can serve a request right now.
///
/// Four questions, and each has taken a service down somewhere: is it draining,
/// did it finish starting, can it reach the database inside a bounded wait, and
/// is the schema one this build reads.
pub async fn ready(vitals: web::Data<Vitals>) -> HttpResponse {
    if vitals.draining() {
        return not_ready("draining");
    }
    if !vitals.started.load(Ordering::Relaxed) {
        return not_ready("starting");
    }

    let Ok(Ok(connection)) = tokio::time::timeout(REACH, vitals.pool.get()).await else {
        return not_ready("no connection");
    };
    if tokio::time::timeout(REACH, connection.simple_query("SELECT 1"))
        .await
        .is_err()
    {
        return not_ready("database not answering");
    }

    match schema_of(&connection).await {
        Some(applied) if applied <= vitals.schema => HttpResponse::Ok().json(Answer {
            ready: true,
            why: None,
        }),
        // Behind is a pod that has not migrated yet and will; ahead is one a
        // peer migrated past, which cannot read what that peer now writes.
        Some(_) => not_ready("schema ahead of this build"),
        None => not_ready("no schema"),
    }
}

/// Started: the process finished coming up.
///
/// Its own probe because the others answer during startup and mean something
/// else: a slow migration would otherwise read as a pod that keeps failing its
/// liveness probe, and an orchestrator would restart it into the same slow
/// migration forever.
pub async fn started(vitals: web::Data<Vitals>) -> HttpResponse {
    if vitals.started.load(Ordering::Relaxed) {
        HttpResponse::Ok().finish()
    } else {
        not_ready("starting")
    }
}

fn not_ready(why: &'static str) -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(Answer {
        ready: false,
        why: Some(why),
    })
}

/// The highest migration the database has applied.
///
/// Read at the column's own width. `version` is an `integer`, so anything
/// wider fails to convert, and a failed conversion reads as a database with no
/// schema at all.
async fn schema_of(connection: &deadpool_postgres::Object) -> Option<i32> {
    connection
        .query_opt("SELECT max(version) FROM schema_migrations", &[])
        .await
        .ok()
        .flatten()
        .and_then(|row| row.try_get::<_, Option<i32>>(0).ok().flatten())
}
