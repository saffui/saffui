//! Binds the two planes, runs them, and stops them in the order a rolling
//! restart needs: readiness first, then a delay for traffic to move away,
//! then the data plane, the operations plane last.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::thread;
use std::time::Duration;

use actix_web::dev::Server;
use actix_web::rt::time::sleep;
use actix_web::{App, HttpServer, web};
use futures_util::future::try_join3;

use crate::api::config::{register_data_plane, register_ops_plane};
use crate::api::rest::endpoints::health::DrainFlag;

/// How long both planes keep serving once readiness has failed: the time
/// whoever routes traffic needs to notice. The operator can change it.
pub const DEFAULT_DRAIN_DELAY_SECONDS: u64 = 5;

/// How long requests in flight then have to finish. With the default delay,
/// under the 30 seconds an orchestrator usually grants before it kills.
pub const DEFAULT_DRAIN_TIMEOUT_SECONDS: u64 = 20;
const _: () = assert!(DEFAULT_DRAIN_DELAY_SECONDS + DEFAULT_DRAIN_TIMEOUT_SECONDS < 30);

/// Connections the data plane holds at once, all its workers together: under the
/// 1024 descriptors a process is commonly given, the probes must still answer.
const DATA_PLANE_CONNECTIONS: usize = 768;

/// How long an idle connection is kept, and how long the head of the first
/// request of a connection has to arrive. The framework's defaults today,
/// written so that an upgrade cannot move them.
const KEEP_ALIVE: Duration = Duration::from_secs(5);
const FIRST_REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(5);

/// What the framework starts when it cannot tell the available parallelism.
const WORKERS_WHEN_PARALLELISM_IS_UNKNOWN: NonZeroUsize = NonZeroUsize::new(2).unwrap();

// The operations plane only answers probes: it is kept as small as it can be.
const OPS_PLANE_WORKERS: usize = 1;
const OPS_PLANE_BLOCKING_THREADS: usize = 1;
const OPS_PLANE_CONNECTIONS: usize = 16;

#[derive(Clone, Copy)]
pub struct PlaneAddresses {
    pub data: SocketAddr,
    pub ops: SocketAddr,
}

/// The pace of a shutdown, in whole seconds as the framework counts its own.
#[derive(Clone, Copy)]
pub struct ShutdownOptions {
    /// How long both planes keep serving once readiness has failed.
    pub drain_delay_seconds: u64,
    /// How long requests in flight then have to finish on the data plane.
    pub drain_timeout_seconds: u64,
}

pub struct BindError {
    pub address: SocketAddr,
    pub source: io::Error,
}

/// Both planes, bound and not serving yet.
pub struct BoundPlanes {
    /// The addresses really bound: a port asked as 0 is known here.
    pub addresses: PlaneAddresses,
    data_plane: Server,
    ops_plane: Server,
    drain_flag: web::Data<DrainFlag>,
    drain_delay: Duration,
}

/// Binds one listener per plane, the data plane mounted as the product mounts
/// it. Nothing is served before [`BoundPlanes::run_until`].
///
/// # Errors
///
/// Returns the first address that cannot be bound.
pub fn bind_planes(
    asked: PlaneAddresses,
    options: ShutdownOptions,
) -> Result<BoundPlanes, BindError> {
    bind_planes_with(asked, options, register_data_plane)
}

/// Binds one listener per plane, the data plane mounted by `mount_data_plane`:
/// a test mounts a handler it holds, to stop the planes around a request in flight.
///
/// # Errors
///
/// Returns the first address that cannot be bound.
pub fn bind_planes_with<F>(
    asked: PlaneAddresses,
    options: ShutdownOptions,
    mount_data_plane: F,
) -> Result<BoundPlanes, BindError>
where
    F: Fn(&mut web::ServiceConfig) + Send + Clone + 'static,
{
    let drain_flag = web::Data::new(DrainFlag::default());
    // The framework starts one worker per unit of available parallelism and
    // does not say how many: the cap is split by the same count.
    let workers = thread::available_parallelism().unwrap_or(WORKERS_WHEN_PARALLELISM_IS_UNKNOWN);

    // Neither plane hears signals itself: the framework would stop accepting
    // the moment one lands, before readiness had failed.
    //
    // The framework times the head of the first request only: a body, or a
    // later request, may trickle in forever. Nothing here bounds a slow client yet.
    let data_plane = HttpServer::new(move || App::new().configure(&mount_data_plane))
        .disable_signals()
        .keep_alive(KEEP_ALIVE)
        .client_request_timeout(FIRST_REQUEST_HEAD_TIMEOUT)
        .max_connections(split_connections(DATA_PLANE_CONNECTIONS, workers))
        .shutdown_timeout(options.drain_timeout_seconds)
        .bind(asked.data)
        .map_err(|source| BindError {
            address: asked.data,
            source,
        })?;
    let ops_plane = {
        let drain_flag = drain_flag.clone();
        HttpServer::new(move || App::new().configure(register_ops_plane(drain_flag.clone())))
            .disable_signals()
            .keep_alive(KEEP_ALIVE)
            .client_request_timeout(FIRST_REQUEST_HEAD_TIMEOUT)
            .workers(OPS_PLANE_WORKERS)
            .worker_max_blocking_threads(OPS_PLANE_BLOCKING_THREADS)
            .max_connections(OPS_PLANE_CONNECTIONS)
            .bind(asked.ops)
            .map_err(|source| BindError {
                address: asked.ops,
                source,
            })?
    };

    Ok(BoundPlanes {
        addresses: PlaneAddresses {
            data: data_plane.addrs().first().copied().unwrap_or(asked.data),
            ops: ops_plane.addrs().first().copied().unwrap_or(asked.ops),
        },
        data_plane: data_plane.run(),
        ops_plane: ops_plane.run(),
        drain_flag,
        drain_delay: Duration::from_secs(options.drain_delay_seconds),
    })
}

/// One worker's share of `total` connections, never less than one.
fn split_connections(total: usize, workers: NonZeroUsize) -> usize {
    (total / workers).max(1)
}

impl BoundPlanes {
    /// Serves both planes until `shutdown_requested` resolves, then stops them.
    ///
    /// # Errors
    ///
    /// Returns the error of a plane that cannot start.
    pub async fn run_until(self, shutdown_requested: impl Future<Output = ()>) -> io::Result<()> {
        let Self {
            data_plane,
            ops_plane,
            drain_flag,
            drain_delay,
            ..
        } = self;

        let (data_handle, ops_handle) = (data_plane.handle(), ops_plane.handle());
        let stop_in_order = async {
            shutdown_requested.await;
            drain_flag.start_drain();
            // Both planes serve through the delay: whoever routes traffic must
            // see readiness fail before the data plane refuses a connection.
            sleep(drain_delay).await;
            // Graceful: no new connection, and what is in flight finishes under the
            // drain timeout. The probes keep answering until that is over.
            data_handle.stop(true).await;
            ops_handle.stop(false).await;
            Ok::<(), io::Error>(())
        };

        try_join3(data_plane, ops_plane, stop_in_order).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::split_connections;

    fn count_workers(count: usize) -> NonZeroUsize {
        NonZeroUsize::new(count).expect("a worker count above zero")
    }

    #[test]
    fn the_shares_of_all_workers_together_never_exceed_the_cap() {
        assert_eq!(split_connections(768, count_workers(8)), 96);

        for count in [1, 2, 7, 10, 768] {
            let held = split_connections(768, count_workers(count)) * count;
            assert!(held <= 768, "{count} workers hold {held} connections");
        }
    }

    #[test]
    fn a_worker_keeps_one_connection_when_workers_outnumber_the_cap() {
        assert_eq!(split_connections(768, count_workers(769)), 1);
    }
}
