//! The shutdown on real listeners. The data plane is mounted with a handler
//! the test holds, so that a request is in flight when the stop is asked.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use actix_web::rt::System;
use actix_web::rt::time::sleep;
use actix_web::{HttpResponse, web};
use server::serve::{PlaneAddresses, ShutdownOptions, bind_planes_with};

/// Longer than anything here should take, so that a hang fails instead of lasting.
const PATIENCE: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(10);

const HELD_BODY: &str = "held, then released";

/// Far under the 30 seconds the framework waits by default, which `PATIENCE` would not.
const SHORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// What the test and the planes tell each other. Each flag is raised once.
#[derive(Default)]
struct Flags {
    /// Raised by the handler: the request has reached it.
    request_held: AtomicBool,
    /// Raised by the test: the handler may answer.
    request_released: AtomicBool,
    /// Raised by the test: the future given to `run_until` resolves.
    shutdown_requested: AtomicBool,
}

/// Both planes, serving on a thread of their own.
struct RunningPlanes {
    addresses: PlaneAddresses,
    flags: Arc<Flags>,
    /// Receives what `run_until` returned.
    ended: mpsc::Receiver<io::Result<()>>,
}

/// Binds both planes on free ports, the data plane holding every request to
/// `/held`, and serves them until `shutdown_requested` is raised.
fn run_planes(options: ShutdownOptions) -> RunningPlanes {
    let flags = Arc::new(Flags::default());
    let (announce, announced) = mpsc::channel();
    let (report, ended) = mpsc::channel();
    {
        let flags = Arc::clone(&flags);
        thread::spawn(move || {
            let returned = System::new().block_on(async {
                let held = web::Data::from(Arc::clone(&flags));
                let mount_data_plane = move |config: &mut web::ServiceConfig| {
                    config
                        .app_data(held.clone())
                        .route("/held", web::get().to(hold_request));
                };
                let any_port = SocketAddr::from(([127, 0, 0, 1], 0));
                let asked = PlaneAddresses {
                    data: any_port,
                    ops: any_port,
                };
                let planes = bind_planes_with(asked, options, mount_data_plane)
                    .map_err(|refused| refused.source)?;
                let _ = announce.send(planes.addresses);
                planes
                    .run_until(watch_flag(&flags.shutdown_requested))
                    .await
            });
            let _ = report.send(returned);
        });
    }
    let addresses = announced
        .recv_timeout(PATIENCE)
        .expect("both planes are bound in time");
    RunningPlanes {
        addresses,
        flags,
        ended,
    }
}

async fn hold_request(flags: web::Data<Flags>) -> HttpResponse {
    flags.request_held.store(true, Ordering::SeqCst);
    watch_flag(&flags.request_released).await;
    HttpResponse::Ok().body(HELD_BODY)
}

/// Resolves once `flag` is raised.
async fn watch_flag(flag: &AtomicBool) {
    while !flag.load(Ordering::SeqCst) {
        sleep(TICK).await;
    }
}

/// Sends one `GET` on a connection of its own and leaves the response unread.
fn send_request(address: SocketAddr, path: &str) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(PATIENCE))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    Ok(stream)
}

/// Reads a response to the end of its connection: the status code and the body.
fn read_response(mut stream: TcpStream) -> io::Result<(u16, String)> {
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    response
        .split_once("\r\n\r\n")
        .and_then(|(head, body)| {
            let code = head.split(' ').nth(1)?.parse().ok()?;
            Some((code, body.to_owned()))
        })
        .ok_or_else(|| io::Error::other(format!("not a response: {response:?}")))
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        thread::sleep(TICK);
    }
}

#[test]
fn a_request_in_flight_finishes_after_readiness_has_failed_and_the_planes_stop_cleanly() {
    let planes = run_planes(ShutdownOptions {
        drain_delay_seconds: 0,
        drain_timeout_seconds: PATIENCE.as_secs(),
    });
    let held = send_request(planes.addresses.data, "/held").expect("the data plane accepts");
    wait_until("the request reaches its handler", || {
        planes.flags.request_held.load(Ordering::SeqCst)
    });

    planes
        .flags
        .shutdown_requested
        .store(true, Ordering::SeqCst);

    wait_until("the data plane refuses a new connection", || {
        TcpStream::connect(planes.addresses.data).is_err()
    });
    let readiness = send_request(planes.addresses.ops, "/readyz").and_then(read_response);
    assert_eq!(
        readiness.ok(),
        Some((503, String::new())),
        "the operations plane must answer, and say not ready, while a request is in flight"
    );

    planes.flags.request_released.store(true, Ordering::SeqCst);

    assert_eq!(
        read_response(held).ok(),
        Some((200, HELD_BODY.to_owned())),
        "the request in flight must get its whole response"
    );
    let returned = planes
        .ended
        .recv_timeout(PATIENCE)
        .expect("run_until returns in time");
    assert!(returned.is_ok(), "run_until failed: {returned:?}");
}

#[test]
fn a_request_that_never_finishes_is_given_up_at_the_drain_timeout() {
    let planes = run_planes(ShutdownOptions {
        drain_delay_seconds: 0,
        drain_timeout_seconds: SHORT_DRAIN_TIMEOUT.as_secs(),
    });
    let _held = send_request(planes.addresses.data, "/held").expect("the data plane accepts");
    wait_until("the request reaches its handler", || {
        planes.flags.request_held.load(Ordering::SeqCst)
    });

    let asked_at = Instant::now();
    planes
        .flags
        .shutdown_requested
        .store(true, Ordering::SeqCst);
    let returned = planes
        .ended
        .recv_timeout(PATIENCE)
        .expect("run_until returns in time");
    let took = asked_at.elapsed();

    assert!(returned.is_ok(), "run_until failed: {returned:?}");
    assert!(
        took >= SHORT_DRAIN_TIMEOUT,
        "the request was given up after {took:?}, before the drain timeout"
    );
}
