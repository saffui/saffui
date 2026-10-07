//! Journeys through the real binary: `serve`, from its settings to its exit.

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStringExt;
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::mpsc;
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

mod support;

/// Longer than anything here should take, so that a hang fails instead of lasting.
const PATIENCE: Duration = Duration::from_secs(10);
const PAUSE: Duration = Duration::from_millis(20);

/// Port 0 leaves the choice to the system, and the journal says what it chose:
/// no test picks a port that another could be given.
const ANY_PORT: &str = "127.0.0.1:0";

/// A running `serve`. It is killed when the test ends, passed or failed.
struct Serve {
    process: Child,
    /// Standard error, where the journal goes. `None` once a test has closed it.
    journal: Option<BufReader<ChildStderr>>,
    /// What was already read from it.
    heard: String,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Serve {
    fn spawn(configure: impl FnOnce(&mut Command)) -> Self {
        let mut command = support::saffui_command();
        command
            .arg("serve")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        configure(&mut command);
        let mut process = command.spawn().expect("the saffui binary starts");
        let journal = process.stderr.take().map(BufReader::new);
        Self {
            process,
            journal,
            heard: String::new(),
        }
    }

    /// The first line of the journal. A thread reads it, so that a process which
    /// writes nothing fails the test after `PATIENCE` instead of hanging it.
    fn read_first_line(&mut self) -> String {
        let mut journal = self.journal.take().expect("standard error is open");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let _ = journal.read_line(&mut line);
            let _ = sender.send((line, journal));
        });
        let (line, journal) = receiver
            .recv_timeout(PATIENCE)
            .expect("serve wrote a first line in time");
        self.journal = Some(journal);
        self.heard.push_str(&line);
        line
    }

    fn send_signal(&self, name: &str) {
        let sent = Command::new("kill")
            .args(["-s", name, &self.process.id().to_string()])
            .status()
            .expect("the kill command runs");
        assert!(sent.success(), "kill -s {name} failed");
    }

    /// The exit code, and everything the process wrote on standard error.
    fn wait_for_exit(mut self) -> (Option<i32>, String) {
        let deadline = Instant::now() + PATIENCE;
        let status = loop {
            if let Some(status) = self.process.try_wait().expect("the process can be polled") {
                break status;
            }
            assert!(Instant::now() < deadline, "serve did not exit in time");
            sleep(PAUSE);
        };
        let mut journal = mem::take(&mut self.heard);
        if let Some(mut unread) = self.journal.take() {
            unread
                .read_to_string(&mut journal)
                .expect("standard error is text");
        }
        (status.code(), journal)
    }
}

/// Starts `serve` on a free port per plane, with `drain_delay` seconds of
/// delay, all given the way `pass_settings` decides. Returns the data address,
/// then the ops one, as the `listening` line of the journal names them.
fn start_serve(
    pass_settings: fn(&mut Command, &str),
    drain_delay: &str,
) -> (Serve, SocketAddr, SocketAddr) {
    let mut serving = Serve::spawn(|command| pass_settings(command, drain_delay));
    let line = serving.read_first_line();
    assert!(
        line.contains(" listening "),
        "serve did not say that it listens: {line:?}"
    );
    let (data, ops) = (read_address(&line, "data="), read_address(&line, "ops="));
    (serving, data, ops)
}

fn pass_as_options(command: &mut Command, drain_delay: &str) {
    command.args(["--listen", ANY_PORT, "--ops-listen", ANY_PORT]);
    command.args(["--drain-delay", drain_delay]);
}

fn pass_as_variables(command: &mut Command, drain_delay: &str) {
    command
        .env("SAFFUI_LISTEN", ANY_PORT)
        .env("SAFFUI_OPS_LISTEN", ANY_PORT)
        .env("SAFFUI_DRAIN_DELAY", drain_delay);
}

/// The address a journal line gives after `key`, as in `data=127.0.0.1:8080`.
fn read_address(line: &str, key: &str) -> SocketAddr {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(key))
        .and_then(|address| address.parse().ok())
        .unwrap_or_else(|| panic!("no {key} address in {line:?}"))
}

/// Each line of a journal without its timestamp: the level, the target, the message.
fn read_journal_lines(journal: &str) -> Vec<&str> {
    journal
        .lines()
        .map(|line| line.split_once(' ').map_or(line, |(_, rest)| rest).trim())
        .collect()
}

/// What a whole run stopped by `signal` writes: these lines and no other.
fn tell_whole_run(data: SocketAddr, ops: SocketAddr, signal: &str) -> [String; 3] {
    [
        format!("INFO saffui::cli::serve: listening data={data} ops={ops}"),
        format!("INFO saffui::cli::serve: shutdown requested signal=\"{signal}\""),
        "INFO saffui::cli::serve: shutdown complete".to_owned(),
    ]
}

/// One `GET` on a connection of its own: the status code, or why there is none.
fn request_status(address: SocketAddr, path: &str) -> io::Result<u16> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(PATIENCE))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut status_line = String::new();
    BufReader::new(stream).read_line(&mut status_line)?;
    status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::other(format!("not a status line: {status_line:?}")))
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        sleep(PAUSE);
    }
}

/// Runs `serve` with `taken_option` on an address that already listens.
fn assert_taken_address_is_refused(taken_option: &str, free_option: &str) {
    let taken = TcpListener::bind(ANY_PORT).expect("a free port");
    let address = taken.local_addr().expect("a bound address").to_string();

    let refused = Serve::spawn(|command| {
        command.args([taken_option, &address, free_option, ANY_PORT]);
    });

    let (code, stderr) = refused.wait_for_exit();
    assert_eq!(code, Some(1), "stderr was: {stderr}");
    assert!(
        stderr.contains(&format!("cannot listen on {address}")),
        "{address} is not named: {stderr}"
    );
}

#[test]
fn sigterm_fails_readiness_first_serves_through_the_drain_delay_then_exits_with_0() {
    // Long enough for a loaded machine to reach the data plane before the delay is over.
    const DRAIN_DELAY: Duration = Duration::from_secs(4);
    let (serving, data, ops) = start_serve(pass_as_options, &DRAIN_DELAY.as_secs().to_string());

    let signaled_at = Instant::now();
    serving.send_signal("TERM");

    wait_until("readiness reports 503 after SIGTERM", || {
        request_status(ops, "/readyz").ok() == Some(503)
    });
    assert_eq!(
        request_status(data, "/livez").ok(),
        Some(404),
        "the data plane must still answer once readiness has failed, and never serve a probe"
    );

    let (code, journal) = serving.wait_for_exit();
    assert_eq!(code, Some(0), "journal was: {journal}");
    assert!(
        signaled_at.elapsed() >= DRAIN_DELAY,
        "serve exited before its drain delay was over"
    );
    assert_eq!(
        read_journal_lines(&journal),
        tell_whole_run(data, ops, "SIGTERM"),
        "journal was: {journal}"
    );
}

#[test]
fn sigint_asks_for_the_same_shutdown_and_exits_with_0() {
    let (serving, data, ops) = start_serve(pass_as_options, "0");

    serving.send_signal("INT");

    let (code, journal) = serving.wait_for_exit();
    assert_eq!(code, Some(0), "journal was: {journal}");
    assert_eq!(
        read_journal_lines(&journal),
        tell_whole_run(data, ops, "SIGINT"),
        "journal was: {journal}"
    );
}

#[test]
fn every_setting_is_read_from_the_environment_when_no_option_is_given() {
    let (serving, data, ops) = start_serve(pass_as_variables, "0");

    // Port 0 came from the variables: the defaults would have bound 8080 and 8081.
    assert_ne!(data.port(), 8080, "SAFFUI_LISTEN was not read");
    assert_ne!(ops.port(), 8081, "SAFFUI_OPS_LISTEN was not read");
    assert_eq!(
        request_status(data, "/livez").ok(),
        Some(404),
        "the data plane does not answer where the journal says"
    );
    assert_eq!(
        request_status(ops, "/livez").ok(),
        Some(200),
        "the operations plane does not answer where the journal says"
    );

    let signaled_at = Instant::now();
    serving.send_signal("TERM");
    let (code, journal) = serving.wait_for_exit();
    assert_eq!(code, Some(0), "journal was: {journal}");
    assert!(
        signaled_at.elapsed() < Duration::from_secs(5),
        "SAFFUI_DRAIN_DELAY was not read: serve waited for its default delay"
    );
}

#[test]
fn one_address_for_both_planes_is_refused_with_code_2_and_both_settings_named() {
    let refused = Serve::spawn(|command| {
        command.args([
            "--listen",
            "127.0.0.1:8080",
            "--ops-listen",
            "127.0.0.1:8080",
        ]);
    });

    let (code, stderr) = refused.wait_for_exit();
    assert_eq!(code, Some(2), "stderr was: {stderr}");
    for setting in [
        "--listen",
        "SAFFUI_LISTEN",
        "--ops-listen",
        "SAFFUI_OPS_LISTEN",
    ] {
        assert!(stderr.contains(setting), "{setting} is not named: {stderr}");
    }
}

#[test]
fn an_unreadable_address_is_named_on_stderr_and_exits_with_2() {
    let refused = Serve::spawn(|command| {
        command.env("SAFFUI_OPS_LISTEN", "nowhere");
    });

    let (code, stderr) = refused.wait_for_exit();
    assert_eq!(code, Some(2), "stderr was: {stderr}");
    for named in ["SAFFUI_OPS_LISTEN", "nowhere"] {
        assert!(stderr.contains(named), "{named} is not named: {stderr}");
    }
}

#[test]
fn an_unreadable_drain_delay_is_named_on_stderr_and_exits_with_2() {
    let refused = Serve::spawn(|command| {
        command.args(["--drain-delay", "soon"]);
    });

    let (code, stderr) = refused.wait_for_exit();
    assert_eq!(code, Some(2), "stderr was: {stderr}");
    for named in ["--drain-delay", "soon"] {
        assert!(stderr.contains(named), "{named} is not named: {stderr}");
    }
}

#[test]
fn a_variable_that_is_not_unicode_is_refused_with_code_2_and_does_not_pass_for_absent() {
    let refused = Serve::spawn(|command| {
        command.env("SAFFUI_LISTEN", OsString::from_vec(vec![0xff]));
    });

    let (code, stderr) = refused.wait_for_exit();
    assert_eq!(code, Some(2), "stderr was: {stderr}");
    assert!(
        stderr.contains("SAFFUI_LISTEN"),
        "the variable is not named: {stderr}"
    );
}

#[test]
fn a_control_character_in_an_unreadable_value_reaches_stderr_escaped() {
    let refused = Serve::spawn(|command| {
        command.args(["--drain-delay", "\u{1b}[31msoon"]);
    });

    let (code, stderr) = refused.wait_for_exit();
    assert_eq!(code, Some(2), "stderr was: {stderr:?}");
    assert!(
        !stderr.contains('\u{1b}'),
        "the escape character reached standard error: {stderr:?}"
    );
    assert!(
        stderr.contains("\\u{1b}"),
        "the value is not shown escaped: {stderr:?}"
    );
}

#[test]
fn a_data_address_already_taken_is_named_on_stderr_and_exits_with_1() {
    assert_taken_address_is_refused("--listen", "--ops-listen");
}

#[test]
fn an_operations_address_already_taken_is_named_on_stderr_and_exits_with_1() {
    assert_taken_address_is_refused("--ops-listen", "--listen");
}

#[test]
fn serve_help_shows_the_variable_and_the_default_of_every_setting() {
    let output = support::saffui_command()
        .args(["serve", "--help"])
        .output()
        .expect("the saffui binary starts");
    // The help wraps its lines: the breaks are not part of what it says.
    let help = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert_eq!(output.status.code(), Some(0));
    for shown in [
        "[env: SAFFUI_LISTEN] [default: 127.0.0.1:8080]",
        "[env: SAFFUI_OPS_LISTEN] [default: 127.0.0.1:8081]",
        "[env: SAFFUI_DRAIN_DELAY] [default: 5]",
    ] {
        assert!(help.contains(shown), "{shown:?} is not in the help: {help}");
    }
}

#[test]
fn a_journal_nobody_reads_does_not_end_the_process_before_its_shutdown() {
    let (mut serving, _data, _ops) = start_serve(pass_as_options, "0");
    // With the reading end closed, every later write to standard error fails.
    drop(serving.journal.take());

    serving.send_signal("TERM");

    let (code, _) = serving.wait_for_exit();
    assert_eq!(code, Some(0), "a failed journal write must not be fatal");
}
