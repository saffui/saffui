//! A serving node on a database a test owns, killed when the test ends.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use pgcore::APP_ROLE;
use pgcore::testkit::TestDatabase;

pub const PUBLIC_ORIGIN: &str = "http://localhost:8080";

pub struct Node {
    process: Child,
    journal: Arc<Mutex<Vec<String>>>,
    pub data: SocketAddr,
    pub ops: SocketAddr,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Node {
    /// Starts `serve` on free ports and waits until it says where it listens.
    pub fn start(mut command: Command, database: &TestDatabase) -> Self {
        command
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--ops-listen",
                "127.0.0.1:0",
            ])
            .args(["--drain-delay", "0"])
            .env("SAFFUI_DATABASE_URL", database.connection_string(APP_ROLE))
            .env("SAFFUI_PUBLIC_ORIGIN", PUBLIC_ORIGIN)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut process = command.spawn().expect("the saffui binary starts");
        let mut journal = BufReader::new(process.stderr.take().expect("standard error is piped"));

        // A thread reads, so that a node that says nothing fails the test instead of hanging it.
        let (sender, receiver) = mpsc::channel();
        let kept = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&kept);
        thread::spawn(move || {
            let mut line = String::new();
            let _ = journal.read_line(&mut line);
            let _ = sender.send(line);
            // Keeps reading: a node whose journal nobody drains would block on a full pipe.
            let mut rest = String::new();
            while journal.read_line(&mut rest).is_ok_and(|read| read > 0) {
                lines
                    .lock()
                    .expect("the journal of the node")
                    .push(std::mem::take(&mut rest));
            }
        });
        let line = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("the node wrote a first line in time");
        assert!(
            line.contains(" listening "),
            "the node did not start: {line:?}"
        );
        let read_address = |key: &str| -> SocketAddr {
            line.split_whitespace()
                .find_map(|field| field.strip_prefix(key))
                .and_then(|address| address.parse().ok())
                .unwrap_or_else(|| panic!("no {key} address in {line:?}"))
        };
        Self {
            data: read_address("data="),
            ops: read_address("ops="),
            journal: kept,
            process,
        }
    }

    /// Waits up to `patience` for a line of the journal that holds every one of `parts`.
    pub fn wait_for_journal_line(&self, parts: &[&str], patience: Duration) -> Option<String> {
        let deadline = Instant::now() + patience;
        loop {
            let found = self
                .journal
                .lock()
                .expect("the journal of the node")
                .iter()
                .find(|line| parts.iter().all(|part| line.contains(part)))
                .cloned();
            if found.is_some() || Instant::now() >= deadline {
                return found;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
