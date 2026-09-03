//! One linked binary for a family of suites: fifty-nine binaries were
//! fifty-nine link editions, and the links were most of the wait.
mod support;

#[path = "grouped/aggregated_claims.rs"]
mod aggregated_claims;
#[path = "grouped/assertions.rs"]
mod assertions;
#[path = "grouped/encryption.rs"]
mod encryption;
#[path = "grouped/fapi.rs"]
mod fapi;
#[path = "grouped/offline.rs"]
mod offline;
#[path = "grouped/pairwise.rs"]
mod pairwise;
#[path = "grouped/tls_auth.rs"]
mod tls_auth;
#[path = "grouped/token_exchange.rs"]
mod token_exchange;
#[path = "grouped/workload.rs"]
mod workload;
