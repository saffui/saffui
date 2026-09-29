//! The relation store, in a process that runs it, beside the wallet verifier
//! the console contract asks with. Both are experimental and off unless the
//! process turns them on, which a process does once: these suites share a
//! binary of their own, and every case turns them on first.
mod support;

#[path = "grouped/admin_authz.rs"]
mod admin_authz;
#[path = "grouped/console_contract.rs"]
mod console_contract;
#[path = "grouped/enforcement.rs"]
mod enforcement;
#[path = "grouped/relation_doors.rs"]
mod relation_doors;
#[path = "grouped/relations.rs"]
mod relations;
