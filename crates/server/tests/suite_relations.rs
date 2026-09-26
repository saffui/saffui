//! The relation store, in a process that runs it. The store is experimental
//! and off unless the process turns it on, which a process does once: its
//! suites share a binary of their own, and every case turns it on first.
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
