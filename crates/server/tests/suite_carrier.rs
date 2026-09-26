//! The carrier's guard, in a process that runs it. The guard is experimental
//! and off unless the process turns it on, which a process does once: its
//! suite is a binary of its own, so the switch it needs is thrown for nothing
//! else.
mod support;

#[path = "grouped/sim_swap.rs"]
mod sim_swap;
