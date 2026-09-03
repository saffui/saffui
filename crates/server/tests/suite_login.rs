//! One linked binary for a family of suites: fifty-nine binaries were
//! fifty-nine link editions, and the links were most of the wait.
mod support;

#[path = "grouped/protocol.rs"]
mod protocol;
#[path = "grouped/consent.rs"]
mod consent;
#[path = "grouped/binding.rs"]
mod binding;
#[path = "grouped/brute_force.rs"]
mod brute_force;
#[path = "grouped/recovery.rs"]
mod recovery;
#[path = "grouped/signup.rs"]
mod signup;
#[path = "grouped/mailed.rs"]
mod mailed;
#[path = "grouped/login_script.rs"]
mod login_script;
#[path = "grouped/hosted.rs"]
mod hosted;
#[path = "grouped/org_login.rs"]
mod org_login;
#[path = "grouped/ui_theme.rs"]
mod ui_theme;
#[path = "grouped/session_management.rs"]
mod session_management;
#[path = "grouped/hybrid.rs"]
mod hybrid;
#[path = "grouped/form_post.rs"]
mod form_post;
#[path = "grouped/provenance.rs"]
mod provenance;
#[path = "grouped/registration.rs"]
mod registration;
#[path = "grouped/require_par.rs"]
mod require_par;
#[path = "grouped/enforcement.rs"]
mod enforcement;
