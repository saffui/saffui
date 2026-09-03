//! One linked binary for a family of suites: fifty-nine binaries were
//! fifty-nine link editions, and the links were most of the wait.
mod support;

#[path = "grouped/broker_login.rs"]
mod broker_login;
#[path = "grouped/caep.rs"]
mod caep;
#[path = "grouped/ldap_front.rs"]
mod ldap_front;
#[path = "grouped/ldap_login.rs"]
mod ldap_login;
#[path = "grouped/outbound.rs"]
mod outbound;
#[path = "grouped/scim.rs"]
mod scim;
#[path = "grouped/spnego_login.rs"]
mod spnego_login;
#[path = "grouped/ssf_poll.rs"]
mod ssf_poll;
