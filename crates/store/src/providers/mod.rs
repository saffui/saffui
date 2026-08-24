//! Reading and writing one family of rows.
//!
//! Every method takes a transaction the caller opened and will commit. There is
//! deliberately no second form that opens its own: a provider that could would
//! be the one every caller reached for, and nothing built from several of them
//! could then be made atomic.
//!
//! The tenant is not a parameter. It is whatever the transaction was scoped to,
//! so a caller cannot name one that disagrees with the rules being applied.

pub mod auth_flows;
pub mod authz_policies;
pub mod authz_surface;
pub mod client_scopes;
pub mod clients;
pub mod credentials;
pub mod login;
pub mod mail;
pub mod oidc;
pub mod one_time_tokens;
pub mod organizations;
pub mod pairwise;
pub mod pushed;
pub mod realm_keys;
pub mod realms;
pub mod rebac;
pub mod roles;
pub mod sessions;
pub mod tenants;
pub mod users;
pub mod webauthn;
