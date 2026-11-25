//! The OpenID Connect provider of a realm.

pub mod authorize;
pub mod code;
pub mod discovery;
pub mod errors;
pub(crate) mod implicit;
pub mod introspect;
pub mod logout;
pub mod pkce;
pub(crate) mod refresh;
pub mod registration;
pub mod response;
pub mod revoke;
#[cfg(test)]
pub(crate) mod scenario;
pub mod token;
pub mod userinfo;
