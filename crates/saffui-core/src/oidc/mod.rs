//! The OpenID Connect provider of a realm.

pub mod authorize;
pub mod code;
pub mod discovery;
pub mod errors;
pub mod introspect;
pub mod logout;
pub mod pkce;
mod refresh;
pub mod revoke;
#[cfg(test)]
mod scenario;
pub mod token;
pub mod userinfo;
