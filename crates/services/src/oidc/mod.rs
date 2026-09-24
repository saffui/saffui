//! The protocol, endpoint by endpoint: what OAuth 2.0 and OpenID Connect
//! ask of an authorization server, and the claims it mints.

pub mod authorize;
pub mod ciba;
pub mod detached;
pub mod device;
pub mod encryption;
pub mod fapi;
pub mod form_post;
pub mod grant;
pub mod implicit;
pub mod introspection;
pub mod landing;
pub mod logout;
pub mod mappers;
pub mod minting;
pub mod pairwise;
pub mod pushed;
pub mod registration;
pub mod request_object;
pub mod response_type;
pub mod revocation;
pub mod sign_in;
pub mod userinfo;
pub mod ussd;
