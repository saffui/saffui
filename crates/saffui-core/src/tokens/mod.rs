//! Tokens: what a realm signs, and how what it signed is read back.

pub mod jws;
pub mod mint;
pub mod store;
pub mod verify;

/// What a token endpoint hands out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedAccessToken {
    pub token: String,
    pub expires_in: u64,
    pub scope: String,
}

/// The `typ` of an access token (RFC 9068): a token of another kind, an
/// identity token for one, is never accepted in its place.
pub const ACCESS_TOKEN_TYPE: &str = "at+jwt";

/// The claim of an access token that names the family of refresh tokens of
/// its grant, when that grant named claims for userinfo: short, as each
/// token is resent with each request, and in no registry of claim names.
pub const FAMILY_CLAIM: &str = "fam";

/// The `typ` of an identity token.
pub const IDENTITY_TOKEN_TYPE: &str = "JWT";

/// The algorithm of every access token, and of the identity tokens of a
/// client that names none. A realm is born with a key of it.
pub const DEFAULT_ALGORITHM: crate::ports::crypto::SignatureAlgorithm =
    crate::ports::crypto::SignatureAlgorithm::Es256;

/// How long an access token lives.
pub const ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 300;
