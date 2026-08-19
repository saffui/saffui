//! What a refusal looks like from outside.
//!
//! The four gates answer with distinct reasons because the log needs them
//! distinct. What the caller is told is decided here, and it is deliberately
//! less: which actions exist, and whether a route is declared at all, are not
//! things an unaccepted token gets to learn from the shape of its refusal.

use commons::error::ErrorCode;
use commons::http::ApiError;

use crate::middleware::admin_policy::Refusal;

/// The answer a refused request receives.
///
/// Every refusal renders as the same code. A caller that could tell "you may
/// not" from "this route wants something you do not hold" would have a probe
/// for the shape of the admin plane.
pub fn refused(refusal: Refusal) -> ApiError {
    // The reason is not lost: it is what the decision returned, and the log
    // records it. This is only what travels back.
    let _ = refusal;
    ApiError::new(ErrorCode::AccessDenied)
}

/// A request that carried no token, or one this deployment cannot read.
///
/// Distinct from a refusal because it is actionable: a caller with no token can
/// go and get one, and telling it so reveals nothing about what it would then
/// be allowed to do.
pub fn unauthenticated() -> ApiError {
    ApiError::new(ErrorCode::Unauthorized)
}
