//! What runs before a handler does.
//!
//! Two gates over one admission. `bearer` reads a token and establishes who is
//! asking; `caller` stops there, and `admin_guard` additionally charges the
//! route against what that caller may do.

pub mod admin_guard;
pub mod admin_policy;
pub(crate) mod bearer;
pub mod caller;
