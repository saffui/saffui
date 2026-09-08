pub mod admin;
pub mod authz;
pub mod ops;
pub mod protocol;
pub mod scim;

use store::tenancy::TenantContext;

use crate::middleware::admin_guard::Admin;

/// The tenant and realm a handler works in.
///
/// The realm is the token's, never the path's. The guard already refuses a
/// path naming a realm the token did not mint, so the two agree by the time
/// a handler runs; reading it off the token makes that agreement structural
/// instead of merely upheld. A handler reached some other way would work in
/// its caller's own realm rather than in the one the URL asked for.
///
/// The path's realm is still taken, because it is what the route means, and
/// still compared where assertions are on: a disagreement is a routing
/// mistake, and a test is the right place to lose over it.
pub fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    debug_assert_eq!(
        realm_id, admin.context.tenant.realm_id,
        "a handler named a realm the token did not mint"
    );
    TenantContext::new(&admin.context.tenant.tenant, &admin.context.tenant.realm_id)
}
