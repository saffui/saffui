//! From the types of the core to what the administration API says.

use api::RealmView;
use saffui_core::instant::write_instant;
use saffui_core::tenancy::Realm;

pub(super) fn show_realm(realm: &Realm, issuer: String) -> RealmView {
    RealmView {
        id: realm.id.as_uuid().to_string(),
        tenant_id: realm.tenant.as_uuid().to_string(),
        name: realm.name.to_string(),
        issuer,
        enabled: realm.enabled,
        created_at: write_instant(realm.created_at),
    }
}
