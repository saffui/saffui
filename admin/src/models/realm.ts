// Hand-written mirrors of the server's serde models, one file per domain,
// grown slice by slice with the pages that read them. Each type names the
// Rust struct it mirrors, so drift has an address; a generated replacement
// (ts-rs or OpenAPI) is a later slice with a CI guard.

/// Mirrors `server::api::rest::endpoints::admin::dto::RealmBrief`.
export interface RealmBrief {
  realm_id: string;
  name: string;
  display_name: string;
  enabled: boolean;
}

/// The slice of `models::entities::realm::RealmModel` the console reads so
/// far; fields join this mirror as pages need them.
export interface RealmSettings {
  realm_id: string;
  name: string;
  display_name: string;
  enabled: boolean;
  client_registration: "disabled" | "open" | "protected";
  registration_bounds: {
    max_clients: number | null;
    requires_consent: boolean;
    trusted_hosts: string[];
  };
  require_pushed_authorization_requests: boolean;
}
