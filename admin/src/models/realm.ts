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
  registration_allowed: boolean | null;
  register_email_as_username: boolean | null;
  verify_email: boolean | null;
  login_with_email_allowed: boolean | null;
  duplicated_email_allowed: boolean | null;
  edit_user_name_allowed: boolean | null;
  reset_password_allowed: boolean | null;
  remember_me: boolean | null;
  revoke_refresh_token: boolean | null;
  refresh_token_max_reuse: number | null;
  access_token_lifespan: number | null;
  offline_session_lifespan: number | null;
  offline_session_max_lifespan: number;
  max_offline_grants: number;
  action_tokens_lifespan: number | null;
  access_code_lifespan: number | null;
  access_code_lifespan_login: number | null;
  not_before: number | null;
  ssl_enforcement: string | null;
  password_policy: unknown;
  brute_force: unknown;
}

/// The realm theme, as `GET /admin/realms/{realm}/theme` answers it: the 15
/// token names per half, or null when the realm wears the default look.
export type RealmTheme = {
  light?: Record<string, string>;
  dark?: Record<string, string>;
} | null;
