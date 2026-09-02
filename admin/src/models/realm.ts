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
  refresh_token_lifespan: number | null;
  session_max_lifespan: number;
  offline_session_lifespan: number | null;
  offline_session_max_lifespan: number;
  max_offline_grants: number;
  action_tokens_lifespan: number | null;
  access_code_lifespan: number | null;
  access_code_lifespan_login: number | null;
  access_code_lifespan_user_action: number | null;
  not_before: number | null;
  acr_loa_map: Record<string, number> | null;
  attributes: Record<string, unknown> | null;
  events_enabled: boolean | null;
  admin_events_enabled: boolean | null;
  otp_policy: OtpPolicy | null;
  webauthn_policy: WebauthnPolicy | null;
  mail_templates: Record<string, Record<string, MailTemplate>> | null;
  device_code_lifespan: number | null;
  device_poll_interval: number | null;
  browser_flow: string | null;
  supported_locales: string[] | null;
  default_locale: string | null;
  ssl_enforcement: string | null;
  password_policy: PasswordPolicy | null;
  brute_force: BruteForce;
}

/// Mirrors `models::entities::realm::PasswordPolicy`. The hashing block is
/// required by the server's deserializer, so a write always echoes the held
/// one; OWASP_HASHING mirrors the server's own default for a realm that has
/// no policy yet.
export interface PasswordPolicy {
  min_length: number | null;
  max_length: number | null;
  min_digits: number | null;
  min_upper_case: number | null;
  min_lower_case: number | null;
  min_special_chars: number | null;
  not_email: boolean | null;
  not_username: boolean | null;
  not_birthdate: boolean | null;
  blacklisted: string[] | null;
  regex_pattern: string | null;
  expires_after_days: number | null;
  history_look_back: number | null;
  hashing: { m_cost: number; t_cost: number; p_cost: number; output_len: number };
}

/// Mirrors `models::entities::realm::MailTemplate`.
export interface MailTemplate {
  subject: string;
  body: string;
}

/// Mirrors `models::entities::realm::WebauthnPolicy`. Deliberately small:
/// the verifier fixes user verification and attestation, the passkey
/// contract; the realm shapes only its shown name and the subdomain reach.
export interface WebauthnPolicy {
  rp_name: string | null;
  allow_subdomains: boolean;
}

/// Mirrors `models::entities::realm::OtpPolicy`; defaults mirror the
/// server's own (6 digits, 30 s, SHA1, 1 step).
export interface OtpPolicy {
  digits: number;
  period: number;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  window: number;
}
export const OTP_DEFAULTS: OtpPolicy = { digits: 6, period: 30, algorithm: "SHA1", window: 1 };

/// `crypto::provider::Argon2Params::default()`: the OWASP 2024 baseline.
export const OWASP_HASHING = { m_cost: 19456, t_cost: 2, p_cost: 1, output_len: 32 };

/// Mirrors `models::entities::realm::BruteForce`.
export interface BruteForce {
  protected: boolean;
  max_failures: number;
  lockout_seconds: number;
  max_lockout_seconds: number;
  reset_seconds: number;
}

/// Mirrors `models::entities::realm::RealmUpdateModel`: every field optional,
/// absent means unchanged, so a save sends only the group it edited.
export interface RealmUpdate {
  display_name?: string;
  enabled?: boolean;
  registration_allowed?: boolean;
  register_email_as_username?: boolean;
  verify_email?: boolean;
  login_with_email_allowed?: boolean;
  duplicated_email_allowed?: boolean;
  edit_user_name_allowed?: boolean;
  reset_password_allowed?: boolean;
  remember_me?: boolean;
  ssl_enforcement?: string;
  password_policy?: PasswordPolicy;
  revoke_refresh_token?: boolean;
  refresh_token_max_reuse?: number;
  access_token_lifespan?: number;
  refresh_token_lifespan?: number;
  session_max_lifespan?: number;
  offline_session_lifespan?: number;
  offline_session_max_lifespan?: number;
  max_offline_grants?: number;
  action_tokens_lifespan?: number;
  access_code_lifespan?: number;
  access_code_lifespan_login?: number;
  access_code_lifespan_user_action?: number;
  not_before?: number;
  acr_loa_map?: Record<string, number>;
  attributes?: Record<string, string>;
  events_enabled?: boolean;
  admin_events_enabled?: boolean;
  otp_policy?: OtpPolicy;
  webauthn_policy?: WebauthnPolicy;
  mail_templates?: Record<string, Record<string, MailTemplate>>;
  device_code_lifespan?: number;
  device_poll_interval?: number;
  browser_flow?: string;
  supported_locales?: string[];
  default_locale?: string;
  client_registration?: "disabled" | "open" | "protected";
  brute_force?: BruteForce;
  registration_bounds?: {
    max_clients: number | null;
    requires_consent: boolean;
    trusted_hosts: string[];
  };
  require_pushed_authorization_requests?: boolean;
}

/// The realm theme, as `GET /admin/realms/{realm}/theme` answers it: the 15
/// token names per half, or null when the realm wears the default look.
export type RealmTheme = {
  light?: Record<string, string>;
  dark?: Record<string, string>;
} | null;
