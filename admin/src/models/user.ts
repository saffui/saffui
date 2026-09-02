/// Mirrors `server::api::rest::endpoints::admin::dto::UserBrief`.
export interface UserBrief {
  user_id: string;
  user_name: string;
  enabled: boolean;
  email: string;
  email_verified: boolean;
  given_name: string | null;
  family_name: string | null;
  phone_number: string | null;
  required_actions: string[];
}

/// Mirrors the `GET .../users/{user}/lockout` answer.
export interface Lockout {
  failures: number;
  locked: boolean;
  until: number;
  last_failure?: number | null;
  last_address?: string | null;
}

/// Mirrors `admin::keys::KeyBrief`: one WebAuthn credential.
export interface KeyBrief {
  credential_id: string;
  label: string | null;
  enrolled_at: number | null;
  last_used_at: number | null;
}

/// Mirrors `admin::dto::SessionBrief` and its `GrantBrief`.
export interface GrantBrief {
  client_id: string;
  offline: boolean;
  expiration: number | null;
}
export interface SessionBrief {
  session_id: string;
  auth_method: string | null;
  ip_address: string | null;
  browser: string | null;
  system: string | null;
  mobile: boolean;
  user_agent: string | null;
  started_at: number;
  auth_time: number | null;
  expiration: number | null;
  grants: GrantBrief[];
}

/// One row of the `GET .../users/{user}/consents` answer.
export interface ConsentBrief {
  client_id: string;
  scopes: string[];
  granted_at: number;
}

/// One row of `GET .../users/{user}/roles`.
export interface RoleBrief {
  role_id: string;
  name: string;
  display_name: string;
  description: string;
  client_id: string | null;
}

/// One row of `GET .../users/{user}/groups`.
export interface GroupBrief {
  group_id: string;
  name: string;
  display_name: string;
  description: string;
}

/// One row of `GET .../users/{user}/organizations`.
export interface OrgBrief {
  org_id: string;
  name: string;
  display_name: string;
  enabled: boolean;
}
