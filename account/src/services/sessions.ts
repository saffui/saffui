import { api } from "./http";
import { composeApiPath } from "./place";

/// What one application holds from a login.
export interface HeldGrant {
  client_id: string;
  name: string;
  /// Whether it may keep reaching the account while the person is away.
  offline: boolean;
  expiration: number | null;
}

/// One of the person's logins, as the account API reads it for them.
export interface HeldLogin {
  session_id: string;
  /// Whether this page rides the login: the browser it runs in.
  current: boolean;
  /// False for a login that ended while an offline grant it gave outlives it.
  open: boolean;
  auth_method: string | null;
  /// The provider a brokered login came through.
  provider: string | null;
  ip_address: string | null;
  browser: string | null;
  system: string | null;
  mobile: boolean;
  started_at: number;
  auth_time: number | null;
  expiration: number | null;
  grants: HeldGrant[];
}

export interface EndedLogins {
  ended_sessions: number;
}

export function listLogins(realm: string): Promise<HeldLogin[]> {
  return api<HeldLogin[]>(composeApiPath(realm, "me/sessions"));
}

export function endLogin(realm: string, sessionId: string): Promise<void> {
  return api<void>(composeApiPath(realm, `me/sessions/${encodeURIComponent(sessionId)}`), {
    method: "DELETE",
  });
}

export function endOtherLogins(realm: string): Promise<EndedLogins> {
  return api<EndedLogins>(composeApiPath(realm, "me/sessions"), { method: "DELETE" });
}

export function revokeGrant(realm: string, sessionId: string, clientId: string): Promise<void> {
  const leaf = `me/sessions/${encodeURIComponent(sessionId)}/grants/${encodeURIComponent(clientId)}`;
  return api<void>(composeApiPath(realm, leaf), { method: "DELETE" });
}
