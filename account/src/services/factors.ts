import { api } from "./http";
import { composeApiPath } from "./place";

/// An authenticator app the person signs in with; no secret is ever shown.
export interface OwnApp {
  id: string;
  kind: string;
  label: string | null;
  created_at: string | null;
  /// Why it has to stay, in the server's words, or null when it may go.
  kept_because: string | null;
}

export interface OwnKey {
  /// The key's identifier, in base64url.
  id: string;
  label: string;
  enrolled_at: string | null;
  last_used_at: string | null;
  kept_because: string | null;
}

/// What the person signs in with, and whether their sign-in may change it now.
export interface OwnFactors {
  password: boolean;
  apps: OwnApp[];
  keys: OwnKey[];
  recovery_codes: number;
  /// Until when, in seconds, the sign-in is recent and strong enough; null when not.
  fresh_until: number | null;
  stronger_sign_in_needed: boolean;
}

export interface ChangedPassword {
  ended_sessions: number;
}

export function listFactors(realm: string): Promise<OwnFactors> {
  return api<OwnFactors>(composeApiPath(realm, "me/credentials"));
}

/// Whether the sign-in may make a sensitive change now: resolves when it may, and
/// throws the step-up the server asks for when it may not.
export function checkRecentSignIn(realm: string): Promise<void> {
  return api<void>(composeApiPath(realm, "me/recent-sign-in"));
}

export function changePassword(
  realm: string,
  current: string,
  replacement: string,
): Promise<ChangedPassword> {
  return api<ChangedPassword>(composeApiPath(realm, "me/password"), {
    method: "PUT",
    json: { current_password: current, new_password: replacement },
  });
}

export function removeApp(realm: string, id: string): Promise<void> {
  return api<void>(composeApiPath(realm, `me/credentials/${encodeURIComponent(id)}`), {
    method: "DELETE",
  });
}

export function removeKey(realm: string, id: string): Promise<void> {
  return api<void>(composeApiPath(realm, `me/keys/${encodeURIComponent(id)}`), {
    method: "DELETE",
  });
}

export function removeRecoveryCodes(realm: string): Promise<void> {
  return api<void>(composeApiPath(realm, "me/recovery-codes"), { method: "DELETE" });
}
