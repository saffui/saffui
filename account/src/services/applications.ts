import { api } from "./http";
import { composeApiPath } from "./place";

/// What the person agreed an application may have.
export interface AgreedConsent {
  scopes: string[];
  granted_at: string;
  /// Whether the application asks for agreement before it signs the person in, so a
  /// withdrawn consent is asked for again.
  asks_consent: boolean;
}

/// What an application holds from the person's logins, gathered across them.
export interface HeldAccess {
  logins: number;
  offline: boolean;
  /// When the last of its grants runs out, in seconds; null when one never does.
  expiration: number | null;
}

/// An application that holds something of the person.
export interface HeldApplication {
  client_id: string;
  name: string;
  /// Where the person may go to reach it, when the realm gave a safe address.
  home: string | null;
  consent: AgreedConsent | null;
  access: HeldAccess | null;
}

export interface EndedGrants {
  ended_grants: number;
}

export function listApplications(realm: string): Promise<HeldApplication[]> {
  return api<HeldApplication[]>(composeApiPath(realm, "me/applications"));
}

export function withdrawConsent(realm: string, clientId: string): Promise<void> {
  const leaf = `me/applications/${encodeURIComponent(clientId)}/consent`;
  return api<void>(composeApiPath(realm, leaf), { method: "DELETE" });
}

export function takeBackAccess(realm: string, clientId: string): Promise<EndedGrants> {
  const leaf = `me/applications/${encodeURIComponent(clientId)}/access`;
  return api<EndedGrants>(composeApiPath(realm, leaf), { method: "DELETE" });
}
