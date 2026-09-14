import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";

/// What a change of one's own password ended besides the password.
export interface OwnPasswordChanged {
  ended_sessions: number;
}

/// The signed-in administrator's own password, replaced on proof of the
/// current one. The server signs out every other session of the account.
export async function changeOwnPassword(
  realm: string,
  current: string,
  replacement: string,
): Promise<OwnPasswordChanged> {
  return api<OwnPasswordChanged>(adminPath(realm, "account/password"), {
    method: "PUT",
    json: { current_password: current, new_password: replacement },
    subject: say("subject-own-password"),
  });
}

/// An authenticator app the person holds, as the plane shows it: no secret.
export interface OwnApp {
  id: string;
  kind: string;
  label: string | null;
  created_at: string | null;
  /// Why it has to stay, in the server's words, or null when it may go.
  kept_because: string | null;
}

export interface OwnKey {
  id: string;
  label: string;
  enrolled_at: string | null;
  last_used_at: string | null;
  kept_because: string | null;
}

export interface OwnFactors {
  password: boolean;
  apps: OwnApp[];
  keys: OwnKey[];
  recovery_codes: number;
  /// Until when, in epoch seconds, the sign-in behind this page may remove a factor.
  fresh_until: number | null;
  /// Whether that sign-in is recent but weaker than the flow lets this person sign in.
  stronger_sign_in_needed: boolean;
}

export async function listOwnFactors(realm: string): Promise<OwnFactors> {
  return api<OwnFactors>(adminPath(realm, "account/credentials"));
}

export async function removeOwnApp(realm: string, id: string): Promise<void> {
  await api<void>(adminPath(realm, `account/credentials/${encodeURIComponent(id)}`), {
    method: "DELETE",
    subject: say("subject-own-factor"),
  });
}

export async function removeOwnKey(realm: string, id: string): Promise<void> {
  await api<void>(adminPath(realm, `account/keys/${encodeURIComponent(id)}`), {
    method: "DELETE",
    subject: say("subject-own-factor"),
  });
}

export async function removeOwnRecoveryCodes(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "account/recovery-codes"), {
    method: "DELETE",
    subject: say("subject-own-factor"),
  });
}
