import { adminPath, api } from "@/services/http";
import type { MailBrief, MailWrite } from "@/models/mail";
import type { RealmKeys } from "@/models/keys";
import type { RealmSettings, RealmTheme } from "@/models/realm";

export async function getRealmSettings(realm: string): Promise<RealmSettings> {
  return api<RealmSettings>(`/admin/realms/${encodeURIComponent(realm)}`);
}

export async function getMail(realm: string): Promise<MailBrief> {
  return api<MailBrief>(adminPath(realm, "mail"));
}

export async function writeMail(realm: string, asked: MailWrite): Promise<void> {
  await api<unknown>(adminPath(realm, "mail"), { method: "PUT", json: asked });
}

export async function forgetMail(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "mail"), { method: "DELETE" });
}

export async function getRealmKeys(realm: string): Promise<RealmKeys> {
  return api<RealmKeys>(adminPath(realm, "keys"));
}

/// Mint a successor for the named algorithm: the active key goes passive
/// and keeps verifying, the fresh one signs.
export async function rotateKey(realm: string, algorithm: string): Promise<void> {
  await api<unknown>(adminPath(realm, "keys"), { method: "POST", json: { algorithm } });
}

export async function getRealmTheme(realm: string): Promise<RealmTheme> {
  return api<RealmTheme>(adminPath(realm, "theme"));
}

export async function writeRealmTheme(
  realm: string,
  theme: NonNullable<RealmTheme>,
): Promise<void> {
  await api<void>(adminPath(realm, "theme"), { method: "PUT", json: theme });
}

export async function forgetRealmTheme(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "theme"), { method: "DELETE" });
}
