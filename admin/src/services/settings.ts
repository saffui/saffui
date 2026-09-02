import { adminPath, api } from "@/services/http";
import { say } from "@/i18n";
import type { MailBrief, MailWrite } from "@/models/mail";
import type { RealmKeys } from "@/models/keys";
import type { RealmSettings, RealmTheme, RealmUpdate } from "@/models/realm";

export async function getRealmSettings(realm: string): Promise<RealmSettings> {
  return api<RealmSettings>(
    `/admin/realms/${encodeURIComponent(realm)}?briefRepresentation=false`,
  );
}

/// Rewrite the mentioned switches; the server leaves absent ones alone and
/// answers the whole settings document back.
export async function reshapeRealm(
  realm: string,
  changes: RealmUpdate,
  subject: string,
): Promise<RealmSettings> {
  return api<RealmSettings>(`/admin/realms/${encodeURIComponent(realm)}`, {
    method: "PUT",
    json: changes,
    subject,
  });
}

export async function getMail(realm: string): Promise<MailBrief> {
  return api<MailBrief>(adminPath(realm, "mail"));
}

export async function writeMail(realm: string, asked: MailWrite): Promise<void> {
  await api<unknown>(adminPath(realm, "mail"), {
    method: "PUT",
    json: asked,
    subject: say("settings-group-email"),
  });
}

export async function forgetMail(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "mail"), {
    method: "DELETE",
    subject: say("settings-group-email"),
  });
}

export async function getRealmKeys(realm: string): Promise<RealmKeys> {
  return api<RealmKeys>(adminPath(realm, "keys"));
}

/// Mint a successor for the named algorithm: the active key goes passive
/// and keeps verifying, the fresh one signs.
export async function rotateKey(realm: string, algorithm: string): Promise<void> {
  await api<unknown>(adminPath(realm, "keys"), {
    method: "POST",
    json: { algorithm },
    subject: say("subject-key", { algorithm }),
  });
}

export async function getRealmTheme(realm: string): Promise<RealmTheme> {
  return api<RealmTheme>(adminPath(realm, "theme"));
}

export async function writeRealmTheme(
  realm: string,
  theme: NonNullable<RealmTheme>,
): Promise<void> {
  await api<void>(adminPath(realm, "theme"), {
    method: "PUT",
    json: theme,
    subject: say("nav-theme"),
  });
}

export async function forgetRealmTheme(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "theme"), {
    method: "DELETE",
    subject: say("nav-theme"),
  });
}

/// Draw the secret protected registration is opened with; answered once.
export async function rotateRegistrationSecret(realm: string): Promise<string> {
  const drawn = await api<{ registration_secret: string }>(
    adminPath(realm, "registration-secret"),
    { method: "POST", quiet: true },
  );
  return drawn.registration_secret;
}

export async function forgetRegistrationSecret(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "registration-secret"), {
    method: "DELETE",
    subject: say("settings-registration-secret"),
  });
}

/// What this build carries and what is on. Read-only by nature: the gating
/// is compile-time.
export async function listFeatures() {
  return api<import("@/models/feature").FeatureBrief[]>("/admin/features");
}

/// One page of the sign-in log, newest first.
export async function listSignInEvents(realm: string, first: number, max: number) {
  return api<import("@/models/paging").Page<import("@/models/events").SignInEvent>>(
    adminPath(realm, `sign-in-events?first=${first}&max=${max}&count=true`),
  );
}
