import { adminPath, api } from "@/services/http";
import { say } from "@/i18n";
import type { MailBrief, MailWrite } from "@/models/mail";
import type { SmsBrief, SmsWrite } from "@/models/sms";
import type { RealmKeys } from "@/models/keys";
import type { RealmSettings, RealmTheme, RealmUpdate } from "@/models/realm";

export async function getRealmSettings(realm: string): Promise<RealmSettings> {
  return api<RealmSettings>(
    `/admin/realms/${encodeURIComponent(realm)}?briefRepresentation=false`,
  );
}

export async function exportRealm(
  realm: string,
  includeUsers = true,
): Promise<Record<string, unknown>> {
  return api<Record<string, unknown>>(
    `${adminPath(realm, "export")}?include_users=${includeUsers}`,
  );
}

export type ImportCollisionPolicy = "skip" | "overwrite" | "fail";

export interface PartialImportCollision {
  section: string;
  identifier: string;
  reason: string;
}

export interface PartialImportCounts {
  [section: string]: number;
}

export interface PartialImportReport {
  realm_id: string;
  new: PartialImportCounts;
  overwritten: PartialImportCounts;
  skipped: PartialImportCounts;
  collisions: PartialImportCollision[];
  collision_count: number;
  collisions_truncated: boolean;
}

export async function previewPartialImport(
  realm: string,
  document: Record<string, unknown>,
  collision: ImportCollisionPolicy,
): Promise<PartialImportReport> {
  return api<PartialImportReport>(adminPath(realm, "import/preview"), {
    method: "POST",
    json: { document, collision },
    subject: say("settings-partial-import"),
  });
}

export async function importPartialRealm(
  realm: string,
  document: Record<string, unknown>,
  collision: ImportCollisionPolicy,
): Promise<PartialImportReport> {
  return api<PartialImportReport>(adminPath(realm, "import"), {
    method: "POST",
    json: { document, collision },
    subject: say("settings-partial-import"),
  });
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

export async function disableRealmKey(realm: string, kid: string): Promise<void> {
  await api<void>(`${adminPath(realm, "keys")}/${encodeURIComponent(kid)}`, {
    method: "DELETE",
    subject: say("subject-key-disable"),
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
/// What this realm spent on texts today, and what its brakes held back.
export async function readSmsToday(realm: string) {
  return api<import("@/models/sms").SmsToday>(adminPath(realm, "sms/today"));
}

/// Hold the relay in conversation and report what it said. Sends nothing.
export async function lookAtRelay(realm: string) {
  return api<import("@/models/mail").RelayReport>(adminPath(realm, "mail/probe"));
}

/// What this realm tried to send lately and could not.
export async function readRelayRefusals(realm: string) {
  const told = await api<{ items: import("@/models/mail").MailRefusal[]; hours: number }>(
    adminPath(realm, "mail/refusals"),
  );
  return told;
}

export async function listFeatures() {
  return api<import("@/models/feature").FeatureBrief[]>("/admin/features");
}

/// The same registry, said for one realm.
export async function listRealmFeatures(realm: string) {
  const told = await api<{ items: import("@/models/feature").RealmFeature[] }>(
    adminPath(realm, "features"),
  );
  return told.items;
}

/// Say what this realm wants of one capability. `null` returns it to whatever
/// the process runs, which is not the same as asking for it to be off.
export async function keepFeatureWish(realm: string, slug: string, enabled: boolean | null) {
  await api<void>(adminPath(realm, `features/${encodeURIComponent(slug)}`), {
    method: "PUT",
    json: { enabled },
    subject: say("subject-feature", { slug }),
  });
}

/// One page of the sign-in log, newest first.
export async function listSignInEvents(realm: string, first: number, max: number) {
  return api<import("@/models/paging").Page<import("@/models/events").SignInEvent>>(
    adminPath(realm, `sign-in-events?first=${first}&max=${max}`),
  );
}

/// Drive the relay end to end: connect, TLS, auth, one real mail to the
/// given address. Green means the settings on screen actually carry mail.
export async function sendTestMail(realm: string, to: string): Promise<void> {
  await api<void>(adminPath(realm, "mail/test"), {
    method: "POST",
    json: { to },
    subject: say("mail-test-subject"),
  });
}

/// Mirrors the `GET .../page-keys` answer: every hosted-page key with its
/// built value per tongue.
export interface PageKey {
  name: string;
  en: string;
  fr: string;
}

export async function listPageKeys(realm: string): Promise<{ keys: PageKey[] }> {
  return api<{ keys: PageKey[] }>(adminPath(realm, "page-keys"));
}

export async function getSms(realm: string): Promise<SmsBrief> {
  return api<SmsBrief>(adminPath(realm, "sms"));
}

export async function writeSms(realm: string, asked: SmsWrite): Promise<void> {
  await api<unknown>(adminPath(realm, "sms"), {
    method: "PUT",
    json: asked,
    subject: say("settings-group-phone"),
  });
}

export async function forgetSms(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "sms"), {
    method: "DELETE",
    subject: say("settings-group-phone"),
  });
}

/// Drive the gateway end to end: one real text to the given number. Green
/// means the settings on screen actually carry texts.
export async function sendTestSms(realm: string, to: string): Promise<void> {
  await api<void>(adminPath(realm, "sms/test"), {
    method: "POST",
    json: { to },
    subject: say("sms-test-subject"),
  });
}

export interface UssdBrief {
  has_secret: boolean;
}

export async function getUssd(realm: string): Promise<UssdBrief> {
  return api<UssdBrief>(adminPath(realm, "ussd"));
}

export async function writeUssd(realm: string, secret: string): Promise<void> {
  await api<unknown>(adminPath(realm, "ussd"), {
    method: "PUT",
    json: { secret },
    subject: say("ussd-title"),
  });
}

export async function forgetUssd(realm: string): Promise<void> {
  await api<void>(adminPath(realm, "ussd"), {
    method: "DELETE",
    subject: say("ussd-title"),
  });
}
