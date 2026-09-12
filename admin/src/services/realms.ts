import { api } from "@/services/http";
import { say } from "@/i18n";
import type { Page } from "@/models/paging";
import type { RealmBrief } from "@/models/realm";

/// The realms this operator may see, for the switcher and the realm list.
/// The server answers a page; the switcher wants the rows.
export async function listRealms(): Promise<RealmBrief[]> {
  const page = await api<Page<RealmBrief>>("/admin/realms");
  return page.items;
}

/// What a birth answers with: the realm, and the one credential that opens
/// it. The password is readable this once and never again, so a caller that
/// drops it has drawn a realm nobody can enter.
export interface RealmBorn extends RealmBrief {
  administrator: { user_name: string; password: string };
}

export interface ImportedRealm {
  realm_id: string;
  administrator?: { user_name: string; password: string };
}

/// Create a realm. The server seeds it ready: scopes, console, key and flow
/// arrive with it, and so does its first administrator, because this
/// session's token was minted by another realm and will never reach the new
/// one.
export async function createRealm(
  name: string,
  displayName: string,
  administrator: { userName: string; email: string },
): Promise<RealmBorn> {
  return api<RealmBorn>("/admin/realms", {
    method: "POST",
    json: {
      name,
      display_name: displayName,
      enabled: true,
      administrator: { user_name: administrator.userName, email: administrator.email },
    },
    subject: say("subject-realm", { realm: name }),
  });
}

export async function importRealm(
  document: unknown,
  options: { as: string; administrator?: string },
): Promise<ImportedRealm> {
  const query = new URLSearchParams({ as: options.as });
  if (options.administrator) query.set("administrator", options.administrator);
  return api<ImportedRealm>(`/admin/realms/import?${query}`, {
    method: "POST",
    json: document,
    subject: say("subject-realm", { realm: options.as }),
  });
}

/// Take a realm away. Only this session's own realm, and only by naming it
/// back: everything keyed under it goes, this account included.
export async function deleteRealm(realm: string): Promise<void> {
  const named = encodeURIComponent(realm);
  await api<void>(`/admin/realms/${named}?confirm=${named}`, {
    method: "DELETE",
    quiet: true,
  });
}
