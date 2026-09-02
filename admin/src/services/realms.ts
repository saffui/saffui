import { api } from "@/services/http";
import type { Page } from "@/models/paging";
import type { RealmBrief } from "@/models/realm";

/// The realms this operator may see, for the switcher and the realm list.
/// The server answers a page; the switcher wants the rows.
export async function listRealms(): Promise<RealmBrief[]> {
  const page = await api<Page<RealmBrief>>("/admin/realms");
  return page.items;
}

/// Create a realm. The server seeds it ready: scopes, console, key, flow.
export async function createRealm(name: string, displayName: string): Promise<RealmBrief> {
  return api<RealmBrief>("/admin/realms", {
    method: "POST",
    json: { name, display_name: displayName, enabled: true },
  });
}
