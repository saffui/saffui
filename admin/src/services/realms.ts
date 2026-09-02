import { api } from "@/services/http";
import type { RealmBrief } from "@/models/realm";

/// The realms this operator may see, for the switcher and the realm list.
export async function listRealms(): Promise<RealmBrief[]> {
  return api<RealmBrief[]>("/admin/realms");
}
