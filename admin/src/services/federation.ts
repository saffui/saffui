import { adminPath, api } from "@/services/http";
import type { DirectoryRow, IdpRow, IgaGrant, IgaRule } from "@/models/federation";

export async function listIdps(realm: string): Promise<IdpRow[]> {
  return api<IdpRow[]>(adminPath(realm, "identity-providers"));
}

export async function listDirectories(realm: string): Promise<DirectoryRow[]> {
  return api<DirectoryRow[]>(adminPath(realm, "federations"));
}

export async function listIgaRules(realm: string): Promise<IgaRule[]> {
  return api<IgaRule[]>(adminPath(realm, "iga/rules"));
}

export async function listIgaGrants(realm: string, userId: string): Promise<IgaGrant[]> {
  return api<IgaGrant[]>(adminPath(realm, `iga/grants/${encodeURIComponent(userId)}`));
}

/// The kind a provider row plays, read off its bag; empty means a plain
/// brokering provider.
export function kindOf(row: { configs: IdpRow["configs"] }): string {
  const held = row.configs?.["kind"];
  if (held === undefined) return "";
  if (typeof held === "string") return held;
  return held.Str ?? "";
}
