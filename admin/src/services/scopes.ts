import { adminPath, api } from "@/services/http";
import type { ClientScope, ProtocolMapper } from "@/models/client";

/// The realm's scope catalogue.
export async function listScopeCatalogue(realm: string): Promise<ClientScope[]> {
  return api<ClientScope[]>(adminPath(realm, "client-scopes"));
}

export async function listScopeMappers(
  realm: string,
  scopeId: string,
): Promise<ProtocolMapper[]> {
  return api<ProtocolMapper[]>(
    adminPath(realm, `client-scopes/${encodeURIComponent(scopeId)}/mappers`),
  );
}
