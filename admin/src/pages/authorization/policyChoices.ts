import type { ClientScope } from "@/models/client";

export interface PolicyChoice {
  id: string;
  label: string;
  held: boolean;
}

/// A client-scope policy holds scope identifiers, which the store checks
/// against the catalogue. The name is only what the operator reads.
export function clientScopeChoices(scopes: ClientScope[], held: Set<string>): PolicyChoice[] {
  return scopes.map((scope) => ({
    id: scope.client_scope_id,
    label: scope.name,
    held: held.has(scope.client_scope_id),
  }));
}
