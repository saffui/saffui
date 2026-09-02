import { say } from "@/i18n";
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

export async function createScope(
  realm: string,
  spec: { name: string; description?: string; default_scope?: boolean },
) {
  return api<ClientScope>(adminPath(realm, "client-scopes"), {
    method: "POST",
    json: spec,
    subject: say("subject-scope", { scope: spec.name }),
  });
}

export async function updateScope(
  realm: string,
  scopeId: string,
  spec: { name: string; description?: string; default_scope?: boolean },
): Promise<void> {
  await api<unknown>(adminPath(realm, `client-scopes/${encodeURIComponent(scopeId)}`), {
    method: "PUT",
    json: spec,
    subject: say("subject-scope", { scope: spec.name }),
  });
}

export async function deleteScope(realm: string, scopeId: string): Promise<void> {
  await api<void>(adminPath(realm, `client-scopes/${encodeURIComponent(scopeId)}`), {
    method: "DELETE",
    quiet: true,
  });
}

export async function attachMapperToScope(
  realm: string,
  scopeId: string,
  mapperId: string,
): Promise<void> {
  await api<unknown>(
    adminPath(
      realm,
      `client-scopes/${encodeURIComponent(scopeId)}/mappers/${encodeURIComponent(mapperId)}`,
    ),
    { method: "PUT", subject: say("subject-mapper", { mapper: mapperId }) },
  );
}

export async function detachMapperFromScope(
  realm: string,
  scopeId: string,
  mapperId: string,
): Promise<void> {
  await api<unknown>(
    adminPath(
      realm,
      `client-scopes/${encodeURIComponent(scopeId)}/mappers/${encodeURIComponent(mapperId)}`,
    ),
    { method: "DELETE", subject: say("subject-mapper", { mapper: mapperId }) },
  );
}

export async function listRealmMappers(realm: string) {
  return api<import("@/models/client").ProtocolMapper[]>(adminPath(realm, "protocol-mappers"));
}
