import { adminPath, api } from "@/services/http";
import type { Page } from "@/models/paging";
import type { ClientBrief, ClientScope, ProtocolMapper } from "@/models/client";

export async function listClients(
  realm: string,
  first: number,
  max: number,
): Promise<Page<ClientBrief>> {
  return api<Page<ClientBrief>>(
    `${adminPath(realm, "clients")}?first=${first}&max=${max}&count=true`,
  );
}

export async function getClient(realm: string, clientId: string): Promise<ClientBrief> {
  return api<ClientBrief>(adminPath(realm, `clients/${encodeURIComponent(clientId)}`));
}

/// The scopes attached to this client, each saying whether it is offered
/// (optional) or granted without being asked for (required).
export async function listAttachedScopes(
  realm: string,
  clientId: string,
): Promise<ClientScope[]> {
  return api<ClientScope[]>(adminPath(realm, `clients/${encodeURIComponent(clientId)}/scopes`));
}

export async function listClientMappers(
  realm: string,
  clientId: string,
): Promise<ProtocolMapper[]> {
  return api<ProtocolMapper[]>(
    adminPath(realm, `clients/${encodeURIComponent(clientId)}/mappers`),
  );
}
