import { listClients } from "@/services/clients";
import type { ClientBrief } from "@/models/client";

export async function authorizationClients(realm: string): Promise<ClientBrief[]> {
  const clients: ClientBrief[] = [];
  const size = 100;
  for (;;) {
    const page = await listClients(realm, clients.length, size);
    clients.push(...page.items);
    if (page.items.length < size) return clients;
  }
}

export function selectedClient(clients: ClientBrief[], requested: string): string {
  if (clients.some((client) => client.client_id === requested)) return requested;
  return clients.length === 1 ? clients[0].client_id : "";
}
