import { adminPath, api } from "@/services/http";

export interface SpnegoRow {
  realm_id: string;
  enabled: boolean | null;
  configs: Record<string, { Str?: string } | string> | null;
}

export interface SpnegoMutation {
  enabled: boolean;
  configs: { service_principal: { Str: string } };
}

const path = (realm: string) => adminPath(realm, "spnego");

export function servicePrincipal(row: SpnegoRow): string {
  const value = row.configs?.service_principal;
  return typeof value === "string" ? value : value?.Str ?? "";
}

export async function getSpnego(realm: string): Promise<SpnegoRow> {
  return api<SpnegoRow>(path(realm));
}

export async function putSpnego(realm: string, body: SpnegoMutation): Promise<SpnegoRow> {
  return api<SpnegoRow>(path(realm), { method: "PUT", json: body, subject: "SPNEGO" });
}

export async function deleteSpnego(realm: string): Promise<void> {
  return api<void>(path(realm), { method: "DELETE", subject: "SPNEGO" });
}
