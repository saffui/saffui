import { adminPath, api } from "@/services/http";
import type {
  DeliveryProof,
  DirectoryRow,
  DirectoryImportReport,
  DirectoryMutation,
  IdpMutation,
  IdpMapperMutation,
  IdpMapperRow,
  IdpRow,
  IgaGrant,
  IgaRule,
} from "@/models/federation";

export async function listIdps(realm: string): Promise<IdpRow[]> {
  return api<IdpRow[]>(adminPath(realm, "identity-providers"));
}

export async function createIdp(realm: string, body: IdpMutation): Promise<IdpRow> {
  return api<IdpRow>(adminPath(realm, "identity-providers"), {
    method: "POST",
    json: body,
    subject: body.provider_id,
  });
}

export async function updateIdp(realm: string, alias: string, body: IdpMutation): Promise<IdpRow> {
  return api<IdpRow>(adminPath(realm, `identity-providers/${encodeURIComponent(alias)}`), {
    method: "PUT",
    json: body,
    subject: alias,
  });
}

export async function deleteIdp(realm: string, alias: string): Promise<void> {
  return api<void>(adminPath(realm, `identity-providers/${encodeURIComponent(alias)}`), {
    method: "DELETE",
    subject: alias,
  });
}

function mapperPath(realm: string, alias: string, mapperId?: string): string {
  const base = `identity-providers/${encodeURIComponent(alias)}/mappers`;
  return adminPath(realm, mapperId ? `${base}/${encodeURIComponent(mapperId)}` : base);
}

export async function listIdpMappers(realm: string, alias: string): Promise<IdpMapperRow[]> {
  return api<IdpMapperRow[]>(mapperPath(realm, alias));
}

export async function createIdpMapper(
  realm: string,
  alias: string,
  body: IdpMapperMutation,
): Promise<IdpMapperRow> {
  return api<IdpMapperRow>(mapperPath(realm, alias), {
    method: "POST",
    json: body,
    subject: body.name,
  });
}

export async function updateIdpMapper(
  realm: string,
  alias: string,
  mapperId: string,
  body: IdpMapperMutation,
): Promise<IdpMapperRow> {
  return api<IdpMapperRow>(mapperPath(realm, alias, mapperId), {
    method: "PUT",
    json: body,
    subject: body.name,
  });
}

export async function deleteIdpMapper(
  realm: string,
  alias: string,
  mapperId: string,
): Promise<void> {
  return api<void>(mapperPath(realm, alias, mapperId), {
    method: "DELETE",
    subject: mapperId,
  });
}

/// Ask the server to exercise one connector's pipe, now, and answer what
/// the far side said. Quiet: the proof itself is the message.
export async function proveDelivery(realm: string, alias: string): Promise<DeliveryProof> {
  return api<DeliveryProof>(
    adminPath(realm, `identity-providers/${encodeURIComponent(alias)}/prove`),
    { method: "POST", quiet: true },
  );
}

export async function listDirectories(realm: string): Promise<DirectoryRow[]> {
  return api<DirectoryRow[]>(adminPath(realm, "federations"));
}

function directoryPath(realm: string, alias: string, leaf = ""): string {
  const base = `federations/${encodeURIComponent(alias)}`;
  return adminPath(realm, leaf ? `${base}/${leaf}` : base);
}

export async function putDirectory(
  realm: string,
  alias: string,
  body: DirectoryMutation,
): Promise<DirectoryRow> {
  return api<DirectoryRow>(directoryPath(realm, alias), {
    method: "PUT",
    json: body,
    subject: alias,
  });
}

export async function deleteDirectory(realm: string, alias: string): Promise<void> {
  return api<void>(directoryPath(realm, alias), { method: "DELETE", subject: alias });
}

export async function importDirectory(
  realm: string,
  alias: string,
): Promise<DirectoryImportReport> {
  return api<DirectoryImportReport>(directoryPath(realm, alias, "import"), {
    method: "POST",
    subject: alias,
  });
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
