import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";
import type { Page } from "@/models/paging";
import type { ClientBrief, ClientScope, ProtocolMapper } from "@/models/client";

export async function listClients(
  realm: string,
  first: number,
  max: number,
): Promise<Page<ClientBrief>> {
  return api<Page<ClientBrief>>(
    `${adminPath(realm, "clients")}?first=${first}&max=${max}`,
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

/// Mirrors the server's ClientSpec.
export interface ClientSpec {
  client_id?: string;
  name?: string;
  confidential?: boolean;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
}

/// Creation answers the client, and for a confidential one the secret rides
/// along exactly once as client_secret.
export async function createClient(realm: string, spec: ClientSpec) {
  return api<ClientBrief & { client_secret?: string }>(adminPath(realm, "clients"), {
    method: "POST",
    json: spec,
    subject: say("subject-client", { client: spec.client_id ?? spec.name ?? "" }),
  });
}

export async function updateClient(
  realm: string,
  clientId: string,
  spec: ClientSpec,
): Promise<void> {
  await api<unknown>(adminPath(realm, `clients/${encodeURIComponent(clientId)}`), {
    method: "PUT",
    json: spec,
    subject: say("subject-client", { client: clientId }),
  });
}

export async function deleteClient(realm: string, clientId: string): Promise<void> {
  await api<void>(adminPath(realm, `clients/${encodeURIComponent(clientId)}`), {
    method: "DELETE",
    quiet: true,
  });
}

/// Draw a new secret, answered exactly once.
export async function rotateClientSecret(realm: string, clientId: string): Promise<string> {
  const drawn = await api<{ client_secret: string }>(
    adminPath(realm, `clients/${encodeURIComponent(clientId)}/secret`),
    { method: "POST", quiet: true },
  );
  return drawn.client_secret;
}

/// Attach a scope; required is granted without asking, optional when asked.
export async function attachScope(
  realm: string,
  clientId: string,
  scope: string,
  optional: boolean,
) {
  await api<unknown>(
    adminPath(realm, `clients/${encodeURIComponent(clientId)}/scopes/${encodeURIComponent(scope)}`),
    {
      method: "PUT",
      json: { optional },
      subject: say("subject-scope-attach", { scope, client: clientId }),
    },
  );
}

export async function detachScope(realm: string, clientId: string, scope: string) {
  await api<unknown>(
    adminPath(realm, `clients/${encodeURIComponent(clientId)}/scopes/${encodeURIComponent(scope)}`),
    { method: "DELETE", subject: say("subject-scope-attach", { scope, client: clientId }) },
  );
}

/// One previewed claim: who would write it, and into which token.
export interface PreviewedClaim {
  claim: string;
  value: unknown;
  origin: string;
  lands_in: "access" | "identity" | "both";
}

export async function previewToken(
  realm: string,
  body: { user_id: string; client_id: string; scope?: string },
): Promise<{ claims: PreviewedClaim[]; scope: string }> {
  return api<{ claims: PreviewedClaim[]; scope: string }>(adminPath(realm, "preview-token"), {
    method: "POST",
    json: body,
    quiet: true,
  });
}
