import { adminPath, api } from "@/services/http";
import type {
  EvaluateAnswer,
  EvaluateQuestion,
  PolicyRow,
  ResourceRow,
  ScopeRow,
} from "@/models/authz";

function server(realm: string, clientId: string, leaf: string): string {
  return adminPath(realm, `authz/servers/${encodeURIComponent(clientId)}/${leaf}`);
}

export async function listPolicies(realm: string, clientId: string): Promise<PolicyRow[]> {
  return api<PolicyRow[]>(server(realm, clientId, "policies"));
}

export async function listResources(realm: string, clientId: string): Promise<ResourceRow[]> {
  return api<ResourceRow[]>(server(realm, clientId, "resources"));
}

export async function listAuthzScopes(realm: string, clientId: string): Promise<ScopeRow[]> {
  return api<ScopeRow[]>(server(realm, clientId, "scopes"));
}

export async function evaluate(
  realm: string,
  subject: string,
  question: EvaluateQuestion,
  organization?: string,
): Promise<EvaluateAnswer> {
  return api<EvaluateAnswer>(adminPath(realm, "authz/evaluate"), {
    method: "POST",
    json: { subject, organization: organization || undefined, question },
  });
}
