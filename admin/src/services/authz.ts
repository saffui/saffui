import { say } from "@/i18n";
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
    // A question, not a write: the verdict panel is the answer.
    quiet: true,
  });
}

/// Protect a client: give it a decision point and a strategy.
export async function protectClient(
  realm: string,
  clientId: string,
  enforcement: string,
  strategy: string,
) {
  await api<unknown>(adminPath(realm, `authz/servers/${encodeURIComponent(clientId)}`), {
    method: "POST",
    json: { enforcement_mode: enforcement, decision_strategy: strategy },
    subject: say("subject-server", { client: clientId }),
  });
}

export async function createPolicy(
  realm: string,
  clientId: string,
  body: Record<string, unknown>,
) {
  await api<unknown>(adminPath(realm, `authz/servers/${encodeURIComponent(clientId)}/policies`), {
    method: "POST",
    json: body,
    subject: say("subject-policy", { policy: String(body.name ?? "") }),
  });
}

export async function createResource(
  realm: string,
  clientId: string,
  body: Record<string, unknown>,
) {
  await api<unknown>(adminPath(realm, `authz/servers/${encodeURIComponent(clientId)}/resources`), {
    method: "POST",
    json: body,
    subject: say("subject-resource", { resource: String(body.name ?? "") }),
  });
}

/// One relation tuple into the graph. There is no listing route yet: the
/// graph is written here and read by the engine.
export async function writeRelation(
  realm: string,
  edge: {
    subject_type: string;
    subject_id: string;
    relation: string;
    object_type: string;
    object_id: string;
  },
) {
  await api<unknown>(adminPath(realm, "rebac/relations"), {
    method: "POST",
    json: edge,
    subject: say("subject-relation", { relation: edge.relation }),
  });
}

export async function eraseRelation(
  realm: string,
  edge: {
    subject_type: string;
    subject_id: string;
    relation: string;
    object_type: string;
    object_id: string;
  },
) {
  await api<unknown>(adminPath(realm, "rebac/relations"), {
    method: "DELETE",
    json: edge,
    subject: say("subject-relation", { relation: edge.relation }),
  });
}
