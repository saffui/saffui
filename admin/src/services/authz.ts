import { say } from "@/i18n";
import { adminPath, api } from "@/services/http";
import type {
  EvaluateAnswer,
  EvaluateQuestion,
  DecisionRow,
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

/// What the engine decided lately, newest first.
export async function listDecisions(realm: string, limit = 100): Promise<DecisionRow[]> {
  return api<DecisionRow[]>(adminPath(realm, `authz/decisions?limit=${limit}`));
}

/// Only the decisions where what was reported and what was computed parted
/// company: what a permissive server let through, and would not have.
export async function listDisagreements(realm: string, limit = 100): Promise<DecisionRow[]> {
  return api<DecisionRow[]>(adminPath(realm, `authz/decisions/disagreements?limit=${limit}`));
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

export async function createAuthzScope(
  realm: string,
  clientId: string,
  body: Record<string, unknown>,
) {
  await api<unknown>(server(realm, clientId, "scopes"), {
    method: "POST",
    json: body,
    subject: say("subject-scope", { scope: String(body.name ?? "") }),
  });
}

/// Rework one in place. The identity never moves: a policy binds a resource
/// or a scope by identity, so a rename that made a new row would break the
/// binding while looking on screen like an edit.
async function reworked(
  realm: string,
  clientId: string,
  leaf: string,
  id: string,
  body: Record<string, unknown>,
  subject: string,
) {
  await api<unknown>(`${server(realm, clientId, leaf)}/${encodeURIComponent(id)}`, {
    method: "PUT",
    json: body,
    subject,
  });
}

export async function reworkPolicy(
  realm: string,
  clientId: string,
  policyId: string,
  body: Record<string, unknown>,
) {
  await reworked(realm, clientId, "policies", policyId, body,
    say("subject-policy", { policy: String(body.name ?? "") }));
}

export async function reworkResource(
  realm: string,
  clientId: string,
  resourceId: string,
  body: Record<string, unknown>,
) {
  await reworked(realm, clientId, "resources", resourceId, body,
    say("subject-resource", { resource: String(body.name ?? "") }));
}

export async function reworkAuthzScope(
  realm: string,
  clientId: string,
  scopeId: string,
  body: Record<string, unknown>,
) {
  await reworked(realm, clientId, "scopes", scopeId, body,
    say("subject-scope", { scope: String(body.name ?? "") }));
}

/// Take one away. The bindings that named it go with it, which is why the
/// console asks first wherever it offers this.
async function erased(
  realm: string,
  clientId: string,
  leaf: string,
  id: string,
  subject: string,
) {
  await api<void>(`${server(realm, clientId, leaf)}/${encodeURIComponent(id)}`, {
    method: "DELETE",
    subject,
  });
}

export async function erasePolicy(realm: string, clientId: string, policyId: string, named: string) {
  await erased(realm, clientId, "policies", policyId, say("subject-policy", { policy: named }));
}

export async function eraseResource(
  realm: string,
  clientId: string,
  resourceId: string,
  named: string,
) {
  await erased(realm, clientId, "resources", resourceId, say("subject-resource", { resource: named }));
}

export async function eraseAuthzScope(
  realm: string,
  clientId: string,
  scopeId: string,
  named: string,
) {
  await erased(realm, clientId, "scopes", scopeId, say("subject-scope", { scope: named }));
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
