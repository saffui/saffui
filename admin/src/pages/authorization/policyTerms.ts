import type { PolicyRow } from "@/models/authz";

export interface PolicyDraft {
  name: string;
  policy_type: string;
  description: string;
  /// Held as the policy was opened: the drawer has no box for them, and a
  /// write that dropped them would turn the policy's answer around.
  decision: string;
  logic: string;
  owner: string;
}

export function emptyPolicyDraft(): PolicyDraft {
  return {
    name: "",
    policy_type: "role",
    description: "",
    decision: "unanimous",
    logic: "positive",
    owner: "",
  };
}

export function policyDraftFrom(policy: PolicyRow): PolicyDraft {
  return {
    name: policy.name,
    policy_type: policy.policy_type,
    description: policy.description,
    decision: policy.decision,
    logic: policy.logic,
    owner: policy.policy_owner,
  };
}

/// The whole of what a policy carries. A partial body is not an edit of some
/// of the terms: the server takes the terms it is given, so anything left out
/// is a term set to nothing.
export function policyWrite(
  draft: PolicyDraft,
  listName: string,
  terms: string[],
  server: string,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    name: draft.name.trim(),
    description: draft.description,
    decision: draft.decision,
    logic: draft.logic,
    policy_owner: draft.owner || server,
    policies: [],
    resources: [],
    scopes: [],
    policy_type: draft.policy_type,
  };
  applyPolicyTerms(body, draft.policy_type, listName, terms);
  return body;
}

export function uniquePolicyTerms(terms: string[]): string[] {
  return [...new Set(terms.map((term) => term.trim()).filter(Boolean))];
}

export function termsFromPolicy(policy: PolicyRow, listName: string): string[] {
  if (policy.policy_type === "aggregated") return [...policy.policies];
  if (!listName) return [];
  return [...((policy as unknown as Record<string, string[]>)[listName] ?? [])];
}

export function applyPolicyTerms(
  body: Record<string, unknown>,
  policyType: string,
  listName: string,
  terms: string[],
): void {
  const unique = uniquePolicyTerms(terms);
  if (policyType === "aggregated") body.policies = unique;
  else if (listName) body[listName] = unique;
}
