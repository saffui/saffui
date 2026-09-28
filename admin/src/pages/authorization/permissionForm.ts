export type PermissionType = "resource-permission" | "scope-permission";

export interface PermissionDraft {
  name: string;
  description: string;
  policyType: PermissionType;
  resourceType: string;
  policies: string[];
  resources: string[];
  scopes: string[];
}

/// A permission is known by its kind: one naming only a resource type binds no
/// row and is a permission all the same.
export function isPermission(policy: { policy_type: string }): boolean {
  return policy.policy_type === "resource-permission" || policy.policy_type === "scope-permission";
}

/// What a policy or a permission may be built from: any policy but a
/// permission, and never itself.
export function conditionCandidates<T extends { policy_id: string; policy_type: string }>(
  policies: T[],
  editing: string,
): T[] {
  return policies.filter((held) => !isPermission(held) && held.policy_id !== editing);
}

export function permissionReady(draft: PermissionDraft): boolean {
  if (!draft.name.trim() || !draft.policies.length) return false;
  if (!draft.resources.length && !draft.resourceType.trim()) return false;
  return draft.policyType !== "scope-permission" || draft.scopes.length > 0;
}

export function permissionWrite(draft: PermissionDraft, owner: string): Record<string, unknown> {
  return {
    name: draft.name.trim(),
    description: draft.description.trim(),
    decision: "unanimous",
    logic: "positive",
    policy_owner: owner,
    policies: [...new Set(draft.policies)],
    resources: [...new Set(draft.resources)],
    scopes: draft.policyType === "scope-permission" ? [...new Set(draft.scopes)] : [],
    policy_type: draft.policyType,
    resource_type: draft.resourceType.trim(),
  };
}
