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
