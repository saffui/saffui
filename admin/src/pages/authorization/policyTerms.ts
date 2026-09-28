import type { PolicyRow } from "@/models/authz";

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
