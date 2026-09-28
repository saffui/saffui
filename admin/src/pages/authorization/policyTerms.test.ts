import { describe, expect, it } from "vitest";
import { applyPolicyTerms, termsFromPolicy, uniquePolicyTerms } from "./policyTerms";

describe("authorization policy terms", () => {
  it("normalizes pasted identifiers without changing their spelling", () => {
    expect(uniquePolicyTerms([" role-1 ", "role-1", "role-2", ""])).toEqual([
      "role-1",
      "role-2",
    ]);
  });

  it("writes aggregated children to the common policies binding", () => {
    const body: Record<string, unknown> = { policies: [] };
    applyPolicyTerms(body, "aggregated", "", ["p-1", "p-2"]);
    expect(body.policies).toEqual(["p-1", "p-2"]);
  });

  it("reads the list owned by a typed policy", () => {
    const policy = {
      policy_id: "p-1",
      name: "editors",
      description: "",
      policy_type: "role",
      policies: [],
      resources: [],
      scopes: [],
      decision: "unanimous",
      logic: "positive",
      policy_owner: "app",
      roles: ["role-1"],
    };
    expect(termsFromPolicy(policy, "roles")).toEqual(["role-1"]);
  });
});
