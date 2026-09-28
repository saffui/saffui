import { describe, expect, it } from "vitest";
import {
  applyPolicyTerms,
  emptyPolicyDraft,
  policyDraftFrom,
  policyWrite,
  termsFromPolicy,
  uniquePolicyTerms,
} from "./policyTerms";

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

  it("writes back the fold, the logic and the owner an edited policy holds", () => {
    const held = {
      policy_id: "p-1",
      name: "not-contractors",
      description: "",
      policy_type: "group",
      policies: [],
      resources: [],
      scopes: [],
      decision: "affirmative",
      logic: "negative",
      policy_owner: "alice",
      groups: ["contractors"],
    };
    const body = policyWrite(policyDraftFrom(held), "groups", ["contractors"], "app");
    expect(body.decision).toBe("affirmative");
    expect(body.logic).toBe("negative");
    expect(body.policy_owner).toBe("alice");
    expect(body.groups).toEqual(["contractors"]);
  });

  it("writes a new policy positive, unanimous and owned by the resource server", () => {
    const body = policyWrite({ ...emptyPolicyDraft(), name: "editors" }, "roles", ["role-1"], "app");
    expect(body.decision).toBe("unanimous");
    expect(body.logic).toBe("positive");
    expect(body.policy_owner).toBe("app");
  });
});
