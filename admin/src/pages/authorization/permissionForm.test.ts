import { describe, expect, it } from "vitest";
import {
  conditionCandidates,
  isPermission,
  permissionReady,
  permissionWrite,
  type PermissionDraft,
} from "./permissionForm";

const BASE: PermissionDraft = {
  name: "documents",
  description: "",
  policyType: "resource-permission",
  resourceType: "document",
  policies: ["editors"],
  resources: [],
  scopes: [],
  decision: "unanimous",
  logic: "positive",
  owner: "",
};

describe("authorization permission form", () => {
  it("requires a condition and a resource target", () => {
    expect(permissionReady(BASE)).toBe(true);
    expect(permissionReady({ ...BASE, policies: [] })).toBe(false);
    expect(permissionReady({ ...BASE, resourceType: "", resources: [] })).toBe(false);
  });

  it("knows a permission by its kind, even one bound to a type alone", () => {
    expect(isPermission({ policy_type: "resource-permission" })).toBe(true);
    expect(isPermission({ policy_type: "scope-permission" })).toBe(true);
    expect(isPermission({ policy_type: "aggregated" })).toBe(false);
  });

  it("offers every policy but a permission, and never the one being edited", () => {
    const listed = [
      { policy_id: "editors", policy_type: "role" },
      { policy_id: "combined", policy_type: "aggregated" },
      { policy_id: "documents", policy_type: "resource-permission" },
      { policy_id: "reading", policy_type: "scope-permission" },
    ];
    expect(conditionCandidates(listed, "combined").map((held) => held.policy_id)).toEqual([
      "editors",
    ]);
    expect(conditionCandidates(listed, "").map((held) => held.policy_id)).toEqual([
      "editors",
      "combined",
    ]);
  });

  it("requires a scope only for scope permissions", () => {
    expect(permissionReady({ ...BASE, policyType: "scope-permission" })).toBe(false);
    expect(
      permissionReady({ ...BASE, policyType: "scope-permission", scopes: ["read"] }),
    ).toBe(true);
  });

  it("does not leak scope bindings into a resource permission", () => {
    expect(permissionWrite({ ...BASE, scopes: ["read"] }, "app").scopes).toEqual([]);
  });

  it("writes back the fold, the logic and the owner it was opened with", () => {
    const body = permissionWrite(
      { ...BASE, decision: "affirmative", logic: "negative", owner: "alice" },
      "app",
    );
    expect(body.decision).toBe("affirmative");
    expect(body.logic).toBe("negative");
    expect(body.policy_owner).toBe("alice");
  });

  it("gives a new permission to the resource server", () => {
    expect(permissionWrite(BASE, "app").policy_owner).toBe("app");
  });
});
