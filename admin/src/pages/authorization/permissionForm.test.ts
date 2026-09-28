import { describe, expect, it } from "vitest";
import { permissionReady, permissionWrite, type PermissionDraft } from "./permissionForm";

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
