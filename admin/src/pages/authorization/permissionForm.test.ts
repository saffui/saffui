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
});
