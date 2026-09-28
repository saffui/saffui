import { describe, expect, it } from "vitest";
import { scopeWrite } from "./scopeForm";

describe("client scope form", () => {
  it("keeps the default assignment when creating or editing a scope", () => {
    expect(
      scopeWrite({ name: " profile ", description: " Basic identity ", defaultScope: true }),
    ).toEqual({
      name: "profile",
      description: "Basic identity",
      default_scope: true,
    });
  });
});
