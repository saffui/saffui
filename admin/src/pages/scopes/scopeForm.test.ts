import { describe, expect, it } from "vitest";
import { scopeWrite } from "./scopeForm";

describe("client scope form", () => {
  it("keeps the default assignment when creating or editing a scope", () => {
    expect(
      scopeWrite({ name: " profile ", description: " Basic identity ", defaultScope: true }, null),
    ).toEqual({
      name: "profile",
      description: "Basic identity",
      default_scope: true,
    });
  });

  it("sends an edited scope back with its protocol and its settings", () => {
    const held = {
      client_scope_id: "6f1c2a90-4d3e-4b8f-9a27-5c0e8d1b7f43",
      name: "badge",
      description: "",
      protocol: "saml",
      default_scope: false,
      configs: { "consent.screen.text": { Str: "Your door badge" } },
    };
    expect(
      scopeWrite({ name: "badge", description: "Door badge", defaultScope: false }, held),
    ).toEqual({
      name: "badge",
      description: "Door badge",
      default_scope: false,
      protocol: "saml",
      configs: { "consent.screen.text": { Str: "Your door badge" } },
    });
  });
});
