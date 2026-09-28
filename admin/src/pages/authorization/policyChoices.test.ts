import { describe, expect, it } from "vitest";
import { clientScopeChoices } from "./policyChoices";

describe("authorization policy choices", () => {
  it("offers a client scope by its identifier, under its name", () => {
    const scopes = [
      {
        client_scope_id: "profile",
        name: "profile",
        description: "",
        protocol: "openid-connect",
        default_scope: true,
      },
      {
        client_scope_id: "6f1c2a90-4d3e-4b8f-9a27-5c0e8d1b7f43",
        name: "employment",
        description: "",
        protocol: "openid-connect",
        default_scope: false,
      },
    ];
    expect(clientScopeChoices(scopes, new Set(["6f1c2a90-4d3e-4b8f-9a27-5c0e8d1b7f43"]))).toEqual([
      { id: "profile", label: "profile", held: false },
      { id: "6f1c2a90-4d3e-4b8f-9a27-5c0e8d1b7f43", label: "employment", held: true },
    ]);
  });
});
