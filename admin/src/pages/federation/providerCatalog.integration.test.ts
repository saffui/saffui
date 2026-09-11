import { describe, expect, test } from "vitest";
import { oidcMutation } from "./forms";
import { PROVIDER_CATALOG, presetDraft } from "./providerCatalog";

describe("identity provider catalogue flow", () => {
  test("turns an operational preset into a complete broker mutation", () => {
    const google = PROVIDER_CATALOG.find((provider) => provider.id === "google");
    const draft = presetDraft(google);
    draft.clientId = "console";
    draft.clientSecret = "new-secret";

    expect(oidcMutation(draft)).toEqual(
      expect.objectContaining({
        provider_id: "google",
        display_name: "Google",
        configs: expect.objectContaining({
          issuer: { Str: "https://accounts.google.com" },
          client_id: { Str: "console" },
          client_secret: { Str: "new-secret" },
        }),
      }),
    );
  });
});
