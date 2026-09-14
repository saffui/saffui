import { describe, expect, test } from "vitest";
import { providerMutation } from "./forms";
import { PROVIDER_CATALOG, presetDraft } from "./providerCatalog";

describe("identity provider catalogue flow", () => {
  test("turns an operational preset into a complete broker mutation", () => {
    const google = PROVIDER_CATALOG.find((provider) => provider.id === "google");
    const draft = presetDraft(google);
    draft.clientId = "console";
    draft.clientSecret = "new-secret";

    expect(providerMutation(draft)).toEqual(
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

  test("turns the GitHub preset into a plain OAuth 2.0 broker mutation", () => {
    const github = PROVIDER_CATALOG.find((provider) => provider.id === "github");
    const draft = presetDraft(github);
    draft.clientId = "console";
    draft.clientSecret = "new-secret";

    const configs = providerMutation(draft).configs;
    expect(configs).toEqual(
      expect.objectContaining({
        protocol: { Str: "oauth2" },
        userinfo_endpoint: { Str: "https://api.github.com/user" },
        subject_pointer: { Str: "/id" },
        token_auth: { Str: "client_secret_post" },
        emails_endpoint: { Str: "https://api.github.com/user/emails" },
        client_secret: { Str: "new-secret" },
      }),
    );
    expect(configs.issuer).toBeUndefined();
  });

  test("turns the SAML preset into a SAML broker mutation with no key of the other protocols", () => {
    const draft = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === "saml"));
    draft.alias = "partner";
    draft.idpMetadata = "<md:EntityDescriptor/>";

    const configs = providerMutation(draft).configs;
    expect(Object.keys(configs).sort()).toEqual(["idp_metadata", "name_id_format", "protocol"]);
    expect(configs.protocol).toEqual({ Str: "saml" });
  });
});
