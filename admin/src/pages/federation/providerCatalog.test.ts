import { describe, expect, test } from "vitest";
import { PROVIDER_CATALOG, presetDraft } from "./providerCatalog";

describe("identity provider catalogue", () => {
  test("keeps the designed providers visible", () => {
    const ids = PROVIDER_CATALOG.map((provider) => provider.id);

    expect(ids).toEqual(expect.arrayContaining(["google", "microsoft", "github", "gitlab", "twitter", "oidc", "saml"]));
  });

  test("uses local logos for branded providers", () => {
    const protocols = new Set(["oidc", "saml"]);

    for (const provider of PROVIDER_CATALOG) {
      if (protocols.has(provider.id)) {
        expect(provider.logo).toBeUndefined();
        expect(provider.glyph).toBeTruthy();
      } else {
        expect(provider.logo).toBeTruthy();
        expect(provider.logo).not.toMatch(/^https?:/);
        expect(provider.glyph).toBeUndefined();
      }
    }
  });

  test("prefills providers the OIDC broker can consume", () => {
    const gitlab = PROVIDER_CATALOG.find((provider) => provider.id === "gitlab");
    const draft = presetDraft(gitlab);

    expect(draft.alias).toBe("gitlab");
    expect(draft.authorizationEndpoint).toBe("https://gitlab.com/oauth/authorize");
    expect(draft.scope.split(" ")).toContain("openid");
  });

  test("does not present OAuth-only providers as operational", () => {
    for (const id of ["github", "twitter", "bitbucket", "instagram", "stackoverflow"]) {
      expect(PROVIDER_CATALOG.find((provider) => provider.id === id)?.availability).toBe("backend");
    }
  });
});
