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

  test("keeps out of reach only the providers the broker cannot serve", () => {
    for (const id of ["stackoverflow", "paypal", "saml"]) {
      expect(PROVIDER_CATALOG.find((provider) => provider.id === id)?.availability).toBe("backend");
    }
    for (const id of ["github", "bitbucket", "twitter", "linkedin"]) {
      expect(PROVIDER_CATALOG.find((provider) => provider.id === id)?.availability).toBe("ready");
    }
    expect(PROVIDER_CATALOG.some((provider) => provider.id === "instagram")).toBe(false);
  });

  test("prefills the plain OAuth 2.0 providers by their stable subject", () => {
    for (const [id, subject] of [
      ["github", "/id"],
      ["bitbucket", "/uuid"],
      ["twitter", "/data/id"],
    ]) {
      const draft = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === id));
      expect(draft.protocol).toBe("oauth2");
      expect(draft.subjectPointer).toBe(subject);
      expect(draft.userinfoEndpoint).toMatch(/^https:\/\//);
    }
    const linkedin = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === "linkedin"));
    expect(linkedin.protocol).toBe("oidc");
    expect(linkedin.tokenAuth).toBe("client_secret_post");
    expect(linkedin.pkce).toBe(false);
  });
});
