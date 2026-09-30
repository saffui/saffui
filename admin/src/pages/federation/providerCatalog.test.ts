import { describe, expect, test } from "vitest";
import { PROVIDER_CATALOG, presetDraft } from "./providerCatalog";

describe("identity provider catalogue", () => {
  test("keeps the designed providers visible", () => {
    const ids = PROVIDER_CATALOG.map((provider) => provider.id);

    expect(ids).toEqual(expect.arrayContaining(["google", "microsoft", "github", "gitlab", "twitter", "oidc", "saml"]));
  });

  test("uses local logos for branded providers, and a glyph where no mark is shipped", () => {
    const unmarked = new Set(["oidc", "saml", "esignet", "esignet-1"]);

    for (const provider of PROVIDER_CATALOG) {
      if (unmarked.has(provider.id)) {
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
    for (const id of ["stackoverflow", "paypal"]) {
      expect(PROVIDER_CATALOG.find((provider) => provider.id === id)?.availability).toBe("backend");
    }
    for (const id of ["github", "bitbucket", "twitter", "linkedin"]) {
      expect(PROVIDER_CATALOG.find((provider) => provider.id === id)?.availability).toBe("ready");
    }
    expect(PROVIDER_CATALOG.some((provider) => provider.id === "instagram")).toBe(false);
  });

  test("prefills eSignet with what it takes: a signed assertion and an encrypted userinfo", () => {
    const esignet = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === "esignet"));
    expect(esignet.protocol).toBe("oidc");
    expect(esignet.tokenAuth).toBe("private_key_jwt");
    expect(esignet.algorithms).toBe("PS256");
    expect(esignet.userinfoForm).toBe("jwe");
    expect(JSON.parse(esignet.claimsRequest).userinfo.name).toEqual({ essential: true });
    expect(esignet.issuer).toBe("");
  });

  test("prefills eSignet 1.x with what it takes: RS256 alone, addressed to its token endpoint", () => {
    const older = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === "esignet-1"));
    expect(older.tokenAuth).toBe("private_key_jwt");
    expect([older.assertionAlgorithm, older.assertionAudience]).toEqual(["RS256", "token_endpoint"]);
    expect([older.algorithms, older.userinfoForm, older.claimsRequest]).toEqual(["RS256", "", ""]);
    const newer = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === "esignet"));
    expect([newer.assertionAlgorithm, newer.assertionAudience]).toEqual(["PS256", "issuer"]);
  });

  test("opens SAML 2.0 on the SAML form", () => {
    const saml = PROVIDER_CATALOG.find((provider) => provider.id === "saml");
    expect(saml?.availability).toBe("manual");
    expect(presetDraft(saml).protocol).toBe("saml");
  });

  test("prefills each plain OAuth 2.0 provider's stable subject, client authentication and PKCE", () => {
    for (const [id, subject, tokenAuth, pkce] of [
      ["github", "/id", "client_secret_post", true],
      ["bitbucket", "/uuid", "client_secret_basic", false],
      ["twitter", "/data/id", "client_secret_basic", true],
    ] as const) {
      const draft = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === id));
      expect(draft.protocol).toBe("oauth2");
      expect(draft.subjectPointer).toBe(subject);
      expect(draft.userinfoEndpoint).toMatch(/^https:\/\//);
      expect(draft.tokenAuth).toBe(tokenAuth);
      expect(draft.pkce).toBe(pkce);
    }
    const linkedin = presetDraft(PROVIDER_CATALOG.find((provider) => provider.id === "linkedin"));
    expect(linkedin.protocol).toBe("oidc");
    expect(linkedin.tokenAuth).toBe("client_secret_post");
    expect(linkedin.pkce).toBe(false);
  });
});
