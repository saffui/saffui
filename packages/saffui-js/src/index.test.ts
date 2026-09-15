import { afterEach, describe, expect, it, vi } from "vitest";
import { peek, readChallenge, SaffuiError, Saffui } from "./index";

describe("peek", () => {
  it("reads claims without verifying, and only displays them", () => {
    const claims = { sub: "ada", preferred_username: "ada" };
    const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
    expect(peek(`h.${body}.s`)).toEqual(claims);
  });
  it("throws on a token with no body to read", () => {
    expect(() => peek("not-a-token")).toThrow();
  });
});

describe("endpoints", () => {
  it("speaks the realm's own protocol paths", () => {
    const held = new Saffui({ realm: "main", clientId: "saffui-console" });
    expect(held.endpoint("token")).toBe("/realms/main/protocol/openid-connect/token");
    const away = new Saffui({ url: "https://id.example", realm: "a b", clientId: "c" });
    expect(away.endpoint("auth")).toBe(
      "https://id.example/realms/a%20b/protocol/openid-connect/auth",
    );
  });
});

describe("SaffuiError", () => {
  it("carries the protocol word beside the prose", () => {
    const refused = new SaffuiError("access_denied", "the login was refused");
    expect(refused.error).toBe("access_denied");
    expect(refused.message).toBe("the login was refused");
  });
});

describe("readChallenge", () => {
  it("reads what RFC 9470 asks of a new sign-in, a comma inside a quoted value included", () => {
    expect(
      readChallenge(
        'Bearer error="insufficient_user_authentication", error_description="sign in again, recently and as strongly as this account allows", acr_values="mfa", max_age="300"',
      ),
    ).toEqual({
      error: "insufficient_user_authentication",
      description: "sign in again, recently and as strongly as this account allows",
      acrValues: "mfa",
      maxAge: 300,
    });
  });

  it("reads a challenge naming no level, a bare token value, and a scheme in any case", () => {
    expect(readChallenge('Bearer error="insufficient_user_authentication", max_age=300')).toEqual({
      error: "insufficient_user_authentication",
      description: undefined,
      acrValues: undefined,
      maxAge: 300,
    });
    expect(readChallenge('bearer error="invalid_token"')).toMatchObject({ error: "invalid_token" });
  });

  it("unescapes a quoted pair, and the first of a repeated parameter counts", () => {
    expect(
      readChallenge('Bearer error_description="say \\"again\\"", error="first", error="second"'),
    ).toMatchObject({ description: 'say "again"', error: "first" });
  });

  it("reads nothing from no header or another scheme, and no age from a malformed one", () => {
    expect(readChallenge(null)).toBeNull();
    expect(readChallenge("")).toBeNull();
    expect(readChallenge('Basic realm="x"')).toBeNull();
    expect(readChallenge('DPoP error="use_dpop_nonce"')).toBeNull();
    expect(readChallenge('Bearer max_age="soon"')).toMatchObject({ maxAge: undefined });
  });
});

describe("stepUp", () => {
  function stubBrowser(): string[] {
    const kept = new Map<string, string>();
    const sent: string[] = [];
    vi.stubGlobal("sessionStorage", {
      getItem: (key: string) => kept.get(key) ?? null,
      setItem: (key: string, value: string) => void kept.set(key, value),
      removeItem: (key: string) => void kept.delete(key),
    });
    vi.stubGlobal("location", { assign: (url: string) => void sent.push(url) });
    return sent;
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("asks the sign-in for the challenge's level and age, beside the caller's own parameters", async () => {
    const sent = stubBrowser();
    await new Saffui({ realm: "main", clientId: "account-console" }).stepUp({
      redirectUri: "https://id.example/realms/main/account/login/return",
      scope: "openid account",
      extra: { ui_locales: "fr" },
      challenge: { error: "insufficient_user_authentication", acrValues: "mfa", maxAge: 300 },
    });
    const asked = new URL(sent[0], "https://id.example");
    expect(asked.pathname).toBe("/realms/main/protocol/openid-connect/auth");
    expect(Object.fromEntries(asked.searchParams)).toMatchObject({
      client_id: "account-console",
      redirect_uri: "https://id.example/realms/main/account/login/return",
      scope: "openid account",
      ui_locales: "fr",
      acr_values: "mfa",
      max_age: "300",
      code_challenge_method: "S256",
    });
  });

  it("leaves out what the challenge does not name", async () => {
    const sent = stubBrowser();
    await new Saffui({ realm: "main", clientId: "c" }).stepUp({
      redirectUri: "https://app.example/back",
      challenge: { maxAge: 300 },
    });
    const asked = new URL(sent[0], "https://id.example").searchParams;
    expect(asked.has("acr_values")).toBe(false);
    expect(asked.get("max_age")).toBe("300");
  });
});
