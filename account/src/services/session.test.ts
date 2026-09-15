import { beforeEach, describe, expect, test, vi } from "vitest";

const client = vi.hoisted(() => ({
  configs: [] as unknown[],
  login: vi.fn(async (_asked: unknown) => {}),
  renew: vi.fn(),
  logout: vi.fn(async (_hint?: string) => {}),
}));

vi.mock("saffui-js", () => ({
  Saffui: class {
    login = client.login;
    renew = client.renew;
    logout = client.logout;
    constructor(config: unknown) {
      client.configs.push(config);
    }
  },
}));

import {
  adoptTokens,
  holdRealm,
  isFreshlyAdopted,
  isSignedIn,
  loseSignIn,
  readBearer,
  rememberPath,
  session,
  signIn,
  signOut,
  takeRememberedPath,
} from "./session";

function stubSessionStorage(): void {
  const held = new Map<string, string>();
  vi.stubGlobal("sessionStorage", {
    getItem: (key: string) => held.get(key) ?? null,
    setItem: (key: string, value: string) => void held.set(key, value),
    removeItem: (key: string) => void held.delete(key),
  });
}

const HOUR = { access_token: "a", refresh_token: "r1", expires_in: 3600, token_type: "Bearer" };

beforeEach(() => {
  vi.unstubAllGlobals();
  stubSessionStorage();
  vi.stubGlobal("location", { origin: "https://id.example" });
  client.configs.length = 0;
  client.login.mockClear();
  client.renew.mockReset();
  client.logout.mockClear();
  loseSignIn("ended");
  session.lost = "";
  holdRealm("main");
});

describe("the page to land back on", () => {
  test("is the one the sign-in interrupted, taken once", () => {
    rememberPath("/profile?tab=contact");
    expect(takeRememberedPath()).toBe("/profile?tab=contact");
    expect(takeRememberedPath()).toBe("/profile");
  });

  test("is never anywhere but this console", () => {
    for (const away of [
      "//evil.example/x",
      "/\\evil.example",
      "https://evil.example",
      "profile",
      "/login/return?code=x",
      "",
    ]) {
      rememberPath(away);
      expect(takeRememberedPath(), away).toBe("/profile");
    }
  });
});

describe("signing in", () => {
  test("asks the realm for the account scope, in the console's tongue, back to the console", async () => {
    await signIn("/profile");
    expect(client.configs).toEqual([{ realm: "main", clientId: "account-console" }]);
    expect(client.login).toHaveBeenCalledWith({
      redirectUri: "https://id.example/realms/main/account/login/return",
      scope: "openid account",
      extra: { ui_locales: expect.stringMatching(/^(en|fr)$/) },
    });
    expect(takeRememberedPath()).toBe("/profile");
  });

  test("holds a token until a little before it runs out", () => {
    adoptTokens({ ...HOUR, expires_in: 300 }, 1_000);
    expect(isSignedIn(1_000 + 284_999)).toBe(true);
    expect(isSignedIn(1_000 + 285_000)).toBe(false);
  });

  test("tells a token adopted only just now from one held a while", () => {
    adoptTokens(HOUR, 1_000);
    expect(isFreshlyAdopted(1_000 + 29_999)).toBe(true);
    expect(isFreshlyAdopted(1_000 + 30_000)).toBe(false);
  });
});

describe("a stale token", () => {
  test("is renewed once for every caller waiting on it", async () => {
    adoptTokens(HOUR, 0);
    client.renew.mockResolvedValue({ ...HOUR, access_token: "renewed", refresh_token: "r2" });
    const later = Date.now();
    await expect(Promise.all([readBearer(later), readBearer(later)])).resolves.toEqual([
      "renewed",
      "renewed",
    ]);
    expect(client.renew).toHaveBeenCalledTimes(1);
    expect(client.renew).toHaveBeenCalledWith("r1");
  });

  test("that cannot be renewed loses the sign-in as ended", async () => {
    adoptTokens(HOUR, 0);
    client.renew.mockRejectedValue(new Error("invalid_grant"));
    await expect(readBearer(Date.now())).rejects.toThrow();
    expect(session.lost).toBe("ended");
    expect(session.accessToken).toBe("");
  });

  test("with nothing to renew it by loses the sign-in as ended", async () => {
    await expect(readBearer()).rejects.toThrow();
    expect(client.renew).not.toHaveBeenCalled();
    expect(session.lost).toBe("ended");
  });
});

describe("signing out", () => {
  test("forgets the tokens here before telling the server", async () => {
    adoptTokens({ ...HOUR, id_token: "id-1" });
    client.logout.mockImplementation(async () => {
      expect(session.accessToken).toBe("");
    });
    await signOut();
    expect(client.logout).toHaveBeenCalledWith("id-1");
    expect(isSignedIn()).toBe(false);
  });

  test("stands when the server cannot be reached", async () => {
    adoptTokens(HOUR);
    client.logout.mockRejectedValue(new Error("offline"));
    await expect(signOut()).resolves.toBeUndefined();
    expect(isSignedIn()).toBe(false);
  });
});
