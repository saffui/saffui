import { beforeEach, describe, expect, test, vi } from "vitest";

const client = vi.hoisted(() => {
  class SaffuiError extends Error {
    error: string;
    constructor(error: string, description: string) {
      super(description);
      this.error = error;
    }
  }
  return {
    configs: [] as unknown[],
    login: vi.fn(async (_asked: unknown) => {}),
    stepUp: vi.fn(async (_asked: unknown) => {}),
    handleRedirect: vi.fn(),
    renew: vi.fn(),
    logout: vi.fn(async (_hint?: string) => {}),
    SaffuiError,
  };
});

vi.mock("saffui-js", () => ({
  // Handed over in the constructor: a class field named like an import of this file
  // would be rewritten by the mock hoisting into a read of that import.
  Saffui: class {
    constructor(config: unknown) {
      client.configs.push(config);
      Object.assign(this, {
        login: client.login,
        stepUp: client.stepUp,
        handleRedirect: client.handleRedirect,
        renew: client.renew,
        logout: client.logout,
      });
    }
  },
  SaffuiError: client.SaffuiError,
}));

import {
  adoptTokens,
  chooseRefusedRoute,
  composeRefusedPath,
  enrolFactor,
  finishSignIn,
  forgetSignIn,
  holdRealm,
  isFreshlyAdopted,
  isSignedIn,
  isStepUpRecent,
  loseSignIn,
  readBearer,
  rememberPath,
  session,
  signIn,
  SignInRefused,
  signOut,
  stepUp,
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
const RETURN = "https://id.example/realms/main/account/login/return";
const TONGUE = expect.stringMatching(/^(en|fr)$/);

beforeEach(() => {
  vi.unstubAllGlobals();
  stubSessionStorage();
  vi.stubGlobal("location", { origin: "https://id.example" });
  client.configs.length = 0;
  client.login.mockClear();
  client.stepUp.mockClear();
  client.handleRedirect.mockReset();
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
      redirectUri: RETURN,
      scope: "openid account",
      extra: { ui_locales: TONGUE },
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

describe("asking for more than a sign-in", () => {
  test("a step-up asks for what the challenge names, in the console's tongue", async () => {
    const challenge = { error: "insufficient_user_authentication", acrValues: "mfa", maxAge: 300 };
    await stepUp(challenge, "/security");
    expect(client.stepUp).toHaveBeenCalledWith({
      redirectUri: RETURN,
      scope: "openid account",
      extra: { ui_locales: TONGUE },
      challenge,
    });
    expect(client.login).not.toHaveBeenCalled();
  });

  test("adding a way to sign in names the ceremony to the sign-in pages", async () => {
    await enrolFactor("configure-webauthn", "/security");
    expect(client.login).toHaveBeenCalledWith({
      redirectUri: RETURN,
      scope: "openid account",
      extra: { ui_locales: TONGUE, enrol: "configure-webauthn" },
    });
  });
});

describe("coming back from a sign-in", () => {
  test("lands on the page it left, and notes a step-up that came back", async () => {
    client.handleRedirect.mockResolvedValue(HOUR);
    await stepUp({ maxAge: 300 }, "/security");
    await expect(finishSignIn(new URLSearchParams("code=c&state=s"), 5_000)).resolves.toEqual({
      path: "/security",
      attempt: "step-up",
    });
    expect(isSignedIn(5_000)).toBe(true);
    expect(isStepUpRecent(5_000 + 119_999)).toBe(true);
    expect(isStepUpRecent(5_000 + 120_000)).toBe(false);
  });

  test("notes no step-up after a plain sign-in", async () => {
    client.handleRedirect.mockResolvedValue(HOUR);
    await signIn("/sessions");
    await expect(finishSignIn(new URLSearchParams("code=c"), 5_000)).resolves.toEqual({
      path: "/sessions",
      attempt: "sign-in",
    });
    expect(isStepUpRecent(5_000)).toBe(false);
  });

  test("a refused sign-in says where it was meant to land and what it was for", async () => {
    client.handleRedirect.mockRejectedValue(new client.SaffuiError("invalid_request", "refused"));
    await enrolFactor("configure-totp", "/security");
    const refused = await finishSignIn(new URLSearchParams("error=invalid_request")).catch(
      (error: unknown) => error,
    );
    expect(refused).toBeInstanceOf(SignInRefused);
    expect((refused as SignInRefused).landing).toEqual({ path: "/security", attempt: "enrol" });
    expect(isSignedIn()).toBe(false);
    expect(composeRefusedPath({ path: "/security?tab=keys", attempt: "step-up" })).toBe(
      "/security?tab=keys&refused=step-up",
    );
  });

  test("a refused sign-in goes where it can be understood", () => {
    const refusedBy = (attempt: "sign-in" | "enrol" | "step-up", error: string) =>
      new SignInRefused({ path: "/security", attempt }, new client.SaffuiError(error, "refused"));
    expect(chooseRefusedRoute(refusedBy("sign-in", "no_login"))).toBe("/profile");
    expect(chooseRefusedRoute(refusedBy("enrol", "invalid_request"))).toBe(
      "/security?refused=enrol",
    );
    expect(chooseRefusedRoute(refusedBy("step-up", "server_error"))).toBe(
      "/security?refused=step-up",
    );
    expect(chooseRefusedRoute(refusedBy("sign-in", "access_denied"))).toBe("/trouble");
    expect(chooseRefusedRoute(new Error("anything"))).toBe("/trouble");
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

  test("forgets a sign-in the server already ended, telling the server nothing", () => {
    adoptTokens(HOUR);
    session.steppedUpAt = Date.now();
    forgetSignIn();
    expect(isSignedIn()).toBe(false);
    expect(isStepUpRecent()).toBe(false);
    expect(client.logout).not.toHaveBeenCalled();
  });

  test("stands when the server cannot be reached", async () => {
    adoptTokens(HOUR);
    client.logout.mockRejectedValue(new Error("offline"));
    await expect(signOut()).resolves.toBeUndefined();
    expect(isSignedIn()).toBe(false);
  });
});
