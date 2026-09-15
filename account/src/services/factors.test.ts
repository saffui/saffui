import { beforeEach, describe, expect, test, vi } from "vitest";

const sent = vi.hoisted(() => ({ calls: [] as { path: string; method: string; json?: unknown }[] }));

vi.mock("./http", () => ({
  api: async (path: string, init?: RequestInit & { json?: unknown }) => {
    sent.calls.push({ path, method: init?.method ?? "GET", json: init?.json });
    return undefined;
  },
}));

import {
  changePassword,
  checkRecentSignIn,
  listFactors,
  removeApp,
  removeKey,
  removeRecoveryCodes,
} from "./factors";

beforeEach(() => {
  sent.calls.length = 0;
});

describe("the door to the ways to sign in", () => {
  test("names each factor in the path, encoded whole, and sends a password as JSON", async () => {
    await listFactors("main");
    await checkRecentSignIn("main");
    await changePassword("main", "old secret", "new secret");
    await removeApp("main", "app/1");
    await removeKey("main", "a-_b");
    await removeRecoveryCodes("main");
    expect(sent.calls).toEqual([
      { path: "/realms/main/account-api/v1/me/credentials", method: "GET" },
      { path: "/realms/main/account-api/v1/me/recent-sign-in", method: "GET" },
      {
        path: "/realms/main/account-api/v1/me/password",
        method: "PUT",
        json: { current_password: "old secret", new_password: "new secret" },
      },
      { path: "/realms/main/account-api/v1/me/credentials/app%2F1", method: "DELETE" },
      { path: "/realms/main/account-api/v1/me/keys/a-_b", method: "DELETE" },
      { path: "/realms/main/account-api/v1/me/recovery-codes", method: "DELETE" },
    ]);
  });
});
