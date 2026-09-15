import { beforeEach, describe, expect, test, vi } from "vitest";

const sent = vi.hoisted(() => ({ calls: [] as { path: string; method: string }[] }));

vi.mock("./http", () => ({
  api: async (path: string, init?: RequestInit) => {
    sent.calls.push({ path, method: init?.method ?? "GET" });
    return undefined;
  },
}));

import { endLogin, endOtherLogins, listLogins, revokeGrant } from "./sessions";

beforeEach(() => {
  sent.calls.length = 0;
});

describe("the logins door", () => {
  test("names the login and the application in the path, each encoded whole", async () => {
    await listLogins("main");
    await endOtherLogins("main");
    await endLogin("main", "a/b?c");
    await revokeGrant("main", "a/b", "app#1");
    expect(sent.calls).toEqual([
      { path: "/realms/main/account-api/v1/me/sessions", method: "GET" },
      { path: "/realms/main/account-api/v1/me/sessions", method: "DELETE" },
      { path: "/realms/main/account-api/v1/me/sessions/a%2Fb%3Fc", method: "DELETE" },
      { path: "/realms/main/account-api/v1/me/sessions/a%2Fb/grants/app%231", method: "DELETE" },
    ]);
  });
});
