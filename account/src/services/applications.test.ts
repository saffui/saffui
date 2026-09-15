import { beforeEach, describe, expect, test, vi } from "vitest";

const sent = vi.hoisted(() => ({ calls: [] as { path: string; method: string }[] }));

vi.mock("./http", () => ({
  api: async (path: string, init?: RequestInit) => {
    sent.calls.push({ path, method: init?.method ?? "GET" });
    return undefined;
  },
}));

import { listApplications, takeBackAccess, withdrawConsent } from "./applications";

beforeEach(() => {
  sent.calls.length = 0;
});

describe("the applications door", () => {
  test("names the application in the path, encoded whole", async () => {
    await listApplications("main");
    await withdrawConsent("main", "app/1");
    await takeBackAccess("main", "app#2");
    expect(sent.calls).toEqual([
      { path: "/realms/main/account-api/v1/me/applications", method: "GET" },
      { path: "/realms/main/account-api/v1/me/applications/app%2F1/consent", method: "DELETE" },
      { path: "/realms/main/account-api/v1/me/applications/app%232/access", method: "DELETE" },
    ]);
  });
});
