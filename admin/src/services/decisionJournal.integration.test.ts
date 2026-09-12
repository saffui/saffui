import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { listDecisions, listDisagreements, pruneDecisionsBefore } = await import("@/services/authz");

afterEach(() => vi.unstubAllGlobals());

describe("decision journal reads", () => {
  test("keeps decisions and disagreements on their dedicated endpoints", async () => {
    const fetch = vi.fn().mockImplementation((_path: string, init: RequestInit) =>
      new Response(JSON.stringify((init.method ?? "GET") === "DELETE" ? { removed: 8 } : []), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await listDecisions("north/east", 25);
    await listDisagreements("north/east", 25);

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/authz/decisions?limit=25",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/authz/decisions/disagreements?limit=25",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );

    await expect(
      pruneDecisionsBefore("north/east", new Date("2026-08-31T00:00:00.000Z")),
    ).resolves.toEqual({ removed: 8 });
    expect(fetch).toHaveBeenNthCalledWith(
      3,
      "/admin/realms/north%2Feast/authz/decisions?before=2026-08-31T00%3A00%3A00.000Z",
      expect.objectContaining({ method: "DELETE", headers: expect.any(Headers) }),
    );
  });
});
