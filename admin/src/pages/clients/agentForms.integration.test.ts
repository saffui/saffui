import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { registerAgent, reshapeAgent } = await import("@/services/clients");

afterEach(() => vi.unstubAllGlobals());

describe("agent administration write path", () => {
  test("uses the authenticated realm-scoped agent endpoints", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ client_id: "deploy-bot" }), { status: 201 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ client_id: "deploy-bot" }), { status: 200 }));
    vi.stubGlobal("fetch", fetch);

    await registerAgent("north/east", {
      client_id: "deploy-bot",
      capabilities: ["deploy:read"],
      session_seconds: 900,
    });
    await reshapeAgent("north/east", "deploy/bot", { add: ["audit:read"], remove: [] });

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/agents",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/agents/deploy%2Fbot",
      expect.objectContaining({ method: "PUT" }),
    );
    for (const [, init] of fetch.mock.calls) {
      expect((init.headers as Headers).get("authorization")).toBe("Bearer admin-token");
    }
  });
});
