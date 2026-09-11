import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { eraseAuthzRoute, listAuthzRoutes, writeAuthzRoute } = await import("@/services/authz");

afterEach(() => vi.unstubAllGlobals());

describe("authorization route transport", () => {
  test("encodes realm and route ids while preserving the backend shape", async () => {
    const fetch = vi.fn().mockImplementation((path: string, init: RequestInit) => {
      if (init.method === "GET") {
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetch);

    await listAuthzRoutes("north/east");
    await writeAuthzRoute("north/east", "orders/read", {
      method: "GET",
      path: "/api/orders/*",
      server_id: "web-dashboard",
      resource: "orders",
      scope: "read",
      action: "invoke",
      priority: 10,
      enabled: true,
    });
    await eraseAuthzRoute("north/east", "orders/read");

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/authz/routes",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/authz/routes/orders%2Fread",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({
          method: "GET",
          path: "/api/orders/*",
          server_id: "web-dashboard",
          resource: "orders",
          scope: "read",
          action: "invoke",
          priority: 10,
          enabled: true,
        }),
      }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      3,
      "/admin/realms/north%2Feast/authz/routes/orders%2Fread",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});
