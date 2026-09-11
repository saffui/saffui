import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { forgetOrganizationTheme, getOrganizationTheme, writeOrganizationTheme } = await import("@/services/directory");

afterEach(() => vi.unstubAllGlobals());

describe("organization theme transport", () => {
  test("keeps organization ids isolated and supports inherit/reset", async () => {
    const fetch = vi.fn().mockImplementation((path: string, init: RequestInit) => {
      if (init.method === "GET") {
        return new Response(JSON.stringify(null), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new Response(null, { status: 204 });
    });
    vi.stubGlobal("fetch", fetch);

    await getOrganizationTheme("north/east", "org/acme");
    await writeOrganizationTheme("north/east", "org/acme", { light: { bg: "#fff" } });
    await forgetOrganizationTheme("north/east", "org/acme");

    expect(fetch).toHaveBeenNthCalledWith(1, "/admin/realms/north%2Feast/organizations/org%2Facme/theme", expect.anything());
    expect(fetch).toHaveBeenNthCalledWith(2, "/admin/realms/north%2Feast/organizations/org%2Facme/theme", expect.objectContaining({ method: "PUT", body: JSON.stringify({ light: { bg: "#fff" } }) }));
    expect(fetch).toHaveBeenNthCalledWith(3, "/admin/realms/north%2Feast/organizations/org%2Facme/theme", expect.objectContaining({ method: "DELETE" }));
  });
});
