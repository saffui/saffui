import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { deleteSpnego, getSpnego, putSpnego } = await import("@/services/negotiation");

afterEach(() => vi.unstubAllGlobals());

describe("SPNEGO administration path", () => {
  test("keeps realm and endpoint boundaries on read, write and delete", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ realm_id: "main" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ realm_id: "main" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);

    await getSpnego("north/east");
    await putSpnego("north/east", {
      enabled: true,
      configs: { service_principal: { Str: "HTTP/id.example@EXAMPLE.ORG" } },
    });
    await deleteSpnego("north/east");

    expect(fetch).toHaveBeenNthCalledWith(1, "/admin/realms/north%2Feast/spnego", expect.anything());
    expect(fetch).toHaveBeenNthCalledWith(2, "/admin/realms/north%2Feast/spnego", expect.objectContaining({ method: "PUT" }));
    expect(fetch).toHaveBeenNthCalledWith(3, "/admin/realms/north%2Feast/spnego", expect.objectContaining({ method: "DELETE" }));
  });
});
