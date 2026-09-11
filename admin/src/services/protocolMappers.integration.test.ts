import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { createRealmMapper, deleteRealmMapper, listRealmMappers, updateRealmMapper } = await import("@/services/scopes");

afterEach(() => vi.unstubAllGlobals());

describe("protocol mapper transport", () => {
  test("uses the realm mapper endpoints for the full lifecycle", async () => {
    const fetch = vi.fn().mockImplementation((path: string, init: RequestInit) => {
      if (init.method === "GET") return new Response(JSON.stringify([]), { status: 200, headers: { "content-type": "application/json" } });
      if (init.method === "DELETE") return new Response(null, { status: 204 });
      return new Response(JSON.stringify({ mapper_id: "m-1", name: "department", protocol: "openid-connect", mapper_type: "oidc-usermodel-attribute-mapper" }), { status: 200, headers: { "content-type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetch);
    const body = { name: "department", protocol: "openid-connect", mapper_type: "oidc-usermodel-attribute-mapper", configs: { "claim.name": "department" } };

    await listRealmMappers("north/east");
    await createRealmMapper("north/east", body);
    await updateRealmMapper("north/east", "m/1", body);
    await deleteRealmMapper("north/east", "m/1");

    expect(fetch).toHaveBeenNthCalledWith(1, "/admin/realms/north%2Feast/protocol-mappers", expect.anything());
    expect(fetch).toHaveBeenNthCalledWith(2, "/admin/realms/north%2Feast/protocol-mappers", expect.objectContaining({ method: "POST", body: JSON.stringify(body) }));
    expect(fetch).toHaveBeenNthCalledWith(3, "/admin/realms/north%2Feast/protocol-mappers/m%2F1", expect.objectContaining({ method: "PUT", body: JSON.stringify(body) }));
    expect(fetch).toHaveBeenNthCalledWith(4, "/admin/realms/north%2Feast/protocol-mappers/m%2F1", expect.objectContaining({ method: "DELETE" }));
  });
});
