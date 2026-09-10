import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { listFederatedIdentities, listMessageDeliveries } = await import("@/services/users");

afterEach(() => vi.unstubAllGlobals());

describe("user federation and message reads", () => {
  test("keeps both read-only records on the encoded user route", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response("[]", { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ deliveries: [] }), { status: 200 }));
    vi.stubGlobal("fetch", fetch);

    await listFederatedIdentities("north/east", "user/id");
    await listMessageDeliveries("north/east", "user/id");

    expect(fetch).toHaveBeenNthCalledWith(1, "/admin/realms/north%2Feast/users/user%2Fid/federated-identities", expect.anything());
    expect(fetch).toHaveBeenNthCalledWith(2, "/admin/realms/north%2Feast/users/user%2Fid/messages", expect.anything());
  });
});
