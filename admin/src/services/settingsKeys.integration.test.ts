import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { disableRealmKey, getRealmKeys, rotateKey } = await import("@/services/settings");

afterEach(() => vi.unstubAllGlobals());

describe("realm key transport", () => {
  test("preserves the public key view and encodes realm and kid", async () => {
    const response = {
      signing: [{ kid: "kid/one", algorithm: "ES256", status: "active", created_at: 42 }],
      encryption: [],
    };
    const fetch = vi.fn().mockImplementation((_path: string, init: RequestInit) => {
      const method = init.method ?? "GET";
      if (method === "DELETE") return new Response(null, { status: 204 });
      return new Response(JSON.stringify(response), {
        status: method === "POST" ? 201 : 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetch);

    await expect(getRealmKeys("north/east")).resolves.toEqual(response);
    await rotateKey("north/east", "ES256");
    await disableRealmKey("north/east", "kid/one");

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/keys",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/keys",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ algorithm: "ES256" }) }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      3,
      "/admin/realms/north%2Feast/keys/kid%2Fone",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});
