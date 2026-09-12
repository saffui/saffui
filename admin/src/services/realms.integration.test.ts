import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { importRealm } = await import("@/services/realms");

afterEach(() => vi.unstubAllGlobals());

describe("complete realm import transport", () => {
  test("keeps the document intact and encodes the target and administrator", async () => {
    const result = {
      realm_id: "realm-42",
      administrator: { user_name: "admin/root", password: "shown-once" },
    };
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(result), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);
    const document = { realm: { name: "source" }, users: [{ user_name: "ada" }] };

    await expect(
      importRealm(document, { as: "north/east", administrator: "admin/root" }),
    ).resolves.toEqual(result);

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/import?as=north%2Feast&administrator=admin%2Froot",
      expect.objectContaining({ method: "POST", body: JSON.stringify(document) }),
    );
  });

  test("omits an administrator when none was requested", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ realm_id: "realm-42" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await importRealm({}, { as: "north" });

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/import?as=north",
      expect.objectContaining({ method: "POST", body: "{}" }),
    );
  });
});
