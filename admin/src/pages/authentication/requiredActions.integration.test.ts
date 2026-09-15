import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { unregisterAction } = await import("@/services/flows");

afterEach(() => vi.unstubAllGlobals());

describe("a realm's required action", () => {
  test("is unregistered at its own encoded address", async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);

    await unregisterAction("north/east", "configure-totp");

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/north%2Feast/auth/required-actions/configure-totp",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});
