import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { releaseUserAction, requireUserAction } = await import("@/services/users");

afterEach(() => vi.unstubAllGlobals());

describe("one required action of a person", () => {
  test("is asked and taken back at its own encoded address, with no list sent", async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);

    await requireUserAction("north/east", "user/id", "verify-email");
    await releaseUserAction("north/east", "user/id", "verify-email");

    const address = "/admin/realms/north%2Feast/users/user%2Fid/required-actions/verify-email";
    expect(fetch).toHaveBeenNthCalledWith(1, address, expect.objectContaining({ method: "PUT" }));
    expect(fetch).toHaveBeenNthCalledWith(2, address, expect.objectContaining({ method: "DELETE" }));
    expect(fetch.mock.calls.every(([, init]) => init.body === undefined)).toBe(true);
  });
});
