import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { getRealmSettings, reshapeRealm } = await import("@/services/settings");

afterEach(() => vi.unstubAllGlobals());

describe("realm settings transport", () => {
  test("reads the full representation and writes the named toggles", async () => {
    const settings = {
      edit_user_name_allowed: true,
      remember_me: true,
      revoke_refresh_token: true,
      require_pushed_authorization_requests: true,
    };
    const fetch = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify(settings), {
        status: 200,
        headers: { "content-type": "application/json" },
      })),
    );
    vi.stubGlobal("fetch", fetch);

    await getRealmSettings("north/east");
    await reshapeRealm(
      "north/east",
      {
        edit_user_name_allowed: true,
        remember_me: true,
        revoke_refresh_token: true,
        require_pushed_authorization_requests: true,
      },
      "realm settings",
    );

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast?briefRepresentation=false",
      expect.objectContaining({ headers: expect.any(Headers) }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({
          edit_user_name_allowed: true,
          remember_me: true,
          revoke_refresh_token: true,
          require_pushed_authorization_requests: true,
        }),
      }),
    );
  });
});
