import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { readProtectedServer, setProtection, shareResource, unprotectClient, unshareResource } =
  await import("@/services/authz");

afterEach(() => vi.unstubAllGlobals());

const SERVER = "/admin/realms/north%2Feast/authz/servers/my%20api";
const SHARE = { relation: "viewer", subject_type: "user", subject_id: "ada", subject_relation: "" };

describe("a protected client", () => {
  test("is read, changed and let go at its own encoded address", async () => {
    const fetch = vi.fn().mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            server_id: "my api",
            enforcement_mode: "enforcing",
            decision_strategy: "affirmative",
            remote_resource_management: false,
            user_managed_access: true,
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetch);

    await readProtectedServer("north/east", "my api");
    await setProtection("north/east", "my api", {
      enforcement_mode: "permissive",
      decision_strategy: "unanimous",
      user_managed_access: true,
    });
    await unprotectClient("north/east", "my api");

    expect(fetch).toHaveBeenNthCalledWith(1, SERVER, expect.anything());
    expect(fetch.mock.calls[0]?.[1]?.method ?? "GET").toBe("GET");
    expect(fetch).toHaveBeenNthCalledWith(2, SERVER, expect.objectContaining({ method: "PUT" }));
    expect(String(fetch.mock.calls[1]?.[1]?.body)).toContain("permissive");
    expect(fetch).toHaveBeenNthCalledWith(3, SERVER, expect.objectContaining({ method: "DELETE" }));
  });

  test("shares one of its resources and takes the share back at the same address", async () => {
    const fetch = vi.fn().mockImplementation(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);

    await shareResource("north/east", "my api", "r 1", SHARE);
    await unshareResource("north/east", "my api", "r 1", SHARE);

    const address = `${SERVER}/resources/r%201/shares`;
    expect(fetch).toHaveBeenNthCalledWith(1, address, expect.objectContaining({ method: "POST" }));
    expect(fetch).toHaveBeenNthCalledWith(2, address, expect.objectContaining({ method: "DELETE" }));
    for (const call of fetch.mock.calls) {
      expect(String(call[1]?.body)).toContain('"relation":"viewer"');
    }
  });
});
