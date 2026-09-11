import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const {
  addCompositeRole,
  addOrganizationMember,
  listCompositeRoles,
  removeCompositeRole,
  removeOrganizationMember,
} = await import("@/services/directory");
const { revokeSessionGrant, withdrawConsent } = await import("@/services/users");
const { attachMapperToClient, detachMapperFromClient } = await import("@/services/clients");

afterEach(() => vi.unstubAllGlobals());

function transport() {
  const fetch = vi.fn().mockImplementation((_path: string, init: RequestInit) => {
    if ((init.method ?? "GET") === "GET") {
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(null, { status: 204 });
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

describe("directory admin action transport", () => {
  test("uses isolated organization member endpoints", async () => {
    const fetch = transport();

    await addOrganizationMember("north/east", "org/acme", "user/ada");
    await removeOrganizationMember("north/east", "org/acme", "user/ada");

    const path = "/admin/realms/north%2Feast/organizations/org%2Facme/members/user%2Fada";
    expect(fetch).toHaveBeenNthCalledWith(1, path, expect.objectContaining({ method: "PUT" }));
    expect(fetch).toHaveBeenNthCalledWith(2, path, expect.objectContaining({ method: "DELETE" }));
  });

  test("lists and changes direct role composites", async () => {
    const fetch = transport();

    await listCompositeRoles("north/east", "role/admin");
    await addCompositeRole("north/east", "role/admin", "role/reader");
    await removeCompositeRole("north/east", "role/admin", "role/reader");

    const root = "/admin/realms/north%2Feast/roles/role%2Fadmin/composites";
    expect(fetch).toHaveBeenNthCalledWith(1, root, expect.anything());
    expect(fetch).toHaveBeenNthCalledWith(2, `${root}/role%2Freader`, expect.objectContaining({ method: "PUT" }));
    expect(fetch).toHaveBeenNthCalledWith(3, `${root}/role%2Freader`, expect.objectContaining({ method: "DELETE" }));
  });
});

describe("user admin action transport", () => {
  test("revokes one session grant and one client consent", async () => {
    const fetch = transport();

    await revokeSessionGrant("north/east", "user/ada", "session/one", "client/web");
    await withdrawConsent("north/east", "user/ada", "client/web");

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/users/user%2Fada/sessions/session%2Fone/grants/client%2Fweb",
      expect.objectContaining({ method: "DELETE" }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/users/user%2Fada/consents/client%2Fweb",
      expect.objectContaining({ method: "DELETE" }),
    );
  });
});

describe("client mapper action transport", () => {
  test("attaches and detaches an existing realm mapper", async () => {
    const fetch = transport();

    await attachMapperToClient("north/east", "client/web", "mapper/email");
    await detachMapperFromClient("north/east", "client/web", "mapper/email");

    const path = "/admin/realms/north%2Feast/clients/client%2Fweb/mappers/mapper%2Femail";
    expect(fetch).toHaveBeenNthCalledWith(1, path, expect.objectContaining({ method: "PUT" }));
    expect(fetch).toHaveBeenNthCalledWith(2, path, expect.objectContaining({ method: "DELETE" }));
  });
});
