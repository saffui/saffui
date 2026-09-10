import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { importDirectory, putDirectory } = await import("@/services/federation");
const { directoryMutation, emptyDirectoryDraft } = await import("./directoryForms");

afterEach(() => vi.unstubAllGlobals());

describe("directory federation write path", () => {
  test("writes an encoded directory and imports it through the authenticated API", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ alias: "corp/eu" }), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ imported: 3, refreshed: 7, walked: 10 }), { status: 200 }),
      );
    vi.stubGlobal("fetch", fetch);

    const draft = emptyDirectoryDraft();
    draft.alias = "corp/eu";
    draft.url = "ldaps://directory.example:636";
    draft.bindDn = "cn=reader,dc=example";
    draft.bindPassword = "held-secret";
    draft.usersDn = "ou=people,dc=example";

    await putDirectory("north/east", draft.alias, directoryMutation(draft));
    const report = await importDirectory("north/east", draft.alias);

    expect(fetch).toHaveBeenNthCalledWith(
      1,
      "/admin/realms/north%2Feast/federations/corp%2Feu",
      expect.objectContaining({
        method: "PUT",
        body: expect.stringContaining('"bind_password":{"Str":"held-secret"}'),
      }),
    );
    expect(fetch).toHaveBeenNthCalledWith(
      2,
      "/admin/realms/north%2Feast/federations/corp%2Feu/import",
      expect.objectContaining({ method: "POST" }),
    );
    for (const [, init] of fetch.mock.calls) {
      expect((init.headers as Headers).get("authorization")).toBe("Bearer admin-token");
    }
    expect(report).toEqual({ imported: 3, refreshed: 7, walked: 10 });
  });
});
