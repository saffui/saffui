import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { writeRealmTheme } = await import("@/services/settings");
const { emptyTheme, themeDocument } = await import("./themeForm");

afterEach(() => vi.unstubAllGlobals());

describe("realm theme write path", () => {
  test("writes only explicit overrides to the escaped realm resource", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);
    const draft = emptyTheme();
    draft.light["brand-primary"] = "#C99433";
    draft.dark.bg = "#0B0A09";

    await writeRealmTheme("north/east", themeDocument(draft));

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/north%2Feast/theme",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({
          light: { "brand-primary": "#C99433" },
          dark: { bg: "#0B0A09" },
        }),
      }),
    );
  });
});
