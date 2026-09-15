import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { readEventHistory } = await import("@/services/events");

afterEach(() => vi.unstubAllGlobals());

describe("a page of the realm's event history", () => {
  test("is read after a number, under the realm's encoded name", async () => {
    const fetch = vi.fn().mockImplementation(
      async () =>
        new Response(JSON.stringify({ items: [], next_event_id: null, more: false }), {
          status: 200,
        }),
    );
    vi.stubGlobal("fetch", fetch);

    await readEventHistory("north/east", 41, 25);

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/north%2Feast/events/replay?after_event_id=41&limit=25",
      expect.anything(),
    );
  });
});
