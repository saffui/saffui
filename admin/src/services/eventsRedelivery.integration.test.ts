import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { redeliverToConnector } = await import("@/services/events");

afterEach(() => vi.unstubAllGlobals());

describe("connector redelivery transport", () => {
  test("sends the connector, range and simulation flag to the replay endpoint", async () => {
    const result = {
      dry_run: true,
      would_deliver: 8,
      stopped_at: 42,
      more: false,
    };
    const fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(result), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(
      redeliverToConnector(
        "north/east",
        "audit/webhook",
        { fromEventId: 12, toEventId: 42 },
        { dryRun: true },
      ),
    ).resolves.toEqual(result);

    expect(fetch).toHaveBeenCalledWith(
      "/admin/realms/north%2Feast/events/replay",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          connector: "audit/webhook",
          from_event_id: 12,
          to_event_id: 42,
          dry_run: true,
        }),
      }),
    );
  });
});
