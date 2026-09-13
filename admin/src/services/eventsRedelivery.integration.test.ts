import { afterEach, describe, expect, test, vi } from "vitest";

vi.mock("@/stores/session", () => ({
  useSession: () => ({ bearer: async () => "admin-token", signOut: vi.fn() }),
}));

const { redeliverToConnector } = await import("@/services/events");

afterEach(() => vi.unstubAllGlobals());

describe("connector redelivery transport", () => {
  test("names the connector in the path and sends the range and simulation flag", async () => {
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
      "/admin/realms/north%2Feast/identity-providers/audit%2Fwebhook/redeliveries",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          from_event_id: 12,
          to_event_id: 42,
          dry_run: true,
        }),
      }),
    );
  });
});
