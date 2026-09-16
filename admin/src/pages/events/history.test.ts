import { describe, expect, test } from "vitest";
import { appendHistoryPage, readHistoryCursor } from "./history";

const told = (event_id: number) => ({
  event_id,
  kind: "user.created",
  user_id: "ada",
  occurred_at: "2026-09-15T10:00:00Z",
});

describe("the number a history read starts after", () => {
  test("is the oldest kept when nothing is typed", () => {
    expect(readHistoryCursor("")).toBe(0);
    expect(readHistoryCursor("   ")).toBe(0);
  });

  test("is the number typed, and nothing else is read as one", () => {
    expect(readHistoryCursor(" 42 ")).toBe(42);
    expect(readHistoryCursor("4.2")).toBeNull();
    expect(readHistoryCursor("4.0")).toBeNull();
    expect(readHistoryCursor("4.")).toBeNull();
    expect(readHistoryCursor("-1")).toBeNull();
    expect(readHistoryCursor("nine")).toBeNull();
    expect(readHistoryCursor("9007199254740992")).toBeNull();
  });
});

describe("a page of history", () => {
  test("is laid after what is shown, oldest first", () => {
    expect(appendHistoryPage([told(1), told(2)], [told(3), told(4)]).map((row) => row.event_id)).toEqual([
      1, 2, 3, 4,
    ]);
  });

  test("leaves an event already shown where it stands", () => {
    expect(appendHistoryPage([told(1), told(2)], [told(2), told(3)]).map((row) => row.event_id)).toEqual([
      1, 2, 3,
    ]);
  });
});
