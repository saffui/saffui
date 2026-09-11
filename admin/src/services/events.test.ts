import { describe, expect, test } from "vitest";
import { parseLiveEventFrame, withLiveEvent } from "./events";

describe("live event frames", () => {
  test("reads the SSE id and JSON data without requiring EventSource", () => {
    expect(parseLiveEventFrame("event: login\nid: 42\ndata: {\"kind\":\"login\",\"user_id\":\"ada\",\"occurred_at\":\"now\"}\n"))
      .toEqual({ event_id: 42, kind: "login", user_id: "ada", occurred_at: "now" });
    expect(parseLiveEventFrame(": keep-alive\n")).toBeNull();
  });
});

describe("the live feed's frames", () => {
  const frame = (event_id: number) => ({ event_id, kind: "login", user_id: "ada", occurred_at: "now" });

  test("put the newest first", () => {
    expect(withLiveEvent([frame(1)], frame(2)).map((row) => row.event_id)).toEqual([2, 1]);
  });

  test("keep an event already shown where it stands, instead of raising it as the newest", () => {
    expect(withLiveEvent([frame(3), frame(2), frame(1)], frame(2)).map((row) => row.event_id)).toEqual([3, 2, 1]);
  });

  test("hold no more than they are asked to", () => {
    expect(withLiveEvent([frame(2), frame(1)], frame(3), 2).map((row) => row.event_id)).toEqual([3, 2]);
  });
});
