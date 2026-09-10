import { describe, expect, test } from "vitest";
import { parseLiveFrame } from "./events";

describe("live event frames", () => {
  test("reads the SSE id and JSON data without requiring EventSource", () => {
    expect(parseLiveFrame("event: login\nid: 42\ndata: {\"kind\":\"login\",\"user_id\":\"ada\",\"occurred_at\":\"now\"}\n"))
      .toEqual({ event_id: 42, kind: "login", user_id: "ada", occurred_at: "now" });
    expect(parseLiveFrame(": keep-alive\n")).toBeNull();
  });
});
