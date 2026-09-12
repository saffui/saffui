import { describe, expect, test } from "vitest";
import { emptyTimeDraft, timeDraftFrom, timeWindowFrom } from "./timePolicy";

describe("time policy form", () => {
  test("sends UTC instants and every backend window field", () => {
    const draft = emptyTimeDraft();
    draft.not_before = "2026-09-12T09:30";
    draft.not_on_or_after = "2026-09-13T09:30";
    draft.hour = "9";
    draft.hour_end = "17";
    const written = timeWindowFrom(draft);
    expect(written).toMatchObject({
      not_before: Date.parse("2026-09-12T09:30:00Z") / 1000,
      not_on_or_after: Date.parse("2026-09-13T09:30:00Z") / 1000,
      hour: 9,
      hour_end: 17,
      minute: null,
      minute_end: null,
    });
    expect(timeDraftFrom(written!)).toMatchObject(draft);
  });

  test("rejects malformed numbers and dates before a request is sent", () => {
    const draft = emptyTimeDraft();
    draft.year = "20.5";
    expect(timeWindowFrom(draft)).toBeNull();
    draft.year = "2026";
    draft.not_before = "not a date";
    expect(timeWindowFrom(draft)).toBeNull();
    draft.not_before = "";
    draft.year = "";
    draft.year_end = "2027";
    expect(timeWindowFrom(draft)).toBeNull();
    draft.year_end = "";
    draft.year = "";
    expect(timeWindowFrom(draft)).toBeNull();
  });
});
