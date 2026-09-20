import { describe, expect, test } from "vitest";
import { ACCEPTED, LARGEST, markPath, refuses } from "./realmMark";

describe("where a mark is drawn from", () => {
  /// The address never changes, so without a counter a browser redraws the
  /// copy it holds and somebody who just replaced their logo sees the old one.
  test("carries a counter so a replaced mark is fetched again", () => {
    expect(markPath("main", 0)).toBe("/realms/main/protocol/openid-connect/logo");
    expect(markPath("main", 3)).toBe("/realms/main/protocol/openid-connect/logo?drawn=3");
  });

  test("escapes a realm whose name is not a path", () => {
    expect(markPath("odd/name", 0)).toBe("/realms/odd%2Fname/protocol/openid-connect/logo");
  });
});

describe("what is refused before anything is sent", () => {
  test("says the two things the door says, and apart", () => {
    expect(refuses({ size: 1024, type: "image/png" })).toBe("");
    expect(refuses({ size: LARGEST + 1, type: "image/png" })).toBe("too-big");
    expect(refuses({ size: 10, type: "text/plain" })).toBe("not-a-picture");
  });

  /// Absent from the dialog on purpose: served from the server's own origin a
  /// drawing is a document that runs its own script.
  test("never offers a drawing that can carry a script", () => {
    expect(ACCEPTED).not.toContain("svg");
    expect(refuses({ size: 10, type: "image/svg+xml" })).toBe("not-a-picture");
  });

  /// Size before format, so a huge drawing is named for the rule an operator
  /// can act on first.
  test("names the size before the format", () => {
    expect(refuses({ size: LARGEST + 1, type: "image/svg+xml" })).toBe("too-big");
  });
});
