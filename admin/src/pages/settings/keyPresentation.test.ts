import { describe, expect, test } from "vitest";
import { groupKeys, keyCanBeRemoved, keyCreatedAt, publishedKeyCount } from "./keyPresentation";

describe("realm key presentation", () => {
  test("groups algorithms and leads each group with its highest priority", () => {
    const groups = groupKeys([
      { kid: "old", algorithm: "ES256", status: "passive", priority: 10 },
      { kid: "rsa", algorithm: "RS256", status: "active", priority: 12 },
      { kid: "new", algorithm: "ES256", status: "active", priority: 13 },
    ]);

    expect(groups.map((group) => group.algorithm)).toEqual(["ES256", "RS256"]);
    expect(groups[0]?.keys.map((key) => key.kid)).toEqual(["new", "old"]);
  });

  test("counts active and passive keys as published", () => {
    expect(
      publishedKeyCount([
        { kid: "active", algorithm: "ES256", status: "active" },
        { kid: "passive", algorithm: "ES256", status: "passive" },
        { kid: "disabled", algorithm: "ES256", status: "disabled" },
      ]),
    ).toBe(2);
  });

  test("offers removal only for keys no longer active", () => {
    expect(keyCanBeRemoved({ kid: "active", algorithm: "ES256", status: "active" })).toBe(false);
    expect(keyCanBeRemoved({ kid: "passive", algorithm: "ES256", status: "passive" })).toBe(true);
    expect(keyCanBeRemoved({ kid: "disabled", algorithm: "ES256", status: "disabled" })).toBe(false);
  });

  test("reads backend epoch seconds without accepting invalid dates", () => {
    expect(keyCreatedAt({ kid: "a", algorithm: "ES256", status: "active", created_at: 1 })?.toISOString()).toBe(
      "1970-01-01T00:00:01.000Z",
    );
    expect(keyCreatedAt({ kid: "b", algorithm: "ES256", status: "active" })).toBeNull();
  });
});
