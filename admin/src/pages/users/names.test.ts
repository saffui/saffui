import { describe, expect, test } from "vitest";

import { NAME_LIMIT, refusalOf } from "./names";

describe("what the server will take as a user name", () => {
  test("takes the ordinary ones", () => {
    for (const held of ["ada", "kwame.b", "a", "user-1_2", "\u00e9", "ada@example.test"]) {
      expect(refusalOf(held), held).toBe(null);
    }
  });

  test("refuses a name with nothing in it", () => {
    expect(refusalOf("")).toBe("empty");
  });

  test("refuses a space anywhere, not only at the ends", () => {
    expect(refusalOf("ada lovelace")).toBe("spaced");
    expect(refusalOf(" ada")).toBe("spaced");
    expect(refusalOf("ada\tb")).toBe("spaced");
  });

  test("refuses a control character, which a paste carries invisibly", () => {
    expect(refusalOf("ada\u0007")).toBe("control");
    expect(refusalOf("ada\u007f")).toBe("control");
  });

  test("counts to the same limit the server counts to", () => {
    expect(refusalOf("a".repeat(NAME_LIMIT))).toBe(null);
    expect(refusalOf("a".repeat(NAME_LIMIT + 1))).toBe("long");
  });
});
