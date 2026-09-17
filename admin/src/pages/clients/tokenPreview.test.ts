import { describe, expect, test } from "vitest";
import { asMoment, headerLines, linesOf, render, windowOf } from "./tokenPreview";
import type { Foreseen } from "@/services/clients";

const FORESEEN: Foreseen = {
  scope: "openid profile",
  access: {
    header: { alg: "ES256", typ: "at+jwt", kid: "k-1" },
    body: {
      iss: "https://saffui.example/realms/main",
      sub: "ada",
      aud: ["app"],
      jti: "",
      sid: "",
      iat: 1_800_000_000,
      exp: 1_800_000_300,
      typ: "Bearer",
      scope: "openid profile",
      department: "engineering",
    },
  },
  identity: null,
  authors: { department: "department claim" },
  drawn_at_issuance: ["jti", "sid"],
};

describe("a body's lines", () => {
  test("name the mapper that wrote a claim, and nobody for the rest", () => {
    const lines = linesOf(FORESEEN.access, FORESEEN);
    const written = lines.find((line) => line.key === "department");
    expect(written?.author).toBe("department claim");
    expect(lines.find((line) => line.key === "iss")?.author).toBe("");
  });

  /// A claim drawn at issuance shows a stand-in, so it has to be marked or a
  /// reader takes the empty value for the one they will be handed.
  test("mark what only exists once a token is minted", () => {
    const lines = linesOf(FORESEEN.access, FORESEEN);
    expect(lines.filter((line) => line.drawn).map((line) => line.key)).toEqual(["jti", "sid"]);
  });

  test("carry the header too, which nobody but the key writes", () => {
    expect(headerLines(FORESEEN.access)).toEqual([
      { key: "alg", value: '"ES256"', author: "", drawn: false },
      { key: "typ", value: '"at+jwt"', author: "", drawn: false },
      { key: "kid", value: '"k-1"', author: "", drawn: false },
    ]);
  });
});

describe("a value", () => {
  /// A reader has to tell "1" from 1 to know what a client will be handed.
  test("is rendered as the token carries it", () => {
    expect(render("engineering")).toBe('"engineering"');
    expect(render(1)).toBe("1");
    expect(render(["a", "b"])).toBe('["a","b"]');
    expect(render(true)).toBe("true");
    expect(render(undefined)).toBe("null");
  });
});

describe("the claims that bound a token", () => {
  test("are read as moments, and nothing else is", () => {
    expect(asMoment("exp", 1_800_000_300)).toBe("2027-01-15 08:05:00Z");
    expect(asMoment("iat", 1_800_000_000)).toBe("2027-01-15 08:00:00Z");
    /// A claim that merely holds a number is not a time, and saying so would
    /// relabel what somebody wrote.
    expect(asMoment("department", 1_800_000_000)).toBe("");
    expect(asMoment("exp", "soon")).toBe("");
  });

  test("measure the window between them", () => {
    expect(windowOf(FORESEEN.access)).toBe(300);
    expect(windowOf({ header: {}, body: { iat: 1 } })).toBeNull();
  });
});
