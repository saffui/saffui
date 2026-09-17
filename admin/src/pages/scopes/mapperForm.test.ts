import { describe, expect, test } from "vitest";
import {
  asJson,
  fieldsOf,
  fromJson,
  missing,
  readFlag,
  readText,
  switchesOf,
  type Kinds,
} from "./mapperForm";

const KINDS: Kinds = {
  kinds: [
    {
      mapper_type: "oidc-usermodel-attribute-mapper",
      allowed: ["claim.name", "user.attribute", "multivalued", "jsonType.label"],
      required: ["claim.name", "user.attribute"],
      one_of: [],
      booleans: [{ key: "multivalued", resting: false }],
    },
    {
      mapper_type: "oidc-audience-mapper",
      allowed: ["included.client.audience", "included.custom.audience"],
      required: [],
      one_of: ["included.client.audience", "included.custom.audience"],
      booleans: [],
    },
    {
      mapper_type: "oidc-usermodel-client-role-mapper",
      allowed: [],
      required: [],
      one_of: [],
      booleans: [],
    },
  ],
  target_flags: [
    { key: "id.token.claim", resting: true },
    { key: "access.token.claim", resting: true },
    { key: "userinfo.token.claim", resting: true },
  ],
};

describe("the fields a rule offers", () => {
  test("are its own keys, marked as the rule marks them", () => {
    expect(fieldsOf(KINDS, "oidc-usermodel-attribute-mapper")).toEqual([
      { key: "claim.name", required: true, alternative: false },
      { key: "user.attribute", required: true, alternative: false },
      { key: "jsonType.label", required: false, alternative: false },
    ]);

    const audience = fieldsOf(KINDS, "oidc-audience-mapper");
    expect(audience.every((field) => field.alternative)).toBe(true);
    expect(audience.some((field) => field.required)).toBe(false);
  });

  /// A key the rule reads as a switch leaves the text fields, so nobody is
  /// asked to type `true` into a box.
  test("leave the switches to the switches", () => {
    expect(switchesOf(KINDS, "oidc-usermodel-attribute-mapper")).toEqual([
      { key: "multivalued", resting: false },
    ]);
    expect(switchesOf(KINDS, "oidc-audience-mapper")).toEqual([]);
    expect(switchesOf(KINDS, "oidc-invented-elsewhere")).toEqual([]);
  });

  /// The rule whose claim path is fixed offers nothing, and a name this build
  /// does not run offers nothing either rather than a guess.
  test("are none where the rule reads nothing", () => {
    expect(fieldsOf(KINDS, "oidc-usermodel-client-role-mapper")).toEqual([]);
    expect(fieldsOf(KINDS, "oidc-invented-elsewhere")).toEqual([]);
  });
});

describe("a flag", () => {
  /// The server takes a boolean or the string a JSON bag carries, so a rule
  /// written either way has to show the same switch.
  test("is read whichever way it was written", () => {
    expect(readFlag({ Bool: false }, true)).toBe(false);
    expect(readFlag({ Str: "false" }, true)).toBe(false);
    expect(readFlag({ Str: "TRUE" }, false)).toBe(true);
    expect(readFlag({ Str: "1" }, false)).toBe(true);
  });

  /// An absent value does not mean the same thing everywhere: a target flag
  /// absent rides everywhere, multivalued absent is a single value.
  test("absent means what the key says it means", () => {
    expect(readFlag(undefined, true)).toBe(true);
    expect(readFlag(undefined, false)).toBe(false);
  });
});

describe("what the door would refuse", () => {
  test("is said here first, in the same three ways", () => {
    expect(missing(KINDS, "oidc-usermodel-attribute-mapper", {
      "claim.name": { Str: "dept" },
      "user.attribute": { Str: "dept" },
    })).toEqual([]);

    expect(missing(KINDS, "oidc-usermodel-attribute-mapper", {
      "claim.name": { Str: "dept" },
    })).toEqual(["missing:user.attribute"]);

    expect(missing(KINDS, "oidc-usermodel-attribute-mapper", {
      "claim.name": { Str: "dept" },
      "user.attribute": { Str: "dept" },
      "included.custom.audience": { Str: "elsewhere" },
    })).toEqual(["unknown:included.custom.audience"]);

    expect(missing(KINDS, "oidc-audience-mapper", {})).toEqual([
      "one-of:included.client.audience,included.custom.audience",
    ]);
  });

  /// The flags every rule reads pass everywhere, including on the rule that
  /// reads nothing else.
  test("never counts a target flag as a stray", () => {
    expect(
      missing(KINDS, "oidc-usermodel-client-role-mapper", {
        "id.token.claim": { Bool: true },
      }),
    ).toEqual([]);
  });
});

describe("the escape hatch", () => {
  /// The fields and the text are two readings of one bag, so what is typed in
  /// one is what the other shows.
  test("carries the bag both ways without losing it", () => {
    const bag = { "claim.name": { Str: "dept" }, "multivalued": { Bool: true } };
    expect(fromJson(asJson(bag))).toEqual(bag);
  });

  test("refuses what is not a bag", () => {
    expect(fromJson("not json")).toBeNull();
    expect(fromJson("[1, 2]")).toBeNull();
    expect(fromJson("null")).toBeNull();
  });
});

describe("a value's text", () => {
  test("is shown whatever shape it was stored in", () => {
    expect(readText({ Str: "dept" })).toBe("dept");
    expect(readText({ Int: 12 })).toBe("12");
    expect(readText({ ListStr: ["a", "b"] })).toBe("a, b");
    expect(readText(undefined)).toBe("");
  });
});
