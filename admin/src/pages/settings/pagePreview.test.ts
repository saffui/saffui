import { describe, expect, test } from "vitest";
import { LOOKABLE, packed, previewPath, saysAnything } from "./pagePreview";

describe("what is worth keeping", () => {
  /// One packer for saving and for previewing. Packed any other way, a draft
  /// would show a page that saving would not produce.
  test("drops what was typed and rubbed out again", () => {
    expect(
      packed({
        en: { "login-title": "  Come in  ", "login-password": "   ", "login-username": "" },
        fr: {},
      }),
    ).toEqual({ en: { "login-title": "Come in" } });
  });

  test("keeps no tongue that says nothing", () => {
    expect(packed({ en: { "login-title": " " }, fr: {} })).toEqual({});
    expect(saysAnything({ en: { "login-title": " " }, fr: {} })).toBe(false);
    expect(saysAnything({ en: { "login-title": "Come in" }, fr: {} })).toBe(true);
  });
});

describe("where a page is shown", () => {
  test("names the realm and the page, and the draft only when there is one", () => {
    expect(previewPath("main", "login")).toBe(
      "/realms/main/protocol/openid-connect/page-preview/login",
    );
    expect(previewPath("main", "reset", "a1b2")).toBe(
      "/realms/main/protocol/openid-connect/page-preview/reset?draft=a1b2",
    );
  });

  /// A realm name is whatever somebody called it, and it rides in a path.
  test("escapes a realm whose name is not a path", () => {
    expect(previewPath("odd/name", "login")).toBe(
      "/realms/odd%2Fname/protocol/openid-connect/page-preview/login",
    );
  });

  test("offers the four pages this build renders", () => {
    expect([...LOOKABLE]).toEqual(["login", "device", "requests", "reset"]);
  });
});
