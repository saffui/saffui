import { expect, it } from "vitest";
import { canWriteAuthorization } from "./authorizationSetup";

it("holds policy creation until a selected client is protected", () => {
  expect(canWriteAuthorization("", false, false)).toBe(false);
  expect(canWriteAuthorization("web-dashboard", true, false)).toBe(false);
  expect(canWriteAuthorization("web-dashboard", false, true)).toBe(false);
  expect(canWriteAuthorization("web-dashboard", false, false)).toBe(true);
});
