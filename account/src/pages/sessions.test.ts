import { describe, expect, test } from "vitest";
import type { HeldLogin } from "@/services/sessions";
import { countOtherLogins, describeDevice, formatMoment, orderLogins } from "./sessions";

function composeLogin(held: Partial<HeldLogin>): HeldLogin {
  return {
    session_id: "s",
    current: false,
    open: true,
    auth_method: "browser",
    provider: null,
    ip_address: null,
    browser: null,
    system: null,
    mobile: false,
    started_at: 0,
    auth_time: null,
    expiration: null,
    grants: [],
    ...held,
  };
}

describe("the person's logins", () => {
  test("put this browser's first, then the newest", () => {
    const ordered = orderLogins([
      composeLogin({ session_id: "old", started_at: 10 }),
      composeLogin({ session_id: "here", current: true, started_at: 5 }),
      composeLogin({ session_id: "new", started_at: 20 }),
    ]);
    expect(ordered.map((login) => login.session_id)).toEqual(["here", "new", "old"]);
  });

  test("count every login but this browser's, a closed one included", () => {
    expect(
      countOtherLogins([
        composeLogin({ current: true }),
        composeLogin({}),
        composeLogin({ open: false }),
      ]),
    ).toBe(2);
  });
});

describe("a device", () => {
  test("is named by its browser and its system, as far as the browser said them", () => {
    expect(describeDevice(composeLogin({ browser: "Firefox", system: "Linux" }))).toBe(
      "Firefox on Linux",
    );
    expect(describeDevice(composeLogin({ browser: "Safari" }))).toBe("Safari");
    expect(describeDevice(composeLogin({ system: "Android" }))).toBe("Android");
    expect(describeDevice(composeLogin({}))).toBe("Unknown device");
  });
});

describe("a moment", () => {
  test("reads as a date and a time in the console's tongue", () => {
    const noon = Date.UTC(2026, 8, 15, 12) / 1000;
    expect(formatMoment(noon, "en")).toMatch(/^Sep 15, 2026, \d/);
    expect(formatMoment(noon, "fr")).toMatch(/^15 sept\. 2026, \d/);
  });
});
