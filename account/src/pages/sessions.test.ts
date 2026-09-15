import { beforeEach, describe, expect, test, vi } from "vitest";

const calls = vi.hoisted(() => ({
  endLogin: vi.fn(async (_realm: string, _session: string) => {}),
  endOtherLogins: vi.fn(async (_realm: string) => ({ ended_sessions: 2 })),
  revokeGrant: vi.fn(async (_realm: string, _session: string, _client: string) => {}),
  forgetSignIn: vi.fn(() => {}),
}));

vi.mock("@/services/sessions", () => ({
  endLogin: calls.endLogin,
  endOtherLogins: calls.endOtherLogins,
  revokeGrant: calls.revokeGrant,
}));
vi.mock("@/services/session", () => ({ forgetSignIn: calls.forgetSignIn }));

import { ApiError } from "@/services/http";
import type { HeldLogin } from "@/services/sessions";
import {
  carryOutGesture,
  composeConfirmation,
  countOtherLogins,
  describeDevice,
  formatMoment,
  orderLogins,
} from "./sessions";

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

const HERE = composeLogin({ session_id: "here", current: true });
const THERE = composeLogin({ session_id: "there", browser: "Chrome", system: "Android" });
const NEXTCLOUD = { client_id: "nextcloud", name: "Nextcloud", offline: true, expiration: null };

beforeEach(() => {
  vi.clearAllMocks();
});

describe("the person's logins", () => {
  test("put this browser's first, then the newest", () => {
    const ordered = orderLogins([
      composeLogin({ session_id: "old", started_at: 10 }),
      composeLogin({ session_id: "here", current: true, started_at: 5 }),
      composeLogin({ session_id: "new", started_at: 20 }),
    ]);
    expect(ordered.map((login) => login.session_id)).toEqual(["here", "new", "old"]);
  });

  test("count every login but this browser's, closed ones included", () => {
    expect(
      countOtherLogins([
        composeLogin({ current: true }),
        composeLogin({}),
        composeLogin({ open: false }),
        composeLogin({ open: false }),
      ]),
    ).toBe(3);
    expect(countOtherLogins([composeLogin({ current: true })])).toBe(0);
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

describe("a gesture on the logins", () => {
  test("ending this browser's login forgets the sign-in here and signs the page out", async () => {
    await expect(carryOutGesture("main", { kind: "end", login: HERE })).resolves.toMatchObject({
      tone: "ok",
      signedOut: true,
    });
    expect(calls.endLogin).toHaveBeenCalledWith("main", "here");
    expect(calls.forgetSignIn).toHaveBeenCalledTimes(1);
  });

  test("ending a login elsewhere keeps the sign-in here", async () => {
    await expect(carryOutGesture("main", { kind: "end", login: THERE })).resolves.toEqual({
      tone: "ok",
      text: "The sign-in ended.",
      signedOut: false,
    });
    expect(calls.endLogin).toHaveBeenCalledWith("main", "there");
    expect(calls.forgetSignIn).not.toHaveBeenCalled();
  });

  test("signing out everywhere else says how many ended", async () => {
    await expect(carryOutGesture("main", { kind: "end-others" })).resolves.toEqual({
      tone: "ok",
      text: "2 other sign-ins ended.",
      signedOut: false,
    });
    expect(calls.endOtherLogins).toHaveBeenCalledWith("main");
  });

  test("taking back what an application got names the application", async () => {
    await expect(
      carryOutGesture("main", { kind: "take-back", login: THERE, grant: NEXTCLOUD }),
    ).resolves.toEqual({
      tone: "ok",
      text: "Nextcloud no longer holds access through that sign-in.",
      signedOut: false,
    });
    expect(calls.revokeGrant).toHaveBeenCalledWith("main", "there", "nextcloud");
    expect(calls.endLogin).not.toHaveBeenCalled();
  });

  test("something already gone is said calmly, and a failure is said plainly", async () => {
    calls.endLogin.mockRejectedValueOnce(new ApiError(404, "gone", "auth.session.not_found"));
    await expect(carryOutGesture("main", { kind: "end", login: HERE })).resolves.toEqual({
      tone: "ok",
      text: "That had already ended. The list is up to date.",
      signedOut: false,
    });
    expect(calls.forgetSignIn).not.toHaveBeenCalled();
    calls.revokeGrant.mockRejectedValueOnce(new ApiError(500, "broken", "internal_error"));
    await expect(
      carryOutGesture("main", { kind: "take-back", login: THERE, grant: NEXTCLOUD }),
    ).resolves.toMatchObject({ tone: "danger", signedOut: false });
  });
});

describe("the words before a gesture", () => {
  test("say that this browser signs out, or which device does", () => {
    expect(composeConfirmation({ kind: "end", login: HERE }).title).toBe(
      "Sign out of this browser?",
    );
    expect(composeConfirmation({ kind: "end", login: THERE }).body).toMatch(
      /^Chrome on Android is signed out/,
    );
    expect(composeConfirmation({ kind: "end-others" }).body).toContain(
      "This browser stays signed in.",
    );
  });

  test("say what taking back access leaves standing", () => {
    const words = composeConfirmation({ kind: "take-back", login: THERE, grant: NEXTCLOUD });
    expect(words.title).toBe("Take back Nextcloud's access?");
    expect(words.body).toContain("This page stays signed in.");
  });
});
