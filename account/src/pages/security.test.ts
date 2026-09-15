import { beforeEach, describe, expect, test, vi } from "vitest";

const calls = vi.hoisted(() => ({
  changePassword: vi.fn(async (_realm: string, _current: string, _replacement: string) => ({
    ended_sessions: 2,
  })),
  removeApp: vi.fn(async (_realm: string, _id: string) => {}),
  removeKey: vi.fn(async (_realm: string, _id: string) => {}),
  removeRecoveryCodes: vi.fn(async (_realm: string) => {}),
}));

vi.mock("@/services/factors", () => ({
  changePassword: calls.changePassword,
  removeApp: calls.removeApp,
  removeKey: calls.removeKey,
  removeRecoveryCodes: calls.removeRecoveryCodes,
}));

import type { OwnApp, OwnKey } from "@/services/factors";
import { ApiError, StepUpNeeded } from "@/services/http";
import {
  carryOutRemoval,
  checkPasswordForm,
  composeRemovalConfirmation,
  describeKeptBecause,
  describePasswordRefusal,
  formatDay,
  nameApp,
  submitPasswordChange,
} from "./security";

const APP: OwnApp = {
  id: "app-1",
  kind: "totp",
  label: null,
  created_at: "2026-09-01T10:00:00Z",
  kept_because: null,
};
const KEY: OwnKey = {
  id: "a2V5",
  label: "laptop",
  enrolled_at: "2026-09-02T10:00:00Z",
  last_used_at: null,
  kept_because: null,
};
const FORM = { current: "old", replacement: "new", again: "new" };
const LAST_SECOND_FACTOR = "this is the last second factor: add another before removing it";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("the password form", () => {
  test("is sent only with both passwords typed and the repeat matching", () => {
    expect(checkPasswordForm({ current: "", replacement: "new", again: "new" })).toBe("missing");
    expect(checkPasswordForm({ current: "old", replacement: "", again: "" })).toBe("missing");
    expect(checkPasswordForm({ current: "old", replacement: "new", again: "nwe" })).toBe(
      "mismatch",
    );
    expect(checkPasswordForm(FORM)).toBe("ready");
  });
});

describe("a password change", () => {
  test("says how many other sign-ins it ended", async () => {
    await expect(submitPasswordChange("main", FORM)).resolves.toEqual({
      tone: "ok",
      text: "Password changed. 2 other sign-ins ended.",
      stepUp: null,
    });
    expect(calls.changePassword).toHaveBeenCalledWith("main", "old", "new");
  });

  test("refused for want of a new sign-in passes on what the server asks", async () => {
    calls.changePassword.mockRejectedValueOnce(
      new StepUpNeeded({ error: "insufficient_user_authentication", acrValues: "password", maxAge: 300 }),
    );
    await expect(submitPasswordChange("main", FORM)).resolves.toMatchObject({
      tone: "danger",
      stepUp: { acrValues: "password", maxAge: 300 },
    });
  });

  test("says each refusal of the realm's rules in the console's words", () => {
    for (const said of [
      "the password is too short",
      "the password is too long",
      "the password needs more digits",
      "the password needs more capitals",
      "the password needs more small letters",
      "the password needs more punctuation",
      "the password is something about you",
      "the password is one this realm refuses",
      "the password does not match the shape this realm requires",
      "the password is one this account used before",
      "the current password is required",
      "a new password is required",
    ]) {
      const words = describePasswordRefusal(new ApiError(422, said, "validation_error"));
      expect(words, said).toMatch(/^[A-Z][^-]+[.]$/);
    }
    expect(
      describePasswordRefusal(new ApiError(422, "", "user.password.current_mismatch")),
    ).toMatch(/^The current password is not right/);
    expect(describePasswordRefusal(new ApiError(429, "", "user.locked_out"))).toMatch(/locked/);
    expect(describePasswordRefusal(new ApiError(409, "", "user.password.not_held_here"))).toMatch(
      /another service/,
    );
    expect(
      describePasswordRefusal(new ApiError(422, "a rule nobody knows", "validation_error")),
    ).toBe("a rule nobody knows");
  });
});

describe("removing a way to sign in", () => {
  test("removes what was chosen", async () => {
    await carryOutRemoval("main", { kind: "app", app: APP });
    await carryOutRemoval("main", { kind: "key", key: KEY });
    await carryOutRemoval("main", { kind: "recovery-codes", count: 3 });
    expect(calls.removeApp).toHaveBeenCalledWith("main", "app-1");
    expect(calls.removeKey).toHaveBeenCalledWith("main", "a2V5");
    expect(calls.removeRecoveryCodes).toHaveBeenCalledWith("main");
  });

  test("refused for want of a new sign-in passes on what the server asks", async () => {
    calls.removeKey.mockRejectedValueOnce(new StepUpNeeded({ maxAge: 300 }));
    await expect(carryOutRemoval("main", { kind: "key", key: KEY })).resolves.toMatchObject({
      tone: "danger",
      stepUp: { maxAge: 300 },
    });
  });

  test("the last way in stays, in the console's words, and one already gone is said calmly", async () => {
    calls.removeApp.mockRejectedValueOnce(
      new ApiError(409, LAST_SECOND_FACTOR, "account.last_factor"),
    );
    await expect(carryOutRemoval("main", { kind: "app", app: APP })).resolves.toEqual({
      tone: "danger",
      text: describeKeptBecause(LAST_SECOND_FACTOR),
      stepUp: null,
    });
    calls.removeApp.mockRejectedValueOnce(new ApiError(404, "gone", "credential.not_found"));
    await expect(carryOutRemoval("main", { kind: "app", app: APP })).resolves.toEqual({
      tone: "ok",
      text: "That was already removed. The list is up to date.",
      stepUp: null,
    });
  });

  test("the words before a removal name what goes", () => {
    expect(composeRemovalConfirmation({ kind: "app", app: APP }).title).toBe(
      "Remove Authenticator app?",
    );
    expect(composeRemovalConfirmation({ kind: "key", key: KEY }).title).toBe("Remove laptop?");
    expect(composeRemovalConfirmation({ kind: "recovery-codes", count: 3 }).body).toMatch(
      /^Your 3 codes stop working/,
    );
  });
});

describe("what the page shows", () => {
  test("an unnamed app is named by what it is, and a day reads in the console's tongue", () => {
    expect(nameApp(APP)).toBe("Authenticator app");
    expect(nameApp({ ...APP, label: "Phone" })).toBe("Phone");
    expect(formatDay("2026-09-15T12:00:00Z", "en")).toBe("Sep 15, 2026");
    expect(formatDay("not a day", "en")).toBe("");
    expect(formatDay(null, "en")).toBe("");
  });

  test("what keeps a way to sign in is said in the console's words", () => {
    expect(describeKeptBecause(LAST_SECOND_FACTOR)).toMatch(/^This is your last second step/);
    expect(describeKeptBecause("this key is the only way this account signs in")).toMatch(
      /^This key is the only way/,
    );
    expect(describeKeptBecause("an unknown reason")).toBe("an unknown reason");
  });
});
