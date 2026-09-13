import { describe, expect, test } from "vitest";
import { ownPasswordReady, passwordKeptHere } from "./ownPassword";
import { previewAnswer } from "@/services/preview";

describe("changing one's own password", () => {
  test("waits for the current password and the new one", () => {
    expect(ownPasswordReady({ current: "", replacement: "fresh", again: "fresh" })).toBe("missing");
    expect(ownPasswordReady({ current: "worn", replacement: "", again: "" })).toBe("missing");
  });

  test("refuses a confirmation that differs", () => {
    expect(ownPasswordReady({ current: "worn", replacement: "fresh", again: "Fresh" })).toBe(
      "mismatch",
    );
  });

  test("sends a complete form", () => {
    expect(ownPasswordReady({ current: "worn", replacement: "fresh", again: "fresh" })).toBe(
      "ready",
    );
  });

  test("offers no change where a directory keeps the password", () => {
    expect(passwordKeptHere({ origin: "ldap" })).toBe(false);
    expect(passwordKeptHere({ origin: "local" })).toBe(true);
    expect(passwordKeptHere({ origin: null })).toBe(true);
  });

  test("the preview world answers the change with the sessions it ended", () => {
    expect(
      previewAnswer("/admin/realms/main/account/password", "PUT", {
        current_password: "worn",
        new_password: "fresh",
      }),
    ).toEqual({ ended_sessions: 1 });
  });
});
