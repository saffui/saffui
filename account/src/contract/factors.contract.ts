import { describe, expect, test } from "vitest";
import {
  changePassword,
  checkRecentSignIn,
  listFactors,
  removeApp,
  removeRecoveryCodes,
} from "@/services/factors";
import { keepAnswer, REALM } from "./answers";

describe("the person's ways to sign in", () => {
  test("lists the password, the apps, the keys and the codes, to a recent sign-in", async () => {
    const factors = await keepAnswer(listFactors, REALM);
    expect(factors.password).toBe(true);
    expect(factors.apps.length).toBeGreaterThan(1);
    expect(factors.keys.length).toBeGreaterThan(0);
    expect(factors.recovery_codes).toBeGreaterThan(0);
    expect(factors.fresh_until).not.toBeNull();
    await expect(checkRecentSignIn(REALM)).resolves.toBeUndefined();
  });

  test("removes an app while other ways stay, then the codes", async () => {
    const spare = (await listFactors(REALM)).apps.find((app) => app.kept_because === null);
    if (!spare) throw new Error("the world holds no app that may go");
    await removeApp(REALM, spare.id);
    await expect(removeApp(REALM, spare.id)).rejects.toMatchObject({
      status: 404,
      code: "credential.not_found",
    });
    await removeRecoveryCodes(REALM);
    expect((await listFactors(REALM)).recovery_codes).toBe(0);
  });

  test("refuses a password change that does not prove the current password", async () => {
    await expect(
      changePassword(REALM, "not-the-current-password", "a-new-password-of-decent-length"),
    ).rejects.toMatchObject({ status: 422, code: "user.password.current_mismatch" });
  });
});
