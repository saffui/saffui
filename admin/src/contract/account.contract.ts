import { describe, expect, test } from "vitest";
import {
  changeOwnPassword,
  listOwnFactors,
  removeOwnApp,
  removeOwnKey,
  removeOwnRecoveryCodes,
} from "@/services/account";
import { keepAnswer, REALM } from "./answers";

describe("own account", () => {
  test("lists what the account signs in with", async () => {
    const factors = await keepAnswer(listOwnFactors, REALM);
    expect(factors.apps.length).toBeGreaterThan(0);
    expect(factors.keys.length).toBeGreaterThan(0);
  });

  test("asks for a recent sign-in before any factor goes", async () => {
    const factors = await listOwnFactors(REALM);
    const tooOld = { status: 403, code: "account.reauthentication_required" };
    await expect(removeOwnRecoveryCodes(REALM)).rejects.toMatchObject(tooOld);
    await expect(removeOwnApp(REALM, factors.apps[0].id)).rejects.toMatchObject(tooOld);
    await expect(removeOwnKey(REALM, factors.keys[0].id)).rejects.toMatchObject(tooOld);
  });

  test("refuses a password change that does not prove the current one", async () => {
    await expect(
      changeOwnPassword(REALM, "not-the-current-password", "a-new-password-of-decent-length"),
    ).rejects.toMatchObject({ status: 422, code: "user.password.current_mismatch" });
  });
});
