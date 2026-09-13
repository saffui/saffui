import { describe, expect, test } from "vitest";
import { listOwnFactors, removeOwnRecoveryCodes } from "@/services/account";
import { getRealmKeys, getRealmSettings } from "@/services/settings";
import { keepAnswer, REALM } from "./answers";

describe("own account", () => {
  test("lists what the account signs in with", async () => {
    const factors = await keepAnswer(listOwnFactors, REALM);
    expect(factors.apps.length).toBeGreaterThan(0);
  });

  test("asks for a recent sign-in before a factor goes", async () => {
    await expect(removeOwnRecoveryCodes(REALM)).rejects.toMatchObject({
      status: 403,
      code: "account.reauthentication_required",
    });
  });
});

describe("realm settings", () => {
  test("reads the settings and the keys", async () => {
    await keepAnswer(getRealmSettings, REALM);
    const keys = await keepAnswer(getRealmKeys, REALM);
    expect(keys.signing.length).toBeGreaterThan(0);
  });
});
