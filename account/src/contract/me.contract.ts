import { describe, expect, test } from "vitest";
import { readMe } from "@/services/me";
import { keepAnswer, REALM } from "./answers";

describe("the person", () => {
  test("reads what the realm holds of them, and never their subject", async () => {
    const me = await keepAnswer(readMe, REALM);
    expect(me.preferred_username).not.toBe("");
    expect(me).not.toHaveProperty("sub");
  });
});
