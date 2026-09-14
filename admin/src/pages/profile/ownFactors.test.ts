import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { OWN_FACTORS, freshEnough, signInNeededBeforeRemoval } from "./ownFactors";
import { previewAnswer } from "@/services/preview";

const i18n = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "i18n");

describe("the factors a person adds to their own account", () => {
  test("are exactly the ceremonies the server lets an application ask for", () => {
    expect([...OWN_FACTORS]).toEqual([
      "configure-totp",
      "configure-webauthn",
      "configure-recovery-codes",
    ]);
  });

  test("each has its words in every tongue the console speaks", () => {
    for (const tongue of ["en", "fr"]) {
      const words = readFileSync(join(i18n, `${tongue}.ftl`), "utf8");
      for (const factor of OWN_FACTORS) {
        expect(words, `${tongue} has no words for ${factor}`).toContain(
          `\nprofile-factor-${factor} = `,
        );
      }
    }
  });

  test("a sign-in removes a factor only until the moment the server gave", () => {
    expect(freshEnough(1000, 999)).toBe(true);
    expect(freshEnough(1000, 1000)).toBe(true);
    expect(freshEnough(1000, 1001)).toBe(false);
    expect(freshEnough(null, 0)).toBe(false);
  });

  test("asks for a stronger sign-in before a recent but weaker one removes a factor", () => {
    expect(
      signInNeededBeforeRemoval({ fresh_until: null, stronger_sign_in_needed: true }, 1000),
    ).toBe("stronger");
    expect(
      signInNeededBeforeRemoval({ fresh_until: null, stronger_sign_in_needed: false }, 1000),
    ).toBe("recent");
    expect(
      signInNeededBeforeRemoval({ fresh_until: 999, stronger_sign_in_needed: false }, 1000),
    ).toBe("recent");
    expect(
      signInNeededBeforeRemoval({ fresh_until: 1300, stronger_sign_in_needed: false }, 1000),
    ).toBeNull();
  });

  test("the preview world lists factors and takes a removal", () => {
    const held = previewAnswer<{ apps: unknown[]; keys: unknown[] }>(
      "/admin/realms/main/account/credentials",
      "GET",
    );
    expect(held.apps.length).toBeGreaterThan(0);
    expect(held.keys.length).toBeGreaterThan(0);
    expect(previewAnswer("/admin/realms/main/account/recovery-codes", "DELETE")).toBeUndefined();
  });
});
