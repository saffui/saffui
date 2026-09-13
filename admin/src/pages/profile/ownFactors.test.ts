import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { OWN_FACTORS } from "./ownFactors";

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
});
