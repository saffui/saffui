import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { effectScope, nextTick } from "vue";
import { describe, expect, test } from "vitest";

import { afterWrites, wroteSomething } from "./writes";

describe("what a screen shows after a write lands", () => {
  test("a watching screen re-reads, once per write, and stops when it goes", async () => {
    const scope = effectScope();
    let reread = 0;
    scope.run(() => afterWrites(() => (reread += 1)));

    wroteSomething();
    await nextTick();
    expect(reread).toBe(1);

    scope.stop();
    wroteSomething();
    await nextTick();
    expect(reread).toBe(1);
  });
});

/// The wiring is one line per screen, which is one line per screen that can
/// be forgotten. This walks the pages instead of trusting that nobody did.
///
/// Named here are the screens that must NOT re-read on somebody else's
/// write, each with the reason: a form would throw away what its operator
/// is typing, and a tool answers when it is asked rather than on its own.
const EXCUSED: Record<string, string> = {
  "login/LoginPage.vue": "a sign-in screen reads nothing of the realm",
  "login/ReturnPage.vue": "the return leg spends a code, once",
  "clients/TokenPreviewPage.vue": "a tool mints when asked, not when something else writes",
  "settings/SettingsPage.vue": "a form would discard what is being typed into it",
  "settings/PagesPage.vue": "a form would discard what is being typed into it",
  "settings/ThemePage.vue": "a form would discard what is being typed into it",
  "clients/ClientDrawer.vue": "a drawer re-reads after its own writes, keeping its tabs",
  "users/UserDrawer.vue": "a drawer re-reads after its own writes, keeping its tabs",
  "federation/IdpDrawer.vue": "a drawer re-reads after its own writes, keeping its tabs",
};

function everyScreen(at: string, under = ""): string[] {
  return readdirSync(at, { withFileTypes: true }).flatMap((held) =>
    held.isDirectory()
      ? everyScreen(join(at, held.name), `${under}${held.name}/`)
      : held.name.endsWith(".vue")
        ? [`${under}${held.name}`]
        : [],
  );
}

describe("every screen that reads the plane", () => {
  const pages = join(dirname(fileURLToPath(import.meta.url)), "..", "pages");
  for (const leaf of everyScreen(pages)) {
    const source = readFileSync(join(pages, leaf), "utf8");
    // A screen that names no service reads nothing that a write can stale.
    if (!source.includes('from "@/services/')) continue;
    test(`${leaf} follows the writes, or says why not`, () => {
      const follows = source.includes("afterWrites(");
      if (EXCUSED[leaf]) {
        expect(
          follows,
          `${leaf} is excused (${EXCUSED[leaf]}) but follows the writes anyway`,
        ).toBe(false);
        return;
      }
      expect(
        follows,
        `${leaf} reads the plane but never re-reads: a list that shows what is ` +
          "no longer there is lying. Call afterWrites(load), or excuse it here with a reason.",
      ).toBe(true);
    });
  }
});
