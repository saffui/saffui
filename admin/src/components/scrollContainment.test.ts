import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

function source(path: string) {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

describe("scroll containment", () => {
  test("anchors screen-reader-only toggles inside their control", () => {
    expect(source("./AppToggle.vue")).toContain('<label class="relative flex');
  });

  test("keeps page scrolling inside the console main area", () => {
    const shell = source("./layout/ConsoleShell.vue");

    expect(shell).toContain('class="flex h-full overflow-hidden"');
    expect(shell).toContain('class="flex min-h-0 min-w-0 flex-1 flex-col"');
  });

  test("anchors the remaining hidden inputs inside positioned controls", () => {
    expect(source("../pages/profile/ProfilePage.vue")).toContain(
      '<form v-else class="relative mt-2',
    );
    expect(source("../pages/settings/ThemePage.vue")).toContain(
      'class="relative cursor-pointer',
    );
    expect(source("../pages/settings/SettingsPage.vue")).toContain(
      'sf-button sf-button-secondary relative',
    );
  });
});
