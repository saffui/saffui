import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

const page = readFileSync(new URL("./SettingsPage.vue", import.meta.url), "utf8");

describe("realm settings layout", () => {
  test("spreads boolean settings into responsive cards", () => {
    expect(page).toContain("sm:grid-cols-2 xl:grid-cols-3");
    expect(page.match(/sf-toggle-card/g)?.length).toBeGreaterThanOrEqual(10);
  });

  test("uses three columns for dense numeric settings", () => {
    expect(page.match(/sm:grid-cols-2 lg:grid-cols-3/g)?.length).toBeGreaterThanOrEqual(3);
  });
});
