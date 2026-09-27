import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

function source(path: string) {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

describe("console visual language", () => {
  test("gives people and groups distinct silhouettes", () => {
    const icons = source("../AppIcon.vue");

    expect(icons).toContain("users: UserRound");
    expect(icons).toContain("groups: UsersRound");
  });

  test("uses structure instead of decorative dot separators", () => {
    const screens = [
      "./StatusBar.vue",
      "../../pages/overview/OverviewPage.vue",
      "../../pages/metrics/MetricsPage.vue",
      "../../pages/events/EventsPage.vue",
      "../../pages/users/UserDrawer.vue",
      "../../pages/settings/RealmSessionsPage.vue",
      "../../pages/governance/GovernancePage.vue",
      "../../i18n/en.ftl",
      "../../i18n/fr.ftl",
    ];

    for (const screen of screens) expect(source(screen)).not.toMatch(/[·•]|&middot;|··/);
  });
});
