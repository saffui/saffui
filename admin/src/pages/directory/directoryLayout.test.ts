import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

function source(path: string) {
  return readFileSync(new URL(path, import.meta.url), "utf8");
}

describe("directory layouts", () => {
  test("keeps empty directory tables explicit", () => {
    expect(source("./DirectoryTable.vue")).toContain('say("directory-empty")');
  });

  test("spreads creation forms across responsive columns", () => {
    expect(source("./GroupsPage.vue")).toContain("xl:grid-cols-[minmax(0,1fr)");
    expect(source("./RolesPage.vue")).toContain("lg:grid-cols-[minmax(0,1fr)");
    expect(source("./OrganizationsPage.vue")).toContain("lg:grid-cols-[minmax(0,1fr)");
  });
});
