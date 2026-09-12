import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";
import { SIDE_NAV_GROUPS } from "./sideNav";

describe("realm navigation", () => {
  test("keeps realm directory pages in Manage", () => {
    const manage = SIDE_NAV_GROUPS.find((group) => group.label === "nav-cap-manage");

    expect(manage?.items.map((item) => item.leaf)).toEqual([
      "overview",
      "users",
      "groups",
      "roles",
      "organizations",
      "clients",
    ]);
  });

  test("does not repeat a destination", () => {
    const leaves = SIDE_NAV_GROUPS.flatMap((group) => group.items.map((item) => item.leaf));

    expect(new Set(leaves).size).toBe(leaves.length);
  });

  test("renders the realm dialog outside the transformed navigation rail", () => {
    const source = readFileSync(new URL("./RealmSelector.vue", import.meta.url), "utf8");

    expect(source).toMatch(/<Teleport to="body">[\s\S]*v-if="making"/);
  });
});
