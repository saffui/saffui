import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

const page = readFileSync(new URL("./FederationPage.vue", import.meta.url), "utf8");

describe("federation boards", () => {
  test("keeps the provider catalogue and configured brokers on separate tabs", () => {
    expect(page).toContain('const TABS = ["idps", "brokers", "directories", "platforms"]');
    expect(page).toContain('v-if="tab === \'brokers\'"');
    expect(page).toContain('v-if="tab === \'idps\'"');
  });
});
