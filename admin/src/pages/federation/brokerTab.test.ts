import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

const page = readFileSync(new URL("./FederationPage.vue", import.meta.url), "utf8");

describe("federation boards", () => {
  test("keeps the provider catalogue and configured brokers on separate tabs", () => {
    expect(page).toContain('const TABS = ["idps", "brokers", "directories", "platforms"]');
    expect(page).toContain('v-if="tab === \'brokers\'"');
    expect(page).toContain('v-if="tab === \'idps\'"');
  });

  test("places the realm's Kerberos door beside directories and explains trusted platforms", () => {
    expect(page).toContain(':to="`/${realm}/spnego`"');
    expect(page).toContain('<AppHint name="federation-kerberos-help" />');
    expect(page).toContain('<AppHint name="federation-platforms-help" />');
  });
});
