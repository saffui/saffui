import { beforeEach, describe, expect, test, vi } from "vitest";
import type { OrganizationRow } from "@/models/directory";

vi.mock("@/services/directory", () => ({
  forgetOrganizationTheme: vi.fn(async () => undefined),
  getOrganizationTheme: vi.fn(async () => null),
  writeOrganizationTheme: vi.fn(async () => undefined),
}));
vi.mock("@/services/settings", () => ({
  forgetRealmTheme: vi.fn(async () => undefined),
  getRealmTheme: vi.fn(async () => null),
  writeRealmTheme: vi.fn(async () => undefined),
}));

const directory = await import("@/services/directory");
const settings = await import("@/services/settings");
const { forgetScopedTheme, listThemeChoices, readScopedTheme, readThemeOrganization, writeScopedTheme } =
  await import("./themeScope");

const ACME: OrganizationRow = {
  org_id: "o-1",
  name: "acme",
  display_name: "Acme Corp",
  description: "",
  enabled: true,
  domains: [],
  redirect_url: null,
  attributes: null,
};

beforeEach(() => vi.clearAllMocks());

describe("the theme the page edits", () => {
  test("is the organization the address names, and the realm's for anything else", () => {
    expect(readThemeOrganization(" o-1 ")).toBe("o-1");
    expect(readThemeOrganization(["o-1"])).toBe("");
    expect(readThemeOrganization(undefined)).toBe("");
  });

  test("offers each organization by the name it shows, and keeps the one the address names", () => {
    const beta = { ...ACME, org_id: "o-2", name: "beta", display_name: "" };
    expect(listThemeChoices([ACME, beta], "o-9")).toEqual([
      { id: "o-1", label: "Acme Corp" },
      { id: "o-2", label: "beta" },
      { id: "o-9", label: "o-9" },
    ]);
    expect(listThemeChoices([ACME], "o-1")).toEqual([{ id: "o-1", label: "Acme Corp" }]);
    expect(listThemeChoices([ACME], "")).toEqual([{ id: "o-1", label: "Acme Corp" }]);
  });

  test("reads, writes and forgets an organization's theme on the organization, never on the realm", async () => {
    await readScopedTheme("main", "o-1");
    await writeScopedTheme("main", "o-1", { light: { bg: "#000000" } });
    await forgetScopedTheme("main", "o-1");

    expect(directory.getOrganizationTheme).toHaveBeenCalledWith("main", "o-1");
    expect(directory.writeOrganizationTheme).toHaveBeenCalledWith("main", "o-1", {
      light: { bg: "#000000" },
    });
    expect(directory.forgetOrganizationTheme).toHaveBeenCalledWith("main", "o-1");
    expect(settings.getRealmTheme).not.toHaveBeenCalled();
    expect(settings.writeRealmTheme).not.toHaveBeenCalled();
    expect(settings.forgetRealmTheme).not.toHaveBeenCalled();
  });

  test("reads, writes and forgets the realm's theme when no organization is named", async () => {
    await readScopedTheme("main", "");
    await writeScopedTheme("main", "", { dark: { ink: "#FFFFFF" } });
    await forgetScopedTheme("main", "");

    expect(settings.getRealmTheme).toHaveBeenCalledWith("main");
    expect(settings.writeRealmTheme).toHaveBeenCalledWith("main", { dark: { ink: "#FFFFFF" } });
    expect(settings.forgetRealmTheme).toHaveBeenCalledWith("main");
    expect(directory.getOrganizationTheme).not.toHaveBeenCalled();
    expect(directory.writeOrganizationTheme).not.toHaveBeenCalled();
    expect(directory.forgetOrganizationTheme).not.toHaveBeenCalled();
  });
});
