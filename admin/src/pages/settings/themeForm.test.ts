import { describe, expect, test } from "vitest";
import {
  effective,
  emptyTheme,
  invalidThemeToken,
  safeThemeValue,
  THEME_DEFAULTS,
  THEME_TOKENS,
  themeDocument,
} from "./themeForm";

describe("theme form", () => {
  test("covers the complete server token contract once", () => {
    expect(THEME_TOKENS).toHaveLength(15);
    expect(new Set(THEME_TOKENS).size).toBe(THEME_TOKENS.length);
    expect(Object.keys(THEME_DEFAULTS.light).sort()).toEqual([...THEME_TOKENS].sort());
    expect(Object.keys(THEME_DEFAULTS.dark).sort()).toEqual([...THEME_TOKENS].sort());
  });

  test("shows defaults without persisting inherited values", () => {
    const draft = emptyTheme({ light: { "brand-primary": "#123456" } });

    expect(effective(draft, "light", "brand-primary")).toBe("#123456");
    expect(effective(draft, "dark", "brand-primary")).toBe("#D9A441");
    expect(themeDocument(draft)).toEqual({ light: { "brand-primary": "#123456" } });
  });

  test("drops blank overrides", () => {
    expect(themeDocument({ light: { bg: "  " }, dark: { ink: "#EFECE7" } })).toEqual({
      dark: { ink: "#EFECE7" },
    });
  });

  test("matches the server CSS value boundary", () => {
    expect(safeThemeValue("0 1px 2px rgba(23, 21, 15, .06)")).toBe(true);
    expect(safeThemeValue("#C99433")).toBe(true);
    expect(safeThemeValue("url(https://tracker.example/pixel)")).toBe(false);
    expect(safeThemeValue("#fff;}body{display:none")).toBe(false);

    const draft = emptyTheme({ light: { bg: "url(https://tracker.example/pixel)" } });
    expect(invalidThemeToken(draft)).toEqual({ half: "light", token: "bg" });
    expect(effective(draft, "light", "bg")).toBe(THEME_DEFAULTS.light.bg);
  });
});
