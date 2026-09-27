import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

const fonts = readFileSync(new URL("./fonts.css", import.meta.url), "utf8");
const account = readFileSync(new URL("./account.css", import.meta.url), "utf8");

describe("account typography", () => {
  test("uses the same local Plex families as the administrator console", () => {
    expect(fonts.match(/@font-face/g)).toHaveLength(5);
    expect(fonts).not.toMatch(/https?:\/\//);
    expect(account).toContain('--font-sans: "IBM Plex Sans"');
    expect(account).toContain('--font-mono: "IBM Plex Mono"');
  });
});
