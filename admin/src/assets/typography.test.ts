import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

const fonts = readFileSync(new URL("./fonts.css", import.meta.url), "utf8");
const tokens = readFileSync(new URL("./tokens.css", import.meta.url), "utf8");

describe("console typography", () => {
  test("loads Plex locally and only at the weights the console uses", () => {
    expect(fonts.match(/@font-face/g)).toHaveLength(5);
    expect(fonts).not.toMatch(/https?:\/\//);
    expect(fonts.match(/font-display: swap/g)).toHaveLength(5);
    expect(tokens).toContain('--font-sans: "IBM Plex Sans"');
    expect(tokens).toContain('--font-mono: "IBM Plex Mono"');
  });

  test("ships every declared font as WOFF2", () => {
    const files = [...fonts.matchAll(/url\("([^"]+\.woff2)"\)/g)].map((match) => match[1]);

    expect(files).toHaveLength(5);
    for (const path of files) {
      expect(readFileSync(new URL(path, import.meta.url)).subarray(0, 4).toString()).toBe("wOF2");
    }
  });
});
