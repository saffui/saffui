import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

function stylesheets(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return stylesheets(path);
    return entry.name.endsWith(".css") ? [path] : [];
  });
}

/// The weights a Plex Sans face ships at, as the console declares its faces.
function shippedWeights(): Set<number> {
  const faces = readFileSync(join(ROOT, "admin/src/assets/fonts.css"), "utf8").split("@font-face");
  return new Set(
    faces
      .filter((face) => face.includes('"IBM Plex Sans"'))
      .map((face) => Number(/font-weight:\s*(\d+)/.exec(face)?.[1])),
  );
}

describe("Plex weights", () => {
  // A weight no face ships at is drawn by the nearest one, so what the
  // stylesheet says and what the page shows part ways.
  it("asks only for weights a shipped face draws", () => {
    const shipped = shippedWeights();
    expect([...shipped].sort((a, b) => a - b)).toEqual([400, 500, 600]);
    const unshipped = ["admin/src", "account/src"]
      .flatMap((dir) => stylesheets(join(ROOT, dir)))
      .flatMap((path) =>
        [...readFileSync(path, "utf8").matchAll(/font-weight:\s*(\d+)/g)]
          .map((found) => Number(found[1]))
          .filter((weight) => !shipped.has(weight))
          .map((weight) => `${path.slice(ROOT.length)}: ${weight}`),
      );
    expect(unshipped).toEqual([]);
  });
});
