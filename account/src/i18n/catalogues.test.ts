import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FluentResource } from "@fluent/bundle";
import { describe, expect, test } from "vitest";

const TONGUES = ["en", "fr"];
const SOURCES = fileURLToPath(new URL("..", import.meta.url));

function readMessageIds(tongue: string): string[] {
  const source = readFileSync(new URL(`./${tongue}.ftl`, import.meta.url), "utf8");
  return new FluentResource(source).body.map((entry) => entry.id);
}

function findRepeatedIds(ids: string[]): string[] {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) repeated.add(id);
    seen.add(id);
  }
  return [...repeated];
}

/// Every message name the console's own sources pass to `say` as a literal.
function findAskedNames(directory: string): string[] {
  const names: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      names.push(...findAskedNames(path));
    } else if (/\.(ts|vue)$/.test(entry.name) && !entry.name.endsWith(".test.ts")) {
      const source = readFileSync(path, "utf8");
      for (const asked of source.matchAll(/\bsay\(\s*["']([a-z0-9-]+)["']/g)) names.push(asked[1]);
    }
  }
  return names;
}

describe("the account console catalogues", () => {
  // A repeated id fails silently: the bundle keeps the first definition, so the
  // words of the second never reach the screen.
  test.each(TONGUES)("%s defines each message once", (tongue) => {
    expect(findRepeatedIds(readMessageIds(tongue))).toEqual([]);
  });

  test("every tongue defines the same messages", () => {
    const [first, ...others] = TONGUES.map((tongue) => [...new Set(readMessageIds(tongue))].sort());
    for (const ids of others) expect(ids).toEqual(first);
  });

  test("every message the console asks for is defined", () => {
    const defined = new Set(readMessageIds("en"));
    const asked = findAskedNames(SOURCES);
    expect(asked.length).toBeGreaterThan(20);
    expect(asked.filter((name) => !defined.has(name))).toEqual([]);
  });
});
