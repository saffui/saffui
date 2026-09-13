import { readFileSync } from "node:fs";
import { FluentResource } from "@fluent/bundle";
import { describe, expect, test } from "vitest";

const TONGUES = ["en", "fr"];

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

describe("the console catalogues", () => {
  // A repeated id fails silently: the bundle keeps the first definition, so
  // the words of the second never reach the screen.
  test.each(TONGUES)("%s defines each message once", (tongue) => {
    expect(findRepeatedIds(readMessageIds(tongue))).toEqual([]);
  });

  test("every tongue defines the same messages", () => {
    const [first, ...others] = TONGUES.map((tongue) => [...new Set(readMessageIds(tongue))].sort());
    for (const ids of others) expect(ids).toEqual(first);
  });
});
