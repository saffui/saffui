import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, test, vi } from "vitest";

const asked: string[] = [];
let refuse = false;

vi.mock("@/services/http", () => ({
  adminPath: (realm: string, leaf: string) => `/admin/realms/${realm}/${leaf}`,
  api: async (path: string) => {
    asked.push(path);
    // A real door takes longer than a microtask. Resolving in one would let a
    // dropped call look like a shared one, which is the defect under test.
    await new Promise((settle) => setTimeout(settle, 0));
    if (refuse) throw new Error("refused");
    return path.endsWith("/overview")
      ? { users: 1, clients: 2, sessions: 3, pending_requests: 0, queue: 0 }
      : { edit_user_name_allowed: true };
  },
}));

const { useStanding } = await import("./standing");

beforeEach(() => {
  setActivePinia(createPinia());
  asked.length = 0;
  refuse = false;
});

describe("the one reading the bar and the overview share", () => {
  test("two callers on the same navigation pay for it once", async () => {
    const standing = useStanding();
    await Promise.all([standing.read("main"), standing.read("main")]);

    expect(asked.sort()).toEqual([
      "/admin/realms/main/overview",
      "/admin/realms/main?briefRepresentation=false",
    ]);
    expect(standing.held?.users).toBe(1);
    expect(standing.settings?.edit_user_name_allowed).toBe(true);
  });

  test("the second caller waits for it rather than being waved through", async () => {
    const standing = useStanding();
    // The bar asks on mount and the overview asks on the same navigation.
    // Dropping the second call hands the overview an empty store, which it
    // reads as a realm that did not answer.
    const bar = standing.read("main");
    await standing.read("main");

    expect(standing.held?.users, "the second caller returned before the answer did").toBe(1);
    await bar;
  });

  test("a second navigation to the same realm reads nothing again", async () => {
    const standing = useStanding();
    await standing.read("main");
    asked.length = 0;

    await standing.read("main");
    expect(asked).toEqual([]);
  });

  test("a write asks again even though the realm has not changed", async () => {
    const standing = useStanding();
    await standing.read("main");
    asked.length = 0;

    await standing.read("main", true);
    expect(asked.length).toBe(2);
  });

  test("a write landing during the first read queues one fresh reading", async () => {
    const standing = useStanding();

    await Promise.all([
      standing.read("main"),
      standing.read("main", true),
      standing.read("main", true),
    ]);

    expect(asked.filter((path) => path.endsWith("/overview"))).toHaveLength(2);
    expect(asked.filter((path) => path.includes("briefRepresentation=false"))).toHaveLength(2);
  });

  test("another realm is another reading", async () => {
    const standing = useStanding();
    await Promise.all([standing.read("main"), standing.read("annex")]);
    expect(asked.length).toBe(4);
  });
});

describe("what the bar's light is allowed to claim", () => {
  test("it claims nothing before the realm has been asked", () => {
    expect(useStanding().answering).toBe(null);
  });

  test("it says answering only once the realm has answered", async () => {
    const standing = useStanding();
    await standing.read("main");
    expect(standing.answering).toBe(true);
  });

  test("a refusal turns it, rather than leaving it green over an empty bar", async () => {
    refuse = true;
    const standing = useStanding();
    await standing.read("main");

    expect(standing.answering).toBe(false);
    expect(standing.held).toBe(null);
  });
});

/// The store exists so one door is knocked on once. A page that goes back to
/// knocking for itself costs the same answer twice on every navigation and on
/// every write, which is how this was found in the first place.
function everySource(at: string, under = ""): string[] {
  return readdirSync(at, { withFileTypes: true }).flatMap((held) =>
    held.isDirectory()
      ? everySource(join(at, held.name), `${under}${held.name}/`)
      : /\.(ts|vue)$/.test(held.name) && !held.name.endsWith(".test.ts")
        ? [`${under}${held.name}`]
        : [],
  );
}

const ALLOWED_TO_ASK = ["stores/standing.ts", "services/preview.ts"];

describe("who may knock on the overview door", () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  for (const leaf of everySource(root)) {
    if (ALLOWED_TO_ASK.includes(leaf)) continue;
    test(`${leaf} reads the standing store rather than the door`, () => {
      const source = readFileSync(join(root, leaf), "utf8");
      expect(
        /adminPath\([^,]+,\s*["`]overview["`]\)/.test(source),
        `${leaf} asks the overview door itself. The status bar already asked ` +
          "on this navigation; read useStanding() instead of paying twice.",
      ).toBe(false);
    });
  }
});
