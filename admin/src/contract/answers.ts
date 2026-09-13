import { mkdirSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { expect } from "vitest";

const SERVICES = import.meta.glob<Record<string, unknown>>(
  ["../services/*.ts", "!../services/*.test.ts", "!../services/preview.ts"],
  { eager: true },
);

export const REALM = process.env.SAFFUI_CONTRACT_REALM ?? "";

interface KeptAnswer {
  asked: string;
  module: string;
  call: string;
  json: string;
}

const kept: KeptAnswer[] = [];

function serviceModuleOf(call: unknown, name: string): string {
  for (const [path, exported] of Object.entries(SERVICES)) {
    if (Object.values(exported).includes(call)) return basename(path, ".ts");
  }
  throw new Error(`${name} is not exported by a console service`);
}

/// Calls a console service against the live server and keeps its answer, to be
/// judged afterwards against the type that service declares.
export async function keepAnswer<A extends unknown[], R>(
  call: (...args: A) => Promise<R>,
  ...args: A
): Promise<R> {
  const answer = await call(...args);
  if (answer !== undefined) {
    kept.push({
      asked: expect.getState().currentTestName ?? call.name,
      module: serviceModuleOf(call, call.name),
      call: call.name,
      json: JSON.stringify(answer, null, 2),
    });
  }
  return answer;
}

/// Writes what one contract file kept as TypeScript in which every answer has
/// to fit its service's return type. Extra fields fit; a missing, renamed or
/// retyped one does not, and `vue-tsc` says which.
export function writeKeptAnswers(testPath: string) {
  const modules = [...new Set(kept.map((answer) => answer.module))];
  const source = [
    ...modules.map((module) => `import type * as ${module} from "@/services/${module}";`),
    "",
    "const conforms = <T>() => <V extends T>(answer: V) => answer;",
    ...kept.map(
      (answer) =>
        `\n// ${answer.asked.replaceAll("\n", " ")}\n` +
        `conforms<Awaited<ReturnType<typeof ${answer.module}.${answer.call}>>>()(${answer.json});`,
    ),
    "",
  ].join("\n");
  const into = new URL("../../.contract/", import.meta.url);
  mkdirSync(into, { recursive: true });
  writeFileSync(new URL(`${basename(testPath, ".contract.ts")}.ts`, into), source);
}
