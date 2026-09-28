import { rmSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";
import { BaseSequencer, type TestSpecification } from "vitest/node";

// Answers an earlier run kept would otherwise be judged again beside this one's.
rmSync(new URL("./.contract", import.meta.url), { recursive: true, force: true });

/// The files by name, every run. The default orders them by how long each took
/// last time, so the realm they share reaches each file in a state that varies.
class ByName extends BaseSequencer {
  override async sort(files: TestSpecification[]) {
    return [...files].sort((one, other) =>
      one.moduleId < other.moduleId ? -1 : one.moduleId > other.moduleId ? 1 : 0,
    );
  }
}

export default defineConfig({
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    include: ["src/contract/*.contract.ts"],
    setupFiles: ["src/contract/setup.ts"],
    // One server and one realm: the files take turns on it.
    fileParallelism: false,
    sequence: { sequencer: ByName },
  },
});
