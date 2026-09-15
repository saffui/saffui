import { rmSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";

// Answers an earlier run kept would otherwise be judged again beside this one's.
rmSync(new URL("./.contract", import.meta.url), { recursive: true, force: true });

export default defineConfig({
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    include: ["src/contract/*.contract.ts"],
    setupFiles: ["src/contract/setup.ts"],
    // One server and one person: the files take turns on them.
    fileParallelism: false,
  },
});
