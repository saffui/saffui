import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";

// The dev server answers a realm's console itself and proxies everything else
// under the realm to a locally running saffui, so the app is developed against
// the real thing.
const upstream = process.env.SAFFUI_UPSTREAM ?? "http://localhost:8080";
const CONSOLE_PAGE = /^\/realms\/[^/]+\/account(?:[/?#]|$)/;

export default defineConfig({
  // The built assets are the same for every realm, so the server keeps them once
  // under /account/, while the console's pages live under each realm.
  base: "/account/",
  plugins: [vue()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5178,
    proxy: {
      "/realms": {
        target: upstream,
        changeOrigin: false,
        bypass: (request) =>
          CONSOLE_PAGE.test(request.url ?? "") ? "/account/index.html" : undefined,
      },
    },
  },
});
