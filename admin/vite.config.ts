import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

// The dev server proxies the realm and admin APIs to a locally running
// saffui, so the console is developed against the real thing.
const upstream = process.env.SAFFUI_UPSTREAM ?? "http://localhost:8080";

export default defineConfig(({ command }) => ({
  // Embedded builds live under /console/ inside the server binary; dev keeps
  // the root so review links stay stable.
  base: command === "build" ? "/console/" : "/",
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5177,
    proxy: {
      "/realms": { target: upstream, changeOrigin: false },
      "/admin": { target: upstream, changeOrigin: false },
    },
  },
}));
