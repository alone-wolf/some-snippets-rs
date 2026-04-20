import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";
import { fileURLToPath, URL } from "node:url";

const apiPrefixes = [
  "/healthz",
  "/collections",
  "/contents",
  "/nodes",
  "/node-lineages",
  "/draft",
  "/latest",
  "/versions",
  "/files",
];

export default defineConfig({
  base: "/app/",
  plugins: [vue()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "dist",
    manifest: true,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: Object.fromEntries(
      apiPrefixes.map((prefix) => [
        prefix,
        {
          target: "http://127.0.0.1:3000",
        },
      ]),
    ),
  },
  test: {
    environment: "jsdom",
    globals: true,
  },
});
