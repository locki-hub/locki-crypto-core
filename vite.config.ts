import { resolve } from "node:path";
import { defineConfig } from "vite";
import dts from "vite-plugin-dts";

export default defineConfig({
  plugins: [
    dts({
      include: ["src"],
      outDir: "dist",
      rollupTypes: true,
    }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "LockiCrypto",
      formats: ["es", "cjs"],
      fileName: "index",
    },
    minify: "esbuild",
    target: "es2020",
    rollupOptions: {
      external: [],
    },
  },
});
