import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src")
    }
  },
  // Pre-bundle Monaco so the Policy Catalog route doesn't hang the dev server compiling it on
  // first hit (its heavy deps would otherwise be discovered + optimized lazily mid-request).
  optimizeDeps: {
    include: ["@monaco-editor/react", "monaco-editor"]
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("echarts-for-react")) return "echarts-react";
          if (id.includes("zrender")) return "zrender";
          if (id.includes("echarts")) return "echarts-core";
          return undefined;
        }
      }
    }
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/healthz": "http://127.0.0.1:8080",
      "/readyz": "http://127.0.0.1:8080",
      "/ws": {
        target: "ws://127.0.0.1:8080",
        ws: true
      }
    }
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    // Vitest owns the unit tests under src/. The Playwright E2E suite (tests/e2e/**, @playwright/test)
    // must NOT be collected by vitest — its `test()` is a different runner and errors on import.
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["**/node_modules/**", "**/dist/**", "tests/e2e/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      exclude: ["**/*.test.tsx", "**/*.test.ts", "**/types.ts"]
    }
  }
});
