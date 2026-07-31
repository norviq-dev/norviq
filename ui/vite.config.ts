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
    // Pin jsdom's origin OFF port 3000. jsdom defaults to http://localhost:3000, and msw is configured
    // with onUnhandledRequest:"bypass", so any request a test does not explicitly mock is resolved
    // against that origin and put on the real network. Port 3000 is exactly where this project's own
    // docs tell you to put the console (`kubectl port-forward svc/norviq-ui 3000:80`), and that service
    // serves static assets — it accepts the /api/v1 connection and never answers, so the request hangs
    // until the test times out. The result was a suite whose outcome depended on whether the developer
    // happened to have the console open: 7 tests failed with a 15s timeout and passed again after
    // pinning the origin. Nothing listens on 59999, so unmocked requests now fail fast and locally.
    environmentOptions: { jsdom: { url: "http://localhost:59999" } },
    setupFiles: "./src/test/setup.ts",
    // Vitest owns the unit tests under src/. The Playwright E2E suite (tests/e2e/**, @playwright/test)
    // must NOT be collected by vitest — its `test()` is a different runner and errors on import.
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["**/node_modules/**", "**/dist/**", "tests/e2e/**"],
    // MUST stay well above the 5s `asyncUtilTimeout` in src/test/setup.ts. Vitest's default
    // testTimeout is also 5000, so a test that awaits several `findBy*` calls hits the WHOLE-TEST
    // wall clock before any single query gives up — on a loaded CI runner that reports a bare
    // "Test timed out in 5000ms" instead of testing-library's useful "unable to find element" DOM
    // dump. The headroom (4+ queries × 5s) only bites on a real hang; a healthy run is ~1s.
    testTimeout: 30000,
    hookTimeout: 30000,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      exclude: ["**/*.test.tsx", "**/*.test.ts", "**/types.ts"]
    }
  }
});
