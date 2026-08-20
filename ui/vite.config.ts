import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

export default defineConfig({
  // See the NO AMBIENT DEV TOKEN note in `test` below. This has to be a `define` and not `test.env`
  // or a `vi.stubEnv`: Vite INLINES `import.meta.env.VITE_*` at transform time from the loaded .env
  // files, so by the time either of those runs there is no lookup left to intercept. Both were tried
  // and both were inert while reading as a fix. `define` replaces at that same transform stage.
  // Gated on VITEST so production builds keep the real value.
  define: process.env.VITEST ? { "import.meta.env.VITE_DEV_TOKEN": '""' } : {},
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
          // Monaco gets its OWN named chunk so the build output names what is actually large.
          // Without this the bundler folded ~2.5 MB of editor into whichever app module happened to
          // anchor the shared chunk — most recently `ApplyResultPanel`, a ~9 kB status panel — and the
          // >500 kB warning then pointed at a file with nothing to optimize in it. The chunk is still
          // lazy (only the four editor-bearing routes import it, via `__vite__mapDeps`), so this
          // changes the NAME and not what any route downloads.
          if (id.includes("monaco-editor")) return "monaco-editor";
          return undefined;
        }
      }
    }
  },
  // `vite preview` serves the PRODUCTION build, so it is the only way to exercise chunking, lazy
  // route loading and Monaco's worker wiring before an image is built. It needs the same API proxy
  // the dev server has, or every page renders its error state and proves nothing.
  preview: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/healthz": "http://127.0.0.1:8080",
      "/readyz": "http://127.0.0.1:8080",
      "/ws": { target: "ws://127.0.0.1:8080", ws: true }
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
    // NO AMBIENT DEV TOKEN — the same class of bug as the jsdom origin above, and it cost more.
    //
    // AppContext's DEV bootstrap (src/store/AppContext.tsx:148-156) does
    // `localStorage.setItem("nrvq_token", import.meta.env.VITE_DEV_TOKEN)` when no token is present.
    // Vitest runs with DEV true and Vite loads `ui/.env.local`, which is GITIGNORED — so a developer's
    // machine silently authenticated the whole suite and CI, where that file does not exist, did not.
    // AppContext's posture effect opens with `if (!getToken()) return;`, so with no token `posture.mode`
    // stays null forever and every render gated on the namespace's enforcement posture never appears.
    // One test burned its full 30s budget on CI while finishing in 180ms here, and two investigations
    // read that as a slow runner and raised the budget twice (1s -> 15s -> 30s) at something that was
    // never timing.
    //
    // It belongs HERE and not in a `vi.stubEnv` in setup.ts. That was tried first and is INERT: Vite
    // inlines `VITE_*` references at transform time, so by the time a stub runs there is no lookup left
    // to intercept — `import.meta.env.VITE_DEV_TOKEN` still read the real token straight out of
    // .env.local while the setup file claimed to have neutralised it. `test.env` is applied when the
    // environment is built, which is early enough to win.
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
