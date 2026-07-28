// SPDX-License-Identifier: Apache-2.0

import "@testing-library/jest-dom";
import { afterEach, vi } from "vitest";
import { cleanup, configure } from "@testing-library/react";

// Testing-library's `findBy*` / `waitFor` poll against their OWN budget (`asyncUtilTimeout`,
// default 1000ms) — NOT vitest's `testTimeout`. That distinction is the whole bug: raising
// --testTimeout did nothing, because the query gave up long before the test did.
//
// One second is fine for a file run alone and far too tight for the full suite. Pages that mount
// ECharts under jsdom (Dashboard's gauges, via the proxied canvas below) render in well under a
// second in isolation, but with 60 test files across 10 workers the CPU contention regularly pushes
// them past it — so `findByTestId("score-gauge-caption")` reported the element "not found" when the
// component was merely still rendering. The suite failed ~3 runs in 4 in parallel while passing
// 3/3 alone and 2/2 with --no-file-parallelism, which is what identified contention rather than
// pollution: file isolation is on, and the affected test resets its own MSW handlers and API cache.
//
// 5s is a wall-clock allowance for a loaded machine, not a correctness change: a genuinely hung or
// never-rendering component still fails, just not a merely slow one. Raise this before reaching for
// per-call timeouts — a value scattered across individual findBy* calls is the same fix, applied
// inconsistently and re-litigated at every new flake.
configure({ asyncUtilTimeout: 5000 });

// SLIM-MONACO: the lib/monaco side-effect (loader.config + a Vite ?worker import + monaco core) is a
// production-only concern — no-op it in unit tests so pages that import it don't pull Monaco/workers into
// jsdom. The editor component itself is separately mocked where a test renders it.
vi.mock("@/lib/monaco", () => ({}));

// jsdom has no ResizeObserver. Real browsers all do; our native ECharts wrapper (src/components/common/
// EChart.tsx) uses it to keep charts sized to their container. Provide a no-op global so any component
// that renders a chart doesn't throw ReferenceError under jsdom.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}

// jsdom's <canvas> has no 2d context (getContext returns null), which crashes ECharts' canvas renderer
// (`ctx.dpr = ...` / `ctx.clearRect(...)` on null). Real browsers have it. A Proxy stub returns a no-op
// function for any method and lets any property set/read succeed, so a chart can mount+paint headlessly
// without a real canvas — pages that render charts just need to not throw under jsdom.
if (typeof HTMLCanvasElement !== "undefined") {
  const make2d = (): unknown =>
    new Proxy(
      { canvas: {} },
      {
        get(target, prop) {
          if (prop in target) return (target as Record<string, unknown>)[prop as string];
          if (prop === "measureText") return () => ({ width: 0 });
          if (prop === "getImageData") return () => ({ data: [] });
          if (prop === "createLinearGradient" || prop === "createRadialGradient" || prop === "createPattern")
            return () => make2d(); // gradients need .addColorStop(), which resolves via this same proxy
          return () => {}; // every other 2d-context method: no-op
        },
        set() {
          return true; // allow ctx.dpr / ctx.lineWidth / ... assignments
        },
      },
    );
  HTMLCanvasElement.prototype.getContext = (() => make2d()) as unknown as HTMLCanvasElement["getContext"];
}

afterEach(() => {
  cleanup();
});
