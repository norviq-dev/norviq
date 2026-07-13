// SPDX-License-Identifier: Apache-2.0

import "@testing-library/jest-dom";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

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
