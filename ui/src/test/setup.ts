// SPDX-License-Identifier: Apache-2.0

import "@testing-library/jest-dom";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

// SLIM-MONACO: the lib/monaco side-effect (loader.config + a Vite ?worker import + monaco core) is a
// production-only concern — no-op it in unit tests so pages that import it don't pull Monaco/workers into
// jsdom. The editor component itself is separately mocked where a test renders it.
vi.mock("@/lib/monaco", () => ({}));

afterEach(() => {
  cleanup();
});
