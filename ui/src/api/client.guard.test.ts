// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-69 Stage 1 — the api client itself refuses a cluster-scoped mutation while a remote cluster is active, BEFORE
// any network call (the hard backstop behind the per-page deep-link gate).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiSend } from "./client";
import { setRemoteClusterContext } from "./clusterGuard";

describe("apiSend remote-cluster backstop (F-69 Stage 1)", () => {
  beforeEach(() => setRemoteClusterContext(false));
  afterEach(() => {
    setRemoteClusterContext(false);
    vi.restoreAllMocks();
  });

  it("throws NRVQ-UI-4601 and never fetches a cluster-scoped mutation when remote", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    setRemoteClusterContext(true);
    await expect(apiSend("/api/v1/policies", "POST", { rego_source: "x" })).rejects.toThrow(/NRVQ-UI-4601/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("allows the same mutation when local (fetch is called)", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    setRemoteClusterContext(false);
    await apiSend("/api/v1/policies", "POST", { rego_source: "x" });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
