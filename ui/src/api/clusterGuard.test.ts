// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-69 Stage 1 — the mutation backstop. A cluster-scoped write to the LOCAL api must be refused while a REMOTE
// cluster is the active context; reads, non-cluster writes, and the local context are unaffected.

import { describe, it, expect, beforeEach } from "vitest";
import { setRemoteClusterContext, blockedByRemoteCluster, isRemoteClusterActive } from "./clusterGuard";

describe("clusterGuard (F-69 Stage 1)", () => {
  beforeEach(() => setRemoteClusterContext(false));

  it("blocks every cluster-scoped mutation when a remote cluster is active", () => {
    setRemoteClusterContext(true);
    for (const [m, p] of [
      ["POST", "/api/v1/policies"],
      ["POST", "/api/v1/policies/dry-run"],
      ["POST", "/api/v1/policies/default/bot/apply"],
      ["POST", "/api/v1/policies/default/bot/rollback"],
      ["POST", "/api/v1/policy-packs/energy/enable"],
      ["DELETE", "/api/v1/policy-packs/override?namespace=default"],
      ["PUT", "/api/v1/settings?namespace=default"],
      ["PUT", "/api/v1/agents/spiffe%3A%2F%2Fx/trust"],
      ["POST", "/api/v1/attack-paths/compute?namespace=default"],
      ["POST", "/api/v1/evaluate"]
    ] as const) {
      expect(blockedByRemoteCluster(m, p), `${m} ${p}`).toBe(true);
    }
  });

  it("never blocks when the selection is local", () => {
    setRemoteClusterContext(false);
    expect(blockedByRemoteCluster("POST", "/api/v1/policies")).toBe(false);
    expect(blockedByRemoteCluster("PUT", "/api/v1/settings?namespace=default")).toBe(false);
  });

  it("never blocks GET reads, even when remote", () => {
    setRemoteClusterContext(true);
    expect(blockedByRemoteCluster("GET", "/api/v1/policies?namespace=default")).toBe(false);
    expect(blockedByRemoteCluster("GET", "/api/v1/settings?namespace=default")).toBe(false);
  });

  it("does not block non-cluster (user/account/api-key) writes when remote", () => {
    setRemoteClusterContext(true);
    expect(blockedByRemoteCluster("PUT", "/api/v1/account")).toBe(false);
    expect(blockedByRemoteCluster("POST", "/api/v1/keys")).toBe(false);
    expect(blockedByRemoteCluster("DELETE", "/api/v1/keys/abc")).toBe(false);
  });

  it("isRemoteClusterActive reflects the setter", () => {
    setRemoteClusterContext(true);
    expect(isRemoteClusterActive()).toBe(true);
    setRemoteClusterContext(false);
    expect(isRemoteClusterActive()).toBe(false);
  });
});
