// SPDX-License-Identifier: Apache-2.0
// The aggregate-scope guard. A namespace/cluster-scoped mutation must never target the phantom "all".
import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useMutationScope } from "./useMutationScope";

// Mutable backing state so a single file can exercise fleet-off AND fleet-on (a live-binding getter re-reads it).
const state = {
  fleetEnabled: false,
  app: { namespace: "default", selectedCluster: "local", isRemote: false } as Record<string, unknown>
};
vi.mock("../api/fleet", () => ({
  get fleetEnabled() {
    return state.fleetEnabled;
  }
}));
vi.mock("../store/AppContext", () => ({ useApp: () => state.app }));

beforeEach(() => {
  state.fleetEnabled = false;
  state.app = { namespace: "default", selectedCluster: "local", isRemote: false };
});

describe("useMutationScope (aggregate-scope guard)", () => {
  it("a concrete namespace can mutate (fleet off)", () => {
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(true);
    expect(result.current.blockedReason).toBeNull();
  });

  it("the aggregate 'all' namespace CANNOT mutate and prompts for a namespace", () => {
    state.app = { namespace: "all", selectedCluster: "local", isRemote: false };
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(false);
    expect(result.current.blockedReason).toMatch(/Select a namespace/i);
  });

  it("an empty namespace is treated as aggregate (fail-closed) — cannot mutate", () => {
    state.app = { namespace: "", selectedCluster: "local", isRemote: false };
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(false);
  });

  it("FLEET ON: aggregate 'All clusters' (cluster='all') cannot mutate even with a concrete namespace", () => {
    state.fleetEnabled = true;
    state.app = { namespace: "default", selectedCluster: "all", isRemote: false };
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(false);
    expect(result.current.blockedReason).toMatch(/Select a cluster/i);
  });

  it("FLEET ON: both aggregate → prompts for BOTH a namespace and a cluster", () => {
    state.fleetEnabled = true;
    state.app = { namespace: "all", selectedCluster: "all", isRemote: false };
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(false);
    expect(result.current.blockedReason).toMatch(/namespace and a cluster/i);
  });

  it("FLEET ON: a concrete namespace + concrete served cluster CAN mutate", () => {
    state.fleetEnabled = true;
    state.app = { namespace: "default", selectedCluster: "cluster-a", isRemote: false };
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(true);
  });

  it("a remote (non-served) cluster blocks mutation even under a concrete namespace", () => {
    state.app = { namespace: "default", selectedCluster: "cluster-b", isRemote: true };
    const { result } = renderHook(() => useMutationScope());
    expect(result.current.canMutate).toBe(false);
  });
});
