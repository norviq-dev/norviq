// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet-mgmt Stage 1 — the apply-result panel shows the exact manifest + honest outcome; the fleet variant polls
// rollout to render live propagation; the local variant does not poll.

import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, afterEach } from "vitest";

const fetchFleetRollout = vi.fn();
vi.mock("../../api/fleet", () => ({ fetchFleetRollout: () => fetchFleetRollout() }));

import { ApplyResultPanel, type ApplyResult } from "./ApplyResultPanel";

afterEach(() => {
  vi.restoreAllMocks();
  fetchFleetRollout.mockReset();
});

it("local apply: shows the configured resource + honest outcome, does NOT poll rollout", async () => {
  const result: ApplyResult = {
    kind: "local",
    title: "Configured default/bot",
    ok: true,
    outcome: "Loaded into this cluster's policy engine — enforcement \"block\".",
    manifest: { namespace: "default", agent_class: "bot", enforcement_mode: "block" }
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  expect(screen.getByText(/Configured default\/bot/)).toBeInTheDocument();
  expect(screen.getByText(/Loaded into this cluster/)).toBeInTheDocument();
  expect(screen.getByText("Resource configured")).toBeInTheDocument();
  expect(fetchFleetRollout).not.toHaveBeenCalled();
});

it("fleet push: polls rollout and renders 'enforcing' when the targeted spoke applied the bundle", async () => {
  fetchFleetRollout.mockResolvedValue([
    { cluster_id: "fleet-b", bundle_version: 7, applied_version: 7, state: "applied", updated_at: "2026-06-30T20:00:00Z" },
    { cluster_id: "fleet-a", bundle_version: 3, applied_version: 3, state: "applied", updated_at: null }
  ]);
  const result: ApplyResult = {
    kind: "fleet",
    title: 'Fleet policy "blk" v7 published',
    ok: true,
    outcome: "signed bundle distributed",
    manifest: { name: "blk", namespace: "default", agent_class: "bot", rego: "package x" },
    fleetPolicyName: "blk",
    targetClusters: ["fleet-b"]
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  await waitFor(() => expect(fetchFleetRollout).toHaveBeenCalled());
  await waitFor(() => expect(screen.getByText(/enforcing @v7/)).toBeInTheDocument());
  // scoped to the targeted cluster — fleet-a's row is not shown
  expect(screen.queryByText("fleet-a")).not.toBeInTheDocument();
});

it("renders nothing when result is null", () => {
  const { container } = render(<ApplyResultPanel result={null} onClose={() => {}} />);
  expect(container).toBeEmptyDOMElement();
});
