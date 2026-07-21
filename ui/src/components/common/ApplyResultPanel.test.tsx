// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet-mgmt Stage 1 — the apply-result panel shows the exact manifest + honest outcome; the fleet variant polls
// rollout to render live propagation; the local variant does not poll.

import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, afterEach } from "vitest";

const fetchFleetRollout = vi.fn();
vi.mock("../../api/fleet", () => ({ fetchFleetRollout: () => fetchFleetRollout() }));

const verifyPolicyApplied = vi.fn();
vi.mock("../../api/client", () => ({ verifyPolicyApplied: (...args: unknown[]) => verifyPolicyApplied(...args) }));

import { ApplyResultPanel, type ApplyResult } from "./ApplyResultPanel";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  fetchFleetRollout.mockReset();
  verifyPolicyApplied.mockReset();
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
  // Fix 7: an unmistakable APPLIED status chip when ok:true.
  expect(screen.getByText("APPLIED")).toBeInTheDocument();
  expect(fetchFleetRollout).not.toHaveBeenCalled();
});

it("failed local apply: shows a FAILED chip + the NRVQ code + the reason (not an empty panel)", () => {
  const result: ApplyResult = {
    kind: "local",
    title: "Apply rejected",
    ok: false,
    outcome: "namespace is dry-run only; apply is disabled",
    code: "NRVQ-API-7087",
    manifest: { namespace: "default", agent_class: "bot", enforcement_mode: "block" }
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  // The status is unmistakably FAILED, and both the code and the human reason are visible.
  expect(screen.getByText("FAILED")).toBeInTheDocument();
  expect(screen.getByText("NRVQ-API-7087")).toBeInTheDocument();
  expect(screen.getByText(/dry-run only/)).toBeInTheDocument();
  // No APPLIED/PROPAGATING chip leaks onto a failure.
  expect(screen.queryByText("APPLIED")).not.toBeInTheDocument();
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
  // Fix 7: a fleet push polling rollout is unmistakably PROPAGATING (not yet fully APPLIED).
  expect(screen.getByText("PROPAGATING")).toBeInTheDocument();
  await waitFor(() => expect(fetchFleetRollout).toHaveBeenCalled());
  await waitFor(() => expect(screen.getByText(/enforcing @v7/)).toBeInTheDocument());
  // scoped to the targeted cluster — fleet-a's row is not shown
  expect(screen.queryByText("fleet-a")).not.toBeInTheDocument();
});

it("renders nothing when result is null", () => {
  const { container } = render(<ApplyResultPanel result={null} onClose={() => {}} />);
  expect(container).toBeEmptyDOMElement();
});

// FIX B: a local write's 200 is not proof — when expectedVersion is set, the panel must poll a live read
// (verifyPolicyApplied) and show VERIFYING first, then ENFORCING vN once the poll confirms convergence.
it("local verify-by-poll: shows VERIFYING then ENFORCING vN once the polled version matches", async () => {
  verifyPolicyApplied.mockResolvedValue({ matched: true, current_version: 2, enforcement_mode: "audit" });
  const result: ApplyResult = {
    kind: "local",
    title: "Applied default/bot · v2",
    ok: true,
    outcome: "Loaded into this cluster's policy engine — enforcement \"audit\".",
    manifest: { namespace: "default", agent_class: "bot", enforcement_mode: "audit" },
    expectedVersion: 2,
    expectedMode: "audit"
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  // Immediately after mount, before the poll's promise resolves, the honest state is VERIFYING — not a
  // premature APPLIED/ENFORCING claim.
  expect(screen.getByText("VERIFYING")).toBeInTheDocument();
  expect(screen.getByText(/Verifying — confirming the new version is loaded/)).toBeInTheDocument();
  await waitFor(() => expect(verifyPolicyApplied).toHaveBeenCalledWith("default", "bot", 2));
  await waitFor(() => expect(screen.getByText("ENFORCING v2")).toBeInTheDocument());
  expect(screen.getByText(/confirmed via a live read/i)).toBeInTheDocument();
  // Never overclaims full-fleet convergence for a single live read.
  expect(screen.queryByText(/loaded on every pod/i)).not.toBeInTheDocument();
});

// A caller-driven verify with NO expectedVersion (e.g. the PolicyPacks toggle, which verifies via its
// own bespoke poll) must not show a green APPLIED badge while the body still says "Verifying…" underneath.
it("pendingVerify=true shows the VERIFYING badge even with no expectedVersion set", () => {
  const result: ApplyResult = {
    kind: "local",
    title: 'Enabled "finops" — default',
    ok: true,
    outcome: "Verifying — confirming the change is loaded…",
    manifest: { namespace: "default", agent_class: "__pack__finops", enforcement_mode: "enabled" },
    pendingVerify: true
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  expect(screen.getByText("VERIFYING")).toBeInTheDocument();
  expect(screen.queryByText("APPLIED")).not.toBeInTheDocument();
  expect(verifyPolicyApplied).not.toHaveBeenCalled(); // no expectedVersion -> the version-poll never starts
});

it("pendingVerify='stalled' shows the STALLED badge (not a green APPLIED) when the caller's own verify gave up", () => {
  const result: ApplyResult = {
    kind: "local",
    title: 'Enabled "finops" — default',
    ok: true,
    outcome: "The write succeeded but this connection hasn't confirmed the flip yet — it may still be propagating across replicas.",
    manifest: { namespace: "default", agent_class: "__pack__finops", enforcement_mode: "enabled" },
    pendingVerify: "stalled"
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  expect(screen.getByText("STALLED")).toBeInTheDocument();
  expect(screen.queryByText("APPLIED")).not.toBeInTheDocument();
});

it("pendingVerify=false (resolved/converged) falls through to the normal APPLIED badge", () => {
  const result: ApplyResult = {
    kind: "local",
    title: 'Enabled "finops" — default',
    ok: true,
    outcome: 'Confirmed via a live read — "finops" is now enabled for default. Effective on the next tool call.',
    manifest: { namespace: "default", agent_class: "__pack__finops", enforcement_mode: "enabled" },
    pendingVerify: false
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  expect(screen.getByText("APPLIED")).toBeInTheDocument();
});

it("local verify-by-poll: STALLED (amber, not red) with a Check again affordance when the version never converges", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  verifyPolicyApplied.mockResolvedValue({ matched: false, current_version: 1 });
  const result: ApplyResult = {
    kind: "local",
    title: "Applied default/bot · v2",
    ok: true,
    outcome: "Loaded into this cluster's policy engine.",
    manifest: { namespace: "default", agent_class: "bot", enforcement_mode: "block" },
    expectedVersion: 2
  };
  render(<ApplyResultPanel result={result} onClose={() => {}} />);
  expect(screen.getByText("VERIFYING")).toBeInTheDocument();
  // 4 tries total, ~1.5s apart — advance past the full budget.
  for (let i = 0; i < 4; i++) {
    await vi.advanceTimersByTimeAsync(1600);
  }
  expect(await screen.findByText("STALLED")).toBeInTheDocument();
  expect(screen.getByText(/hasn't picked up v2 yet/i)).toBeInTheDocument();
  expect(screen.getByText("Check again")).toBeInTheDocument();
  // Not the same visual severity as a write-time FAILED.
  expect(screen.queryByText("FAILED")).not.toBeInTheDocument();
});
