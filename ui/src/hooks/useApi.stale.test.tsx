// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// `stale` is the fact six separately-reported console defects all needed and none had.
//
// useApi deliberately KEEPS the last good data when a load fails — a flicker to empty is worse than
// showing the previous numbers a moment longer. The consequence nobody exposed: after a namespace
// switch whose read fails, `data` is the PREVIOUS namespace's, and a page renders it under the new
// namespace's header as measured fact. Every page that tried to guard this tested `data == null`,
// which is never true on that path, so the guard looked right and did nothing.

import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { clearApiCache, useApi } from "./useApi";

function Probe({ scope, loader }: { scope: string; loader: (s: string) => Promise<string> }) {
  const r = useApi<string>(() => loader(scope), [scope]);
  return (
    <div>
      <span data-testid="data">{r.data ?? "(none)"}</span>
      <span data-testid="stale">{r.stale ? "STALE" : "fresh"}</span>
      <span data-testid="error">{r.error ?? ""}</span>
    </div>
  );
}

beforeEach(() => clearApiCache());

it("reports data held from a PREVIOUS scope as stale when the new scope's read fails", async () => {
  const loader = vi.fn(async (s: string) => {
    if (s === "payments") return "payments-data";
    throw new Error("500");
  });
  const { rerender } = render(<Probe scope="payments" loader={loader} />);
  await waitFor(() => expect(screen.getByTestId("data")).toHaveTextContent("payments-data"));
  expect(screen.getByTestId("stale")).toHaveTextContent("fresh");

  rerender(<Probe scope="default" loader={loader} />);
  await waitFor(() => expect(screen.getByTestId("error")).toHaveTextContent("500"));

  // The value is STILL payments' — that is the deliberate part, and the reason `stale` must exist.
  expect(screen.getByTestId("data")).toHaveTextContent("payments-data");
  expect(screen.getByTestId("stale")).toHaveTextContent("STALE");
});

it("is not stale once the new scope's read succeeds", async () => {
  const loader = vi.fn(async (s: string) => `${s}-data`);
  const { rerender } = render(<Probe scope="payments" loader={loader} />);
  await waitFor(() => expect(screen.getByTestId("data")).toHaveTextContent("payments-data"));
  rerender(<Probe scope="default" loader={loader} />);
  await waitFor(() => expect(screen.getByTestId("data")).toHaveTextContent("default-data"));
  expect(screen.getByTestId("stale")).toHaveTextContent("fresh");
});

it("is never stale on a first-ever failed load — there is no previous scope to mistake it for", async () => {
  const loader = vi.fn(async () => {
    throw new Error("boom");
  });
  render(<Probe scope="payments" loader={loader} />);
  await waitFor(() => expect(screen.getByTestId("error")).toHaveTextContent("boom"));
  expect(screen.getByTestId("data")).toHaveTextContent("(none)");
  expect(screen.getByTestId("stale")).toHaveTextContent("fresh");
});
