// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// A caller-supplied ScoreGauge caption is NEUTRAL grey (--text-muted), never the score's risk-band
// #ff3b5c (block-red), which is reserved for real block decisions. The built-in risk labels (no `sub`) keep
// the risk color.

import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

// the gauge renders an echarts canvas; stub it so the caption renders in jsdom without a real canvas.
vi.mock("./EChart", () => ({ default: () => null }));

import { ScoreGauge } from "./ScoreGauge";

describe("ScoreGauge caption color", () => {
  it("a caller-supplied caption at a LOW score is grey (--text-muted), NOT block-red", () => {
    render(<ScoreGauge score={40} title="Policy Coverage" sub={<span>rules present · <b>72% proven-blocking</b></span>} />);
    const caption = screen.getByTestId("score-gauge-caption");
    // the caption is tinted with the neutral token, not the risk-band #ff3b5c
    expect(caption.style.color).toBe("var(--text-muted)");
    expect(caption.style.color).not.toMatch(/#ff3b5c/i);
    expect(caption).toHaveTextContent("rules present");
  });

  it("the built-in risk label (no sub) keeps the risk color at a low score", () => {
    render(<ScoreGauge score={40} title="Security Score" />);
    const caption = screen.getByTestId("score-gauge-caption");
    expect(caption).toHaveTextContent(/High Risk/i);
    // jsdom normalizes the hex to rgb — the real risk signal stays red (#ff3b5c == rgb(255,59,92))
    expect(caption).toHaveStyle({ color: "rgb(255, 59, 92)" });
  });

  it("a caller caption never inherits the risk color even when the score is high", () => {
    render(<ScoreGauge score={90} sub="rules present" />);
    expect(screen.getByTestId("score-gauge-caption").style.color).toBe("var(--text-muted)");
  });

  it("the caption sits BELOW the gauge (a sibling after the number overlay), not inside the in-arc overlay", () => {
    render(<ScoreGauge score={40} title="Policy Coverage" sub={<span>rules present · <b>88.9% proven-blocking</b> (last run)</span>} />);
    const caption = screen.getByTestId("score-gauge-caption");
    // the big % lives in the pulled-up (-86) overlay; the caption must NOT be inside that overlay anymore.
    const overlay = document.querySelector('[style*="-86"]') as HTMLElement | null;
    expect(overlay).toBeTruthy();
    expect(overlay!.contains(caption)).toBe(false); // caption is a sibling below, not overlapping the arc
    // it still renders the number and the full caption text
    expect(overlay!).toHaveTextContent("40%");
    expect(caption).toHaveTextContent(/rules present · 88\.9% proven-blocking \(last run\)/i);
  });
});
