// SPDX-License-Identifier: Apache-2.0
// Color-consistency guard (UI-AUDIT round 3). The portal palette is neutral-grey + teal (--accent #2ddab8);
// audit-purple (--audit #7c5cfc) is a decision/agent-node color ONLY; there is no navy/blue chrome. This test
// scans the UI source for hardcoded OFF-PALETTE chrome hexes and fails if any reappear — so the color
// regression can't creep back. It also asserts the two Attack Graph CTAs resolve to the teal accent.
import { describe, it, expect } from "vitest";

// Raw source of every .ts/.tsx under ui/src (this file lives in ui/src/lib).
const sources = import.meta.glob("../**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

// Off-palette chrome values that were swept out. audit-purple (#7c5cfc / #7C5CFC) is NOT here — it is a
// legitimate decision/agent-node color and stays canonical.
const FORBIDDEN = [
  "#6b7688", "#8494b2", "#4a5a78", "#1a0b2e", "#5a4a9e", "#181026", "#c9b6ff",
  "#141826", "#0b0d12", "#b78bff", "#3a2f5e", "#181230", "#2b2350", "#2a2140",
  "#2a2f3a", "#3a4152", "#16181f", "#5aa0ff", "#a855f7", "#c084fc",
  "rgba(124,92,252", "rgba(20,24,38", "rgba(11,13,18", "rgba(24,16,38",
];

// Documented, intentional keeps (data-encoding palettes + one deliberate selection accent).
const ALLOW: Record<string, string[]> = {
  // NS_HULL_COLORS is a CATEGORICAL namespace data palette (qualitative, like the severity colors).
  "d3-helpers.ts": ["#5aa0ff", "#b58cff", "#9db8ff"],
  // The deliberate purple selection accent on the selected attack-path row (Wave-3 kept it).
  "AttackPathList.tsx": ["#c084fc"],
};

describe("color-consistency guard", () => {
  it("no off-palette chrome hex reappears in ui/src", () => {
    const offenders: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (/\.(test|spec)\.tsx?$/.test(path) || path.includes("palette-consistency")) continue;
      const allowed = Object.entries(ALLOW).find(([f]) => path.endsWith(f))?.[1] ?? [];
      const lower = src.toLowerCase();
      for (const hex of FORBIDDEN) {
        if (allowed.includes(hex)) continue;
        if (lower.includes(hex.toLowerCase())) offenders.push(`${path} → ${hex}`);
      }
    }
    expect(offenders, `off-palette chrome must use tokens (teal accent / grey / semantic):\n${offenders.join("\n")}`).toEqual([]);
  });

  it("L1: the shared BrandLoader's green is the --accent token — no raw brand/off-palette hex", () => {
    const loader = Object.entries(sources).find(([p]) => p.endsWith("components/common/BrandLoader.tsx"))?.[1] ?? "";
    expect(loader, "BrandLoader.tsx must exist").not.toBe("");
    // the mark's stroke + halo are token-based (teal accent)
    expect(loader).toContain('stroke="var(--accent)"');
    expect(loader).toContain("var(--accent-glow)");
    expect(loader).toContain('fill="var(--accent)"');
    // NO raw 6-digit hex anywhere in the loader (not even allow-green #00e5a0 — tokens only)
    expect(loader).not.toMatch(/#[0-9a-fA-F]{6}/);
  });

  it("the login screen renders the brand mark via tokens (no raw #00e5a0 for the lockup/loader)", () => {
    const login = Object.entries(sources).find(([p]) => p.endsWith("auth/Login.tsx"))?.[1] ?? "";
    // the centered brand lockup uses the accent token
    expect(login).toContain("var(--accent)");
    // the old hand-rolled #00e5a0 sign-in loader is gone (replaced by the shared BrandLoader)
    expect(login).not.toMatch(/stroke="#00e5a0"/);
  });

  it("A4: the ScoreGauge descriptive caption is a NEUTRAL token, not the score's block-red risk band", () => {
    const gauge = Object.entries(sources).find(([p]) => p.endsWith("components/common/ScoreGauge.tsx"))?.[1] ?? "";
    expect(gauge, "ScoreGauge.tsx must exist").not.toBe("");
    // a caller-supplied caption (sub) is tinted with the neutral --text-muted token, never the risk color
    expect(gauge).toMatch(/captionColor\s*=\s*sub\s*!=\s*null\s*\?\s*"var\(--text-muted\)"/);
    // the Overview gauge caption emphasizes the % with the teal --accent (no raw block-red for the caption)
    const dash = Object.entries(sources).find(([p]) => p.endsWith("pages/Dashboard.tsx"))?.[1] ?? "";
    const gaugeSubBlock = (dash.match(/const gaugeSub[\s\S]*?\);/) ?? [""])[0];
    expect(gaugeSubBlock).toContain("var(--accent)");
    expect(gaugeSubBlock).not.toMatch(/#ff3b5c/i);
  });

  it("the Attack Graph primary CTAs resolve to the teal accent (not purple/indigo)", () => {
    const attackGraph = Object.entries(sources).find(([p]) => p.endsWith("pages/AttackGraph.tsx"))?.[1] ?? "";
    const detail = Object.entries(sources).find(([p]) => p.endsWith("attack-graph/AttackPathDetail.tsx"))?.[1] ?? "";
    // Toolbar global "Define intended behaviour · all classes" = teal-accent secondary; the per-path
    // Simulate lives in the inspector (redundant toolbar Simulate was removed).
    expect(attackGraph).toContain("Define intended behaviour · all classes");
    expect(attackGraph).toMatch(/border: "1px solid var\(--accent/); // Define-intent secondary
    expect(detail).toContain("Simulate (preview)");
    expect(attackGraph).not.toContain("#c084fc"); // no purple gradient CTA
    expect(attackGraph).not.toContain("#1a0b2e"); // no indigo
  });
});
