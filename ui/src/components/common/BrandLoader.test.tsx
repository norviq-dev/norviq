// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// BrandLoader: renders the Norviq mark with an accent-animated edge, exposes an accessible status,
// supports an inline (button) variant + an overlay, and uses ONLY tokens (var(--accent)) for the green — no
// raw off-palette hex. Reduced-motion is handled by CSS (asserted structurally + by the palette guard).

import { render, screen, within } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { BrandLoader, BrandLoaderOverlay } from "./BrandLoader";

describe("BrandLoader", () => {
  it("renders the Norviq Y mark as an accessible status; label is sr-only via aria-label (no visible text node)", () => {
    render(<BrandLoader label="Signing in" />);
    const status = screen.getByRole("status");
    // accessible name for screen readers comes from aria-label (sr-only) + role=status + aria-busy
    expect(status).toHaveAttribute("aria-label", "Signing in");
    expect(status).toHaveAttribute("aria-busy", "true");
    // LOGO-ONLY: NO visible text node (would leak into innerText / show on screen)
    expect(within(status).queryByText("Signing in")).toBeNull();
    expect((status.textContent || "")).not.toContain("Signing in"); // only the <style> block, no label text
    // the mark is two Y paths inside an svg
    expect(status.querySelectorAll("svg path").length).toBe(4); // 2 fill + 2 stroke traces
  });

  it("animates the edge with the ACCENT token (green == --accent, not a raw hex)", () => {
    render(<BrandLoader />);
    const status = screen.getByRole("status");
    // the traced stroke group uses var(--accent); the halo uses var(--accent-glow) — tokens only
    const stroked = status.querySelector("g[stroke]");
    expect(stroked?.getAttribute("stroke")).toBe("var(--accent)");
    const glow = screen.getByTestId("brand-loader-glow");
    expect(glow.getAttribute("style") || "").toContain("var(--accent-glow)");
    // travelling trace paths carry the animation class
    expect(status.querySelectorAll("path.bl-trace").length).toBe(2);
    // no raw off-palette / brand hex is inlined anywhere in the rendered mark
    expect(status.outerHTML).not.toMatch(/#[0-9a-fA-F]{6}/);
  });

  it("inline variant renders no halo (fits inside a button)", () => {
    render(<BrandLoader inline size={18} label="Signing in" />);
    expect(screen.queryByTestId("brand-loader-glow")).toBeNull();
    expect(screen.getByRole("status")).toHaveStyle({ display: "inline-flex" });
  });

  it("inline variant is LOGO-ONLY: no visible text node (empty innerText), a11y via aria-label only", () => {
    render(<BrandLoader inline size={20} label="Signing in" />);
    const status = screen.getByRole("status");
    // the visually-hidden text SPAN is omitted for inline → nothing leaks into the button's innerText…
    expect(within(status).queryByText("Signing in")).toBeNull();
    expect(status.innerText || "").toBe(""); // jsdom innerText is empty (logo + <style> only, no text node)
    // …but the accessible name (sr-only label) is still there for assistive tech
    expect(status).toHaveAttribute("aria-label", "Signing in");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status.querySelectorAll("svg path").length).toBe(4); // logo still rendered
  });

  it("overlay is full-VIEWPORT (position:fixed) by default and centers the loader over a scrim", () => {
    render(<BrandLoaderOverlay />);
    const overlay = screen.getByTestId("brand-loader-overlay");
    expect(overlay).toHaveStyle({ position: "fixed" });
    expect(overlay.style.inset).toBe("0"); // covers the whole viewport
    expect(within(overlay).getByRole("status")).toBeInTheDocument();
  });

  it("overlay (boot/route loader) is LOGO-ONLY: no visible 'Loading Norviq' caption; sr-only accessible name kept", () => {
    render(<BrandLoaderOverlay label="Loading Norviq" />);
    const overlay = screen.getByTestId("brand-loader-overlay");
    const status = within(overlay).getByRole("status");
    // no visible caption text node — the overlay shows only the centered logo
    expect(within(overlay).queryByText("Loading Norviq")).toBeNull();
    expect((status.textContent || "")).not.toContain("Loading Norviq");
    // …but a screen reader still gets the label via aria-label on the role=status live region
    expect(status).toHaveAttribute("aria-label", "Loading Norviq");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status.querySelectorAll("svg path").length).toBe(4); // logo rendered
  });

  it("overlay can be scoped to a positioned ancestor via fullscreen={false}", () => {
    render(<BrandLoaderOverlay fullscreen={false} />);
    expect(screen.getByTestId("brand-loader-overlay")).toHaveStyle({ position: "absolute" });
  });

  it("emits the reduced-motion CSS so motion is disabled when the user prefers it", () => {
    render(<BrandLoader />);
    const style = screen.getByRole("status").querySelector("style")?.textContent ?? "";
    expect(style).toContain("prefers-reduced-motion: reduce");
    expect(style).toMatch(/\.bl-trace\s*\{[^}]*animation:\s*none/);
  });
});
