// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// BrandLoader: the ONE canonical Norviq loading mark. The brand "Y" with a green EDGE glow that animates
// as it loads (a light travelling along the mark's edge over a soft halo). Used for every full-page / route /
// Suspense / refresh load and for the login in-flight state, so the brand moment is identical everywhere and
// the mark never jumps between screens.
//
// PALETTE: green == the brand teal `--accent` (primary). `--allow` (allow-green) is available as an optional
// highlight but this mark stays accent-only for a single, consistent brand green. TOKENS ONLY — no raw hex.
// prefers-reduced-motion → the halo + mark render statically (no travelling trace, no pulse).

// The canonical Norviq "Y" (same paths as the mark asset / IconRail; viewBox 0 0 166 200).
const Y1 = "M0.0 0.0 L77.5 72.3 L77.5 200.0 L74.3 197.2 L57.3 181.0 L57.3 87.4 L0.0 34.4 L0.0 0.4 Z";
const Y2 = "M165.6 0.0 L166.0 34.0 L108.3 87.4 L108.3 180.6 L88.1 200.0 L88.1 72.3 L165.2 0.4 Z";

// Self-contained keyframes so the loader animates anywhere it mounts. `blGlow` pulses the halo; `blTrace`
// moves the accent dash along the mark's edge. Reduced-motion disables both (static glow).
const CSS = `
@keyframes blGlow { 0%,100% { opacity: 0.5; transform: scale(0.95); } 50% { opacity: 1; transform: scale(1.05); } }
@keyframes blTrace { to { stroke-dashoffset: -100; } }
@keyframes blFade { from { opacity: 0; } to { opacity: 1; } }
@media (prefers-reduced-motion: reduce) {
  .bl-glow { animation: none !important; opacity: 0.85 !important; transform: none !important; }
  .bl-trace { animation: none !important; stroke-dasharray: none !important; }
  .bl-fade { animation: none !important; }
}
`;

interface BrandLoaderProps {
  /** Mark size in px (width). Height is derived from the 166×200 aspect. Default 64. */
  size?: number;
  /** Accessible label announced to assistive tech (role=status). */
  label?: string;
  /** Inline flow (e.g. inside a button) instead of a centered block with halo padding. */
  inline?: boolean;
}

/** The shared animated Norviq loading mark. */
export function BrandLoader({ size = 64, label = "Loading", inline = false }: BrandLoaderProps) {
  const w = size;
  const h = Math.round((size * 200) / 166);
  const strokeW = inline ? 12 : 7; // thicker stroke reads better at tiny (button) sizes
  return (
    <span
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-label={label}
      data-testid="brand-loader"
      className="bl-fade"
      style={{
        position: "relative",
        display: inline ? "inline-flex" : "flex",
        alignItems: "center",
        justifyContent: "center",
        width: inline ? w : w + 40,
        height: inline ? h : h + 40,
        animation: "blFade 0.3s ease both",
        verticalAlign: "middle",
      }}
    >
      <style>{CSS}</style>
      {!inline && (
        <span
          aria-hidden="true"
          className="bl-glow"
          data-testid="brand-loader-glow"
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            background: "radial-gradient(circle, var(--accent-glow) 0%, transparent 66%)",
            animation: "blGlow 1.6s ease-in-out infinite",
          }}
        />
      )}
      <svg viewBox="0 0 166 200" width={w} height={h} style={{ overflow: "visible", position: "relative" }} aria-hidden="true">
        <g fill="var(--accent)" opacity={0.16}>
          <path d={Y1} />
          <path d={Y2} />
        </g>
        <g
          fill="none"
          stroke="var(--accent)"
          strokeWidth={strokeW}
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{ filter: "drop-shadow(0 0 5px var(--accent))" }}
        >
          <path className="bl-trace" pathLength={100} d={Y1} style={{ strokeDasharray: "22 78", animation: "blTrace 1.3s linear infinite" }} />
          <path className="bl-trace" pathLength={100} d={Y2} style={{ strokeDasharray: "22 78", animation: "blTrace 1.3s linear infinite", animationDelay: "-0.65s" }} />
        </g>
      </svg>
      {/* LOGO-ONLY everywhere: the label is carried ONLY by `aria-label` on the role=status host (an sr-only,
          screen-reader-announced accessible name) — NOT a text node. The classic clip sr-only technique still
          appears in `innerText`, so any text node would make the boot/route overlay (and the in-button loader)
          visibly read its caption ("Loading Norviq" / "Signing in"). With aria-label + aria-busy + role=status
          the live region is still announced to assistive tech while the on-screen state is just the logo. */}
    </span>
  );
}

interface OverlayProps extends BrandLoaderProps {
  /** Full-VIEWPORT centering (position:fixed, default) so the logo sits at innerWidth/2 × innerHeight/2,
   * independent of any offset ancestor. Set false to scope the overlay to the nearest positioned ancestor. */
  fullscreen?: boolean;
}

/** The shared loader centered over a dim, blurred scrim — the full-page / route / refresh loading overlay.
 * Full-viewport by default so the mark is centered on the whole screen (both axes). */
export function BrandLoaderOverlay({ size = 64, label = "Loading Norviq", fullscreen = true }: OverlayProps) {
  return (
    <div
      data-testid="brand-loader-overlay"
      style={{
        position: fullscreen ? "fixed" : "absolute",
        inset: 0,
        zIndex: 20,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "rgba(13,13,13,0.9)",
        backdropFilter: "blur(6px)",
        WebkitBackdropFilter: "blur(6px)",
      }}
    >
      <BrandLoader size={size} label={label} />
    </div>
  );
}
