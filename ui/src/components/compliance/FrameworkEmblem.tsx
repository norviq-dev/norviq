// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Per-framework emblems for the Compliance page (nominative recreations of the design_handoff_compliance
// ICONS: ATLAS mountain-in-circle, OWASP dragon, NIST/ISO text marks, EU stars). All tinted with `currentColor`
// so they inherit the portal palette (teal/grey per the palette law) — no hardcoded off-palette colors.

type FrameworkId = "atlas" | "owasp" | "nist" | "iso" | "eu";

export function FrameworkEmblem({ framework, size = 24 }: { framework: string; size?: number }) {
  const common = { width: size, height: size, "aria-hidden": true } as const;
  switch (framework as FrameworkId) {
    case "atlas":
      return (
        <svg {...common} data-testid="emblem-atlas" viewBox="0 0 44 44" fill="none" stroke="currentColor" strokeWidth={2.4} strokeLinejoin="round" strokeLinecap="round">
          <circle cx="22" cy="22" r="18" />
          <path d="M13 31 22 12 31 31" />
          <path d="M16.5 24.5H27.5" />
        </svg>
      );
    case "owasp":
      return (
        <svg {...common} data-testid="emblem-owasp" viewBox="0 0 44 44" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinejoin="round" strokeLinecap="round">
          <circle cx="22" cy="22" r="17.5" />
          <path d="M20 14c-1.2-1.8-2.8-2.9-4.4-3.2M24 14c1.2-1.8 2.8-2.9 4.4-3.2" strokeWidth={1.4} />
          <circle cx="22" cy="15.6" r="2.2" fill="currentColor" stroke="none" />
          <ellipse cx="15.6" cy="22.6" rx="5" ry="2.7" transform="rotate(-33 15.6 22.6)" fill="currentColor" stroke="none" opacity={0.88} />
          <ellipse cx="28.4" cy="22.6" rx="5" ry="2.7" transform="rotate(33 28.4 22.6)" fill="currentColor" stroke="none" opacity={0.88} />
          <path d="M22 17.8c-1.9 0-2.9 1.4-2.9 3.1 0 1.2.6 2.2 1.1 3.3.7 1.4 1.3 3.4 1.8 6.2.5-2.8 1.1-4.8 1.8-6.2.5-1.1 1.1-2.1 1.1-3.3 0-1.7-1-3.1-2.9-3.1Z" fill="currentColor" stroke="none" />
        </svg>
      );
    case "nist":
      return (
        <svg {...common} data-testid="emblem-nist" viewBox="0 0 44 44">
          <text x="22" y="27" textAnchor="middle" fontFamily="Outfit, sans-serif" fontSize="13" fontWeight="800" fill="currentColor" letterSpacing="0.5">NIST</text>
        </svg>
      );
    case "iso":
      return (
        <svg {...common} data-testid="emblem-iso" viewBox="0 0 44 44">
          <text x="22" y="27" textAnchor="middle" fontFamily="Outfit, sans-serif" fontSize="14.5" fontWeight="800" fill="currentColor" letterSpacing="0.5">ISO</text>
        </svg>
      );
    case "eu":
      return (
        <svg {...common} data-testid="emblem-eu" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
          <circle cx="12" cy="12" r="9" />
          <g fill="currentColor" stroke="none">
            {[[12, 4.6], [15.7, 5.6], [18.4, 8.3], [19.4, 12], [18.4, 15.7], [15.7, 18.4], [12, 19.4], [8.3, 18.4], [5.6, 15.7], [4.6, 12], [5.6, 8.3], [8.3, 5.6]].map(([cx, cy], i) => (
              <circle key={i} cx={cx} cy={cy} r={0.9} />
            ))}
          </g>
        </svg>
      );
    default:
      return null;
  }
}
