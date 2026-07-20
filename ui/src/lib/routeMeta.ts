// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Single source of truth for which routes are driven by the GLOBAL header time-range selector
// (1h/6h/24h/7d/30d). The selector is rendered ONLY where `isTimeScoped(pathname)` is true, so a
// dead/duplicate control can never drift back onto a page.
//
// TRUE where the global range drives the page's data. Verified live:
//   • `/`           Dashboard/Overview — reads `timeRange` in its fetch deps (stats/records/volume).
//   • `/audit`      AuditLog          — reads `timeRange` in its fetch deps (records query).
//   • `/compliance` Compliance        — it IS range-scoped (per-technique blocked/observed evidence
//                     changes with the window, e.g. /compliance/atlas/coverage?range=1h ≠ range=30d) and had NO
//                     control on its landing/overview (the only picker lived in the DETAIL header). Now the global
//                     header range is Compliance's single source of truth (the redundant detail picker is removed)
//                     and its coverage/evidence refetch on change.
//
// FALSE for current-state pages (Policy Catalog / Policy Packs / Target Settings, Policy Tester, Settings/*, Agents,
// Fleet) AND for pages that DO have their own in-page range picker (verified they still do):
//   • `/threats/graph` Attack Graph — own range via URL `?range=` + in-page dropdown.
//   • `/asset-graph`   Asset Graph  — own in-page Range dropdown.

export const TIME_SCOPED_PATHS = ["/", "/audit", "/compliance"] as const;

/** True when the global header time-range selector genuinely drives this route's data. */
export function isTimeScoped(pathname: string): boolean {
  if (pathname === "/") return true;
  if (pathname === "/compliance" || pathname.startsWith("/compliance/")) return true;
  return pathname === "/audit" || pathname.startsWith("/audit/");
}
