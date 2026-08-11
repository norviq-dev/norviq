#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Aggregate the persona reports and judge them against the G6 bar in docs/design/EXIT-STATE.md.

WHY AN AGGREGATOR AT ALL. Four separate findings lists invite the reader to skim each one and conclude
"mostly fine". The interesting signal is CROSS-PERSONA: a papercut that four unrelated industries all
hit independently is a product defect, while one that only healthcare hit may be a domain quirk. That
correlation is invisible until the reports sit side by side, so it is computed here rather than left to
whoever reads them.

THE BAR (G6), applied literally:
  * all four journeys complete
  * each persona proves >= 1 real decision FLIP it caused
  * 0 unresolved findings rated `blocker`
A persona that filed six `minor` findings and proved its flip PASSES. Findings are the product of this
exercise, not its failure condition.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter, defaultdict

ORDER = ["blocker", "major", "minor", "feature-request"]


def main() -> int:
    out_dir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/persona-out")
    reports = []
    for f in sorted(out_dir.glob("*.json")):
        try:
            reports.append(json.loads(f.read_text()))
        except json.JSONDecodeError:
            print(f"  !! {f.name} is not valid JSON — the persona died mid-write")
    if not reports:
        print(f"no persona reports in {out_dir} — G6 is UNVERIFIED, not passing")
        return 1

    by_sev: Counter[str] = Counter()
    # Group by title so the same defect hit by several industries collapses into one line.
    shared: dict[str, list[str]] = defaultdict(list)
    for r in reports:
        for f in r["findings"]:
            by_sev[f["severity"]] += 1
            shared[f["title"]].append(r["industry"])

    print(f"{len(reports)} persona(s): {', '.join(r['industry'] for r in reports)}")
    print("flips proven: " + ", ".join(f"{r['industry']}={r['flips_proven']}" for r in reports))
    print("findings: " + (", ".join(f"{k}={by_sev[k]}" for k in ORDER if by_sev[k]) or "none"))

    cross = {t: ind for t, ind in shared.items() if len(set(ind)) > 1}
    if cross:
        print("\n--- hit by more than one industry (product defects, not domain quirks) ---")
        for title, inds in sorted(cross.items(), key=lambda kv: -len(set(kv[1]))):
            print(f"  [{len(set(inds))}x] {title}  ({', '.join(sorted(set(inds)))})")

    print("\n--- every finding, by severity ---")
    for sev in ORDER:
        rows = [(r["industry"], f) for r in reports for f in r["findings"] if f["severity"] == sev]
        if not rows:
            continue
        print(f"\n{sev.upper()} ({len(rows)})")
        for industry, f in rows:
            print(f"  · [{industry}] {f['title']}")
            print(f"      {f['detail']}")
            print(f"      repro: {f['repro']}")

    print("\n" + "=" * 72)
    fails = []
    if len(reports) < 4:
        fails.append(f"only {len(reports)}/4 personas reported")
    no_flip = [r["industry"] for r in reports if r["flips_proven"] < 1]
    if no_flip:
        # The most important check here. A persona that ran to completion without changing a single
        # decision has demonstrated the console's usability and NOTHING about its enforcement.
        fails.append(f"no proven decision flip for: {', '.join(no_flip)} — the journey completed but "
                     "never demonstrated that governing the agent changed what it could do")
    if by_sev["blocker"]:
        fails.append(f"{by_sev['blocker']} blocker finding(s) unresolved")

    if fails:
        print("G6 NOT MET")
        for f in fails:
            print(f"  ✗ {f}")
        return 1
    print(f"G6 MET · {len(reports)} journeys, every persona proved a flip, no blockers, "
          f"{sum(by_sev.values())} finding(s) filed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
