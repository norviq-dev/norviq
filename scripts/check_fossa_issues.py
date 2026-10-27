#!/usr/bin/env python3
"""Gate on `fossa test --format json` output. Exit 1 on any non-excepted vulnerability or malware
issue — and exit 1 on a payload whose SHAPE is not recognised.

The inline version of this gate read `d.get("issues", [])`. A missing file, malformed JSON or a bare
`null` raised and failed the step — those failed closed. But `{}`, a capitalised `{"Issues": [...]}`,
or any well-formed object without that exact key produced an empty list, zero findings, and a PASS.
The diagnostic step forty lines earlier already parsed both spellings and a bare list; the gate did
not, so the two could disagree and the gate would win. A scan that cannot tell "no issues" from
"I did not find the issues" reports safety it never verified.
"""

from __future__ import annotations

import json
import sys

# Documented in SECURITY.md. Substring match over the whole issue blob, so either identifier form
# matches wherever FOSSA puts it (cve field, title, or the advisory URL).
ACCEPTED = frozenset({
    "CVE-2024-6825", "CVE-2026-45829", "CVE-2026-26030", "CVE-2026-25592", "GHSA-qwww-vcr4-c8h2",
    # The webhook's k8s.io modules. FOSSA matches these three against any v0.x version; the advisory
    # database says otherwise. CVE-2018-1002105 is against kubernetes/kubernetes < 1.12.3 (an
    # API-server aggregation bug, never a library one). CVE-2019-11250 is fixed in client-go 0.17.0,
    # CVE-2020-8565 in 0.19.6 / 0.20.0-alpha.2. The pinned version is v0.37.0 — twenty minors past
    # the latest fix. A bump cannot satisfy a match that has no upper bound; this exception can.
    "CVE-2018-1002105", "CVE-2019-11250", "CVE-2020-8565",
})
_SEC = ("vulnerability", "malware")


class UnrecognisedShape(ValueError):
    pass


def issues_from(payload: object) -> list[dict]:
    """Every shape the gate accepts. Anything else is an error, not an empty list."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("issues", "Issues"):
            if key in payload:
                v = payload[key]
                if isinstance(v, list):
                    return v
                raise UnrecognisedShape(f"{key!r} is {type(v).__name__}, not a list")
        raise UnrecognisedShape(f"object has none of the expected keys; has {sorted(payload)[:8]}")
    raise UnrecognisedShape(f"top-level {type(payload).__name__}")


def _accepted(issue: dict) -> str | None:
    blob = json.dumps(issue)
    return next((c for c in ACCEPTED if c in blob), None)


def gate(payload: object) -> tuple[int, str]:
    """(exit code, message)."""
    sec = [i for i in issues_from(payload) if (i.get("type") or i.get("Type")) in _SEC]
    accepted = [i for i in sec if _accepted(i)]
    gated = [i for i in sec if not _accepted(i)]
    lines = []
    if accepted:
        lines.append(f"NOTE: {len(accepted)} accepted dependency exception(s) (documented in SECURITY.md):")
        lines += [f"  - {_accepted(i)}: {i.get('revisionId', '')}" for i in accepted]
    if gated:
        lines.append(f"FOSSA security gate FAILED — {len(gated)} dependency vuln/malware issue(s):")
        lines += [f"  - {i.get('type') or i.get('Type')}: {i.get('revisionId', '')} {i.get('cve') or ''}" for i in gated]
        return 1, "\n".join(lines)
    lines.append(f"FOSSA security gate PASSED — 0 non-excepted dependency vuln/malware issues "
                 f"({len(accepted)} documented exception(s); license/outdated are informational).")
    return 0, "\n".join(lines)


def main(path: str = "fossa-issues.json") -> int:
    try:
        payload = json.load(open(path))
    except (OSError, ValueError) as exc:
        print(f"could not read {path}: {exc}")
        return 1
    try:
        code, msg = gate(payload)
    except UnrecognisedShape as exc:
        print(f"FOSSA output has an unrecognised shape — refusing to treat it as zero issues: {exc}")
        return 1
    print(msg)
    return code


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
