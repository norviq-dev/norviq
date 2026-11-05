#!/usr/bin/env python3
"""Gate on `fossa test --format json` output. Exit 1 on any non-excepted vulnerability or malware
issue — and exit 1 on a payload whose SHAPE is not recognised.

The inline version of this gate read `d.get("issues", [])`. A missing file, malformed JSON or a bare
`null` raised and failed the step — those failed closed. But `{}`, a capitalised `{"Issues": [...]}`,
or any well-formed object without that exact key produced an empty list, zero findings, and a PASS.
The diagnostic step forty lines earlier already parsed both spellings and a bare list; the gate did
not, so the two could disagree and the gate would win. A scan that cannot tell "no issues" from
"I did not find the issues" reports safety it never verified.

The gate judges what ships. FOSSA re-resolves transitive Python dependencies server-side, so it can
report a version that is not in the closure the images install (0.2.6: cryptography 46.0.5, urllib3
2.6.3, idna 3.11, while the lock pins 50.0.0, 2.8.0 and 3.18). Given `--shipped <requirements file>`
(the `uv export` closure fossa.yml generates), a pip vulnerability is gated only when its exact
name+version is in that closure; any other is listed separately and does not fail the gate. Malware
always fails, npm/go findings are gated as before, and a shipped file that is missing, empty or
contains a line the parser cannot read fails the gate closed.
"""

from __future__ import annotations

import json
import re
import sys

# Documented in SECURITY.md, whose table must name exactly these ids (tests/test_check_fossa_issues.py
# holds the two together). Substring match over the whole issue blob, so either identifier form
# matches wherever FOSSA puts it (cve field, title, or the advisory URL).
ACCEPTED = frozenset({
    # Optional framework extras only, in no shipped image. chromadb has no fixed release for any of
    # its four; semantic-kernel's fixes all need a pre-release azure-ai-agents.
    "CVE-2026-45829", "CVE-2026-45830", "CVE-2026-45831", "CVE-2026-45833",
    "CVE-2026-26030", "CVE-2026-25592",
    # litellm: a spurious match, like the k8s ones below. The advisory (GHSA-53gh-p8jc-7rg8) covers
    # 1.40.3.dev2 through 1.40.12 only; the lock is at 1.100.4.
    "CVE-2024-6825",
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


class UnreadableShipped(ValueError):
    pass


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;]+)\s*(?:;.*)?$")


def shipped_from(text: str) -> dict[str, set[str]]:
    """{normalised name: {versions}} from a `uv export --no-hashes` requirements file. Comments,
    blank lines and indented `# via` lines are skipped; any other line must be `name==version`."""
    out: dict[str, set[str]] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _REQ.match(line)
        if not m:
            raise UnreadableShipped(f"line {n} is not a pinned `name==version` requirement: {raw!r}")
        out.setdefault(_norm(m.group(1)), set()).add(m.group(2))
    if not out:
        raise UnreadableShipped("no pinned packages found")
    return out


def _pip_pkg(issue: dict) -> tuple[str, str] | None:
    rev = issue.get("revisionId") or ""
    if not rev.startswith("pip+") or "$" not in rev:
        return None
    name, _, version = rev[4:].rpartition("$")
    return (_norm(name), version) if name and version else None


def _not_shipped(issue: dict, shipped: dict[str, set[str]] | None) -> str | None:
    """Why a vulnerability is outside the shipped closure, or None if it is gated."""
    if shipped is None or (issue.get("type") or issue.get("Type")) != "vulnerability":
        return None
    pkg = _pip_pkg(issue)
    if pkg is None:
        return None
    name, version = pkg
    if version in shipped.get(name, ()):
        return None
    if name in shipped:
        return f"FOSSA {version}, shipped {', '.join(sorted(shipped[name]))}"
    return f"FOSSA {version}, package not shipped"


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


def gate(payload: object, shipped: dict[str, set[str]] | None = None) -> tuple[int, str]:
    """(exit code, message). `shipped` None gates every pip finding, as before the closure check."""
    sec = [i for i in issues_from(payload) if (i.get("type") or i.get("Type")) in _SEC]
    accepted = [i for i in sec if _accepted(i)]
    rest = [i for i in sec if not _accepted(i)]
    outside = [(i, _not_shipped(i, shipped)) for i in rest if _not_shipped(i, shipped)]
    gated = [i for i in rest if not _not_shipped(i, shipped)]
    lines = []
    if accepted:
        lines.append(f"NOTE: {len(accepted)} accepted dependency exception(s) (documented in SECURITY.md):")
        lines += [f"  - {_accepted(i)}: {i.get('revisionId', '')}" for i in accepted]
    if outside:
        lines.append(f"NOTE: {len(outside)} finding(s) not in the shipped closure (FOSSA resolved these itself):")
        lines += [f"  - {i.get('revisionId', '')} {i.get('cve') or ''} ({why})" for i, why in outside]
    if gated:
        lines.append(f"FOSSA security gate FAILED — {len(gated)} dependency vuln/malware issue(s):")
        lines += [f"  - {i.get('type') or i.get('Type')}: {i.get('revisionId', '')} {i.get('cve') or ''}" for i in gated]
        return 1, "\n".join(lines)
    lines.append(f"FOSSA security gate PASSED — 0 non-excepted dependency vuln/malware issues "
                 f"({len(accepted)} documented exception(s), {len(outside)} not in the shipped closure; "
                 f"license/outdated are informational).")
    return 0, "\n".join(lines)


def main(*argv: str) -> int:
    args = list(argv)
    shipped_path = None
    if "--shipped" in args:
        k = args.index("--shipped")
        if k + 1 >= len(args):
            print("--shipped needs a requirements file")
            return 1
        shipped_path = args[k + 1]
        del args[k:k + 2]
    path = args[0] if args else "fossa-issues.json"
    shipped = None
    if shipped_path is not None:
        try:
            shipped = shipped_from(open(shipped_path).read())
        except (OSError, ValueError) as exc:
            print(f"could not read the shipped closure {shipped_path} — failing closed: {exc}")
            return 1
    try:
        payload = json.load(open(path))
    except (OSError, ValueError) as exc:
        print(f"could not read {path}: {exc}")
        return 1
    try:
        code, msg = gate(payload, shipped)
    except UnrecognisedShape as exc:
        print(f"FOSSA output has an unrecognised shape — refusing to treat it as zero issues: {exc}")
        return 1
    print(msg)
    return code


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
