# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F047 sector starter policy packs — manifest loading + rego combination.

The catalog and the enable/disable backend read the bundled manifest (policies/sector/packs.json)
and the referenced rego. Enabling a pack materializes the COMBINED rego of a namespace's enabled
packs as its (namespace, '__pack__') policy via the normal policy-create path. Combination unions
each pack's PACK-CONTRIB section (sector-prefixed helpers + the shared blocks/escalates/audits/
reasons partial rules) under one package with exactly one copy of the shared RESOLVER.
"""

from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path

import structlog

log = structlog.get_logger()

_CANDIDATE_DIRS = [
    Path(__file__).resolve().parents[2] / "policies" / "sector",
    Path.cwd() / "policies" / "sector",
]

_CONTRIB_BEGIN = "# >>> PACK-CONTRIB-BEGIN"
_CONTRIB_END = "# >>> PACK-CONTRIB-END"
_RESOLVER_BEGIN = "# >>> RESOLVER-BEGIN"
_RESOLVER_END = "# >>> RESOLVER-END"


def _sector_dir() -> Path | None:
    """Locate the bundled policies/sector directory (baked into the image via COPY policies/)."""
    for d in _CANDIDATE_DIRS:
        if (d / "packs.json").exists():
            return d
    return None


@lru_cache(maxsize=1)
def load_manifest() -> dict:
    """Load packs.json: {'pack_priority': int, 'packs': {pack_id: {...}}}. Empty if missing."""
    d = _sector_dir()
    if d is None:
        log.warning("nrvq.api.packs.manifest_missing", code="NRVQ-API-7097")
        return {"pack_priority": 800, "packs": {}}
    raw = json.loads((d / "packs.json").read_text(encoding="utf-8"))
    packs = {p["id"]: p for p in raw.get("packs", []) if isinstance(p, dict) and p.get("id")}
    return {"pack_priority": int(raw.get("pack_priority", 800)), "packs": packs}


# canonical horizontal rule_id contributed by each shared `requires` entry (for catalog display)
_SHARED_RULE_IDS = {"pci": "pci_card_numbers", "pii": "pii_detection"}


def catalog() -> list[dict]:
    """Public catalog rows (no rego) for GET /policy-packs, sorted by sector then id."""
    packs = load_manifest()["packs"]
    rows = [
        {
            "id": p["id"],
            "sector": p.get("sector", ""),
            "title": p.get("title", ""),
            "enforces": p.get("enforces", ""),
            "rule_ids": p.get("rule_ids", []),
            # canonical horizontal rules composed in at enable-time (e.g. pci_card_numbers, pii_detection)
            "composes": [_SHARED_RULE_IDS[r] for r in p.get("requires", []) if r in _SHARED_RULE_IDS],
            "categories": p.get("categories", []),
            "compliance": p.get("compliance", []),
            "tunables": p.get("tunables", []),
        }
        for p in packs.values()
    ]
    return sorted(rows, key=lambda r: (r["sector"], r["id"]))


def is_known(pack_id: str) -> bool:
    """True if pack_id is a real bundled pack."""
    return pack_id in load_manifest()["packs"]


def pack_priority() -> int:
    """Evaluation priority for the materialized (ns,__pack__) policy."""
    return load_manifest()["pack_priority"]


def _read_rego(pack_id: str) -> str:
    d = _sector_dir()
    rel = load_manifest()["packs"][pack_id]["rego"]
    # rel is repo-relative ("policies/sector/<dir>/<file>"); resolve against the sector dir's parent.
    path = (d.parent.parent / rel) if d else Path(rel)
    return path.read_text(encoding="utf-8")


def read_rego(pack_id: str) -> str:
    """F-54: public accessor for a pack's rego source (read-only view in the console)."""
    return _read_rego(pack_id)


def _between(text: str, begin: str, end: str) -> str:
    """Return the text strictly between the first begin-marker line and the end-marker."""
    bi = text.index(begin)
    bi = text.index("\n", bi) + 1
    ei = text.index(end)
    return text[bi:ei].strip("\n")


def _shared_rego() -> str:
    """The canonical shared horizontal rules module (policies/sector/_shared/horizontal.rego)."""
    d = _sector_dir()
    return (d / "_shared" / "horizontal.rego").read_text(encoding="utf-8") if d else ""


def combine(pack_ids: list[str]) -> str:
    """Build the combined (ns,__pack__) rego for the given enabled packs (order-stable, deduped).

    A pack's manifest `requires` (e.g. finance->pci, healthcare->pii) composes the canonical SHARED-RULE
    section from horizontal.rego into the module — so the namespace gets the SAME PCI/PII coverage as the
    default policy, sourced from one definition, not re-implemented per pack.
    """
    manifest = load_manifest()["packs"]
    ordered = sorted(set(pid for pid in pack_ids if is_known(pid)))
    if not ordered:
        return ""
    contribs: list[str] = []
    resolver = ""
    requires: list[str] = []
    for pid in ordered:
        rego = _read_rego(pid)
        contribs.append(f"# pack: {pid}\n{_between(rego, _CONTRIB_BEGIN, _CONTRIB_END)}")
        if not resolver:
            resolver = _between(rego, _RESOLVER_BEGIN, _RESOLVER_END)
        for req in manifest[pid].get("requires", []):
            if req not in requires:
                requires.append(req)
    shared_secs: list[str] = []
    if requires:
        shared = _shared_rego()
        for req in sorted(requires):
            begin, end = f"# >>> SHARED-RULE {req}", f"# >>> END SHARED-RULE {req}"
            if begin in shared:
                shared_secs.append(f"# shared: {req}\n{_between(shared, begin, end)}")
    parts = ["package norviq.pack", *contribs, *shared_secs, resolver]
    return "\n\n".join(parts) + "\n"
